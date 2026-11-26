//! Accounts: the public header, its MAC, and unlocking.
//!
//! Used by the `.pbv` vault file. Unlocking applies these checks before anything
//! else is read: KDF limits, factor set, unlock key
//! (wrong factors fail here), header MAC, and that the decrypted identity matches
//! the public keys in the header.

use hmac::{Hmac, KeyInit, Mac};
use passback_crypto::{
    Suite,
    aead::SealedBox,
    hash,
    kdf::KdfParams,
    keys::{AccountKey, Id, Identity},
    unlock::{Factor, UnlockParams, derive_unlock_key},
    wire::{Reader, Writer},
};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::{FormatError, Result, commit::Signers};

/// Domain the header MAC is bound to. Equal to the `.pbv` magic and format version,
/// so files written before this module existed keep verifying.
const MAC_DOMAIN: &[u8] = b"PASSBACK\x00\x01";

/// Bit flags naming the factors needed to unlock.
pub mod factor_mask {
    /// Master password (always set).
    pub const PASSWORD: u8 = 1;
    /// Account Secret Key.
    pub const SECRET_KEY: u8 = 2;
    /// Key file.
    pub const KEY_FILE: u8 = 4;
    /// Hardware authenticator.
    pub const HARDWARE: u8 = 8;
}

/// Factor mask for a factor list.
pub fn mask_of(factors: &[Factor<'_>]) -> u8 {
    factors.iter().fold(0, |m, f| {
        m | match f {
            Factor::Password(_) => factor_mask::PASSWORD,
            Factor::SecretKey(_) => factor_mask::SECRET_KEY,
            Factor::KeyFile(_) => factor_mask::KEY_FILE,
            Factor::Hardware(_) => factor_mask::HARDWARE,
        }
    })
}

/// Public header: readable without unlocking, authenticated after unlocking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Suite of the header's own envelopes.
    pub suite: Suite,
    /// KDF inputs.
    pub unlock: UnlockParams,
    /// Factors required (see [`factor_mask`]).
    pub factors: u8,
    wrapped_account_key: SealedBox,
    sealed_identity: SealedBox,
    kem_pk: Vec<u8>,
    sig_pk: Vec<u8>,
    /// Creation time, ms since the Unix epoch.
    pub created_ms: u64,
}

impl Header {
    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.suite.id())
            .fixed(&self.unlock.account_id)
            .fixed(&self.unlock.salt);
        self.unlock.kdf.encode(&mut w);
        w.u8(self.factors);
        self.wrapped_account_key.encode(&mut w);
        self.sealed_identity.encode(&mut w);
        w.bytes(&self.kem_pk).bytes(&self.sig_pk).u64(self.created_ms);
        w.finish()
    }

    /// Decode and validate (KDF limits, factor mask). Not yet authenticated.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let suite = Suite::from_id(r.u8()?)?;
        let account_id = r.fixed()?;
        let salt = r.fixed()?;
        let kdf = KdfParams::decode(&mut r)?;
        let factors = r.u8()?;
        if factors & factor_mask::PASSWORD == 0 || factors > 0x0f {
            return Err(passback_crypto::Error::Factors("bad factor mask").into());
        }
        let h = Self {
            suite,
            unlock: UnlockParams { account_id, salt, kdf },
            factors,
            wrapped_account_key: SealedBox::decode(&mut r, 256)?,
            sealed_identity: SealedBox::decode(&mut r, 256)?,
            kem_pk: r.bytes(4096)?.to_vec(),
            sig_pk: r.bytes(4096)?.to_vec(),
            created_ms: r.u64()?,
        };
        r.finish()?;
        Ok(h)
    }

    /// Account id.
    pub fn account_id(&self) -> &Id {
        &self.unlock.account_id
    }
}

fn header_mac(ak: &AccountKey, header_bytes: &[u8]) -> [u8; 32] {
    let k = hash::hkdf_key(ak.key().expose(), b"", b"passback/v1/header-mac");
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(k.expose()).expect("any key length");
    m.update(MAC_DOMAIN);
    m.update(header_bytes);
    m.finalize().into_bytes().into()
}

/// An unlocked account: header, account key and identity.
pub struct Account {
    header: Header,
    ak: AccountKey,
    identity: Identity,
}

impl Account {
    /// Create a new account protected by `factors` (must include a password).
    pub fn create(factors: &[Factor<'_>], kdf: KdfParams, now_ms: u64) -> Result<Self> {
        let unlock = UnlockParams::generate(kdf)?;
        let uk = derive_unlock_key(&unlock, factors)?;
        let ak = AccountKey::generate()?;
        let identity = Identity::generate()?;
        let header = Header {
            suite: Suite::CURRENT,
            factors: mask_of(factors),
            wrapped_account_key: ak.wrap(&uk, &unlock.account_id)?,
            sealed_identity: ak.seal_identity(&unlock.account_id, &identity)?,
            kem_pk: identity.kem.public().as_bytes().to_vec(),
            sig_pk: identity.sign.public().as_bytes().to_vec(),
            unlock,
            created_ms: now_ms,
        };
        Ok(Self { header, ak, identity })
    }

    /// Unlock from stored header bytes and MAC. Checks, in order: header decoding and
    /// limits, factor set, unlock key, header MAC, identity matches the public keys.
    pub fn unlock(header_bytes: &[u8], mac: &[u8; 32], factors: &[Factor<'_>]) -> Result<Self> {
        let header = Header::decode(header_bytes)?;
        if mask_of(factors) != header.factors {
            return Err(passback_crypto::Error::Factors("factor set does not match this vault").into());
        }
        let uk = derive_unlock_key(&header.unlock, factors)?;
        let ak = AccountKey::unwrap(&uk, &header.unlock.account_id, &header.wrapped_account_key)?;
        if !bool::from(header_mac(&ak, header_bytes).ct_eq(mac)) {
            return Err(FormatError::HeaderTampered);
        }
        let identity = ak.open_identity(&header.unlock.account_id, &header.sealed_identity)?;
        if identity.kem.public().as_bytes() != header.kem_pk || identity.sign.public().as_bytes() != header.sig_pk {
            return Err(FormatError::HeaderTampered);
        }
        Ok(Self { header, ak, identity })
    }

    /// Header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Canonical header bytes, as stored.
    pub fn header_bytes(&self) -> Vec<u8> {
        self.header.encode()
    }

    /// MAC over the header bytes.
    pub fn header_mac(&self) -> [u8; 32] {
        header_mac(&self.ak, &self.header.encode())
    }

    /// Account id.
    pub fn account_id(&self) -> &Id {
        self.header.account_id()
    }

    /// Account key.
    pub fn account_key(&self) -> &AccountKey {
        &self.ak
    }

    /// Identity (KEM and signing keys).
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Keys allowed to sign this account's vault commits.
    pub fn signers(&self) -> Signers {
        let mut s = Signers::new();
        s.allow(self.identity.sign.public().clone());
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use passback_crypto::secret_key::SecretKey;

    #[test]
    fn unlock_checks_factors_mac_and_identity() {
        let sk = SecretKey::from_bytes([4; 16]);
        let f = [Factor::Password("pw"), Factor::SecretKey(&sk)];
        let a = Account::create(&f, KdfParams::MIN, 1).unwrap();
        let (bytes, mac) = (a.header_bytes(), a.header_mac());
        let b = Account::unlock(&bytes, &mac, &f).unwrap();
        assert_eq!(b.account_id(), a.account_id());

        assert!(
            Account::unlock(&bytes, &mac, &[Factor::Password("pw")]).is_err(),
            "missing factor"
        );
        let wrong = SecretKey::from_bytes([5; 16]);
        assert!(Account::unlock(&bytes, &mac, &[Factor::Password("pw"), Factor::SecretKey(&wrong)]).is_err());
        let mut bad_mac = mac;
        bad_mac[0] ^= 1;
        assert_eq!(
            Account::unlock(&bytes, &bad_mac, &f).err(),
            Some(FormatError::HeaderTampered)
        );
    }
}
