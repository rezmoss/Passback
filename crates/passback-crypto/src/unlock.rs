//! Unlock key derivation from one or more factors (two-secret key derivation).
//!
//! ```text
//! pw_salt = HKDF(ikm = salt, salt = account_id, info = "passback/v1/pw-salt")
//! k_pw    = Argon2id(NFKC(password), pw_salt, params)
//! k_i     = HKDF(ikm = factor_i, salt = account_id, info = "passback/v1/factor/" || name_i)
//! UK      = HKDF(ikm = k_pw || k_1 || ... , salt = account_id,
//!                info = "passback/v1/unlock" || factor-type list)
//! ```
//!
//! Factors are sorted by type, so the result does not depend on the order the
//! caller passes them. The factor-type list is part of `info`, so removing a factor
//! changes the key; there is no way to "downgrade" to fewer factors.

use zeroize::Zeroizing;

use crate::{Error, Key32, Result, hash, kdf::KdfParams, secret_key::SecretKey};

/// One unlock factor.
pub enum Factor<'a> {
    /// The master password. Always required.
    Password(&'a str),
    /// The account Secret Key (two-secret key derivation).
    SecretKey(&'a SecretKey),
    /// Contents of a key file (hashed before use).
    KeyFile(&'a [u8]),
    /// A 32-byte response from a hardware authenticator (FIDO2 hmac-secret/PRF,
    /// YubiKey challenge-response, TPM/Secure Enclave unseal).
    Hardware(&'a [u8; 32]),
}

impl Factor<'_> {
    fn type_id(&self) -> u8 {
        match self {
            Factor::Password(_) => 1,
            Factor::SecretKey(_) => 2,
            Factor::KeyFile(_) => 3,
            Factor::Hardware(_) => 4,
        }
    }
    fn name(&self) -> &'static str {
        match self {
            Factor::Password(_) => "password",
            Factor::SecretKey(_) => "secret-key",
            Factor::KeyFile(_) => "key-file",
            Factor::Hardware(_) => "hardware",
        }
    }
}

/// Public, non-secret inputs stored with the account/vault header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnlockParams {
    /// Random account identifier.
    pub account_id: [u8; 16],
    /// Random per-account salt.
    pub salt: [u8; 32],
    /// Argon2id parameters.
    pub kdf: KdfParams,
}

impl UnlockParams {
    /// Fresh parameters for a new account.
    pub fn generate(kdf: KdfParams) -> Result<Self> {
        kdf.validate()?;
        Ok(Self {
            account_id: crate::rand::array()?,
            salt: crate::rand::array()?,
            kdf,
        })
    }
}

/// Derive the unlock key from `factors`.
pub fn derive_unlock_key(params: &UnlockParams, factors: &[Factor<'_>]) -> Result<Key32> {
    let mut sorted: Vec<&Factor<'_>> = factors.iter().collect();
    sorted.sort_by_key(|f| f.type_id());
    if sorted.windows(2).any(|w| w[0].type_id() == w[1].type_id()) {
        return Err(Error::Factors("duplicate factor type"));
    }
    let Some(Factor::Password(password)) = sorted.first() else {
        return Err(Error::Factors("password factor is required"));
    };

    let mut pw_salt = Zeroizing::new([0u8; 32]);
    hash::hkdf(
        &params.salt,
        &params.account_id,
        b"passback/v1/pw-salt",
        &mut pw_salt[..],
    );
    let k_pw = crate::kdf::derive(password, &pw_salt, &params.kdf)?;

    let mut ikm = Zeroizing::new(Vec::with_capacity(32 * sorted.len()));
    ikm.extend_from_slice(k_pw.expose());
    let mut info = b"passback/v1/unlock".to_vec();
    info.push(sorted[0].type_id());

    for f in &sorted[1..] {
        let material: Zeroizing<Vec<u8>> = match f {
            Factor::SecretKey(sk) => Zeroizing::new(sk.expose().to_vec()),
            Factor::KeyFile(bytes) => Zeroizing::new(hash::sha256(bytes).to_vec()),
            Factor::Hardware(r) => Zeroizing::new(r.to_vec()),
            Factor::Password(_) => unreachable!("only first after sort"),
        };
        let label = format!("passback/v1/factor/{}", f.name());
        let k = hash::hkdf_key(&material, &params.account_id, label.as_bytes());
        ikm.extend_from_slice(k.expose());
        info.push(f.type_id());
    }

    Ok(hash::hkdf_key(&ikm, &params.account_id, &info))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> UnlockParams {
        UnlockParams {
            account_id: [1; 16],
            salt: [2; 32],
            kdf: KdfParams::MIN,
        }
    }

    #[test]
    fn order_independent_and_factor_bound() {
        let sk = SecretKey::from_bytes([9; 16]);
        let p = params();
        let a = derive_unlock_key(&p, &[Factor::Password("pw"), Factor::SecretKey(&sk)]).unwrap();
        let b = derive_unlock_key(&p, &[Factor::SecretKey(&sk), Factor::Password("pw")]).unwrap();
        assert_eq!(a.expose(), b.expose());

        let pw_only = derive_unlock_key(&p, &[Factor::Password("pw")]).unwrap();
        assert_ne!(a.expose(), pw_only.expose());
        let other_sk = SecretKey::from_bytes([8; 16]);
        let c = derive_unlock_key(&p, &[Factor::Password("pw"), Factor::SecretKey(&other_sk)]).unwrap();
        assert_ne!(a.expose(), c.expose());
        let mut p2 = p.clone();
        p2.account_id = [3; 16];
        let d = derive_unlock_key(&p2, &[Factor::Password("pw"), Factor::SecretKey(&sk)]).unwrap();
        assert_ne!(a.expose(), d.expose());
    }

    #[test]
    fn key_file_and_hardware_factors_are_bound() {
        let p = params();
        let base = derive_unlock_key(&p, &[Factor::Password("pw")]).unwrap();
        let kf = derive_unlock_key(&p, &[Factor::Password("pw"), Factor::KeyFile(b"file-a")]).unwrap();
        let kf2 = derive_unlock_key(&p, &[Factor::Password("pw"), Factor::KeyFile(b"file-b")]).unwrap();
        let hw = derive_unlock_key(&p, &[Factor::Password("pw"), Factor::Hardware(&[1; 32])]).unwrap();
        let hw2 = derive_unlock_key(&p, &[Factor::Password("pw"), Factor::Hardware(&[2; 32])]).unwrap();
        // Same 32 bytes as a key file vs as a hardware response must not collide.
        let same_bytes_kf = derive_unlock_key(&p, &[Factor::Password("pw"), Factor::KeyFile(&[1; 32])]).unwrap();
        let keys = [&base, &kf, &kf2, &hw, &hw2, &same_bytes_kf];
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a.expose(), b.expose());
            }
        }
    }

    #[test]
    fn nfkc_normalization() {
        let p = params();
        // "é" precomposed vs "e" + combining acute.
        let a = derive_unlock_key(&p, &[Factor::Password("caf\u{e9}")]).unwrap();
        let b = derive_unlock_key(&p, &[Factor::Password("cafe\u{301}")]).unwrap();
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn rejects_bad_factor_sets() {
        let p = params();
        let sk = SecretKey::from_bytes([9; 16]);
        assert!(derive_unlock_key(&p, &[Factor::SecretKey(&sk)]).is_err());
        assert!(derive_unlock_key(&p, &[Factor::Password("a"), Factor::Password("b")]).is_err());
        let mut weak = p.clone();
        weak.kdf.m_kib = 1024;
        assert!(derive_unlock_key(&weak, &[Factor::Password("a")]).is_err());
    }
}
