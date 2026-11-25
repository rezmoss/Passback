//! Key hierarchy.
//!
//! ```text
//! Unlock key (from factors, never stored)
//!   └─ wraps Account key (random)
//!        ├─ wraps Identity: X-Wing KEM seed + composite signing seed
//!        └─ wraps Vault key (random, per vault)      ── or, for shared vaults, sealed to each
//!             └─ wraps Item key (random, per item)        member's X-Wing public key
//!                  └─ encrypts item content (all fields and metadata)
//! ```
//!
//! Every wrap is bound to the ids of the object it belongs to, so a wrapped key or
//! item ciphertext moved to another vault, item or version fails to open.
//! Each level is its own type, so a vault key can't be passed where an item key is
//! expected.

use zeroize::Zeroizing;

use crate::{
    Error, Key32, Result,
    aead::{self, SealedBox},
    kem::{self, KemBox, KemPublicKey, KemSecretKey},
    sign::SigningKey,
    wire::Writer,
};

/// 16-byte random identifier (account, vault, item, device).
pub type Id = [u8; 16];

/// New random id.
pub fn new_id() -> Result<Id> {
    crate::rand::array()
}

fn ids(parts: &[&[u8]]) -> Vec<u8> {
    let mut w = Writer::new();
    for p in parts {
        w.bytes(p);
    }
    w.finish()
}

macro_rules! typed_key {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Debug)]
        pub struct $name(Key32);
        impl $name {
            /// Generate a fresh random key.
            pub fn generate() -> Result<Self> {
                Ok(Self(Key32::generate()?))
            }
            fn from_plain(b: &[u8]) -> Result<Self> {
                Ok(Self(Key32::from_slice(b)?))
            }
            /// Raw key, for use with [`crate::aead`] directly.
            pub fn key(&self) -> &Key32 {
                &self.0
            }
        }
    };
}

typed_key!(
    /// Top-level symmetric key of an account. Wrapped by the unlock key.
    AccountKey
);
typed_key!(
    /// Per-vault symmetric key.
    VaultKey
);
typed_key!(
    /// Per-item symmetric key.
    ItemKey
);

/// The account's long-term asymmetric keys.
pub struct Identity {
    /// For receiving shared vault keys.
    pub kem: KemSecretKey,
    /// For signing commits, devices and audit entries.
    pub sign: SigningKey,
}

impl Identity {
    /// Generate a new identity.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            kem: KemSecretKey::generate()?,
            sign: SigningKey::generate()?,
        })
    }
}

impl AccountKey {
    /// Wrap with the unlock key.
    pub fn wrap(&self, unlock: &Key32, account_id: &Id) -> Result<SealedBox> {
        aead::seal(unlock, "account-key", &ids(&[account_id]), self.0.expose())
    }

    /// Unwrap with the unlock key. A wrong password/Secret Key fails here.
    pub fn unwrap(unlock: &Key32, account_id: &Id, b: &SealedBox) -> Result<Self> {
        Self::from_plain(&aead::open(unlock, "account-key", &ids(&[account_id]), b)?)
    }

    /// Encrypt the identity's private seeds.
    pub fn seal_identity(&self, account_id: &Id, id: &Identity) -> Result<SealedBox> {
        let mut pt = Zeroizing::new(Vec::with_capacity(64));
        pt.extend_from_slice(id.kem.seed().expose());
        pt.extend_from_slice(id.sign.seed().expose());
        aead::seal(&self.0, "identity", &ids(&[account_id]), &pt)
    }

    /// Decrypt the identity.
    pub fn open_identity(&self, account_id: &Id, b: &SealedBox) -> Result<Identity> {
        let pt = aead::open(&self.0, "identity", &ids(&[account_id]), b)?;
        if pt.len() != 64 {
            return Err(Error::Malformed("identity length"));
        }
        Ok(Identity {
            kem: KemSecretKey::from_seed(Key32::from_slice(&pt[..32])?),
            sign: SigningKey::from_seed(Key32::from_slice(&pt[32..])?),
        })
    }
}

impl VaultKey {
    /// Wrap for the vault owner's own account.
    pub fn wrap(&self, ak: &AccountKey, vault_id: &Id) -> Result<SealedBox> {
        aead::seal(ak.key(), "vault-key", &ids(&[vault_id]), self.0.expose())
    }

    /// Unwrap with the account key.
    pub fn unwrap(ak: &AccountKey, vault_id: &Id, b: &SealedBox) -> Result<Self> {
        Self::from_plain(&aead::open(ak.key(), "vault-key", &ids(&[vault_id]), b)?)
    }

    /// Seal to a member's public key (sharing).
    pub fn share(&self, member: &KemPublicKey, vault_id: &Id, member_id: &Id) -> Result<KemBox> {
        kem::seal_to(member, "vault-key-share", &ids(&[vault_id, member_id]), self.0.expose())
    }

    /// Open a vault key shared with us.
    pub fn accept(identity: &Identity, vault_id: &Id, member_id: &Id, b: &KemBox) -> Result<Self> {
        Self::from_plain(&kem::open_from(
            &identity.kem,
            "vault-key-share",
            &ids(&[vault_id, member_id]),
            b,
        )?)
    }
}

impl ItemKey {
    /// Wrap with the vault key.
    pub fn wrap(&self, vk: &VaultKey, vault_id: &Id, item_id: &Id) -> Result<SealedBox> {
        aead::seal(vk.key(), "item-key", &ids(&[vault_id, item_id]), self.0.expose())
    }

    /// Unwrap with the vault key.
    pub fn unwrap(vk: &VaultKey, vault_id: &Id, item_id: &Id, b: &SealedBox) -> Result<Self> {
        Self::from_plain(&aead::open(vk.key(), "item-key", &ids(&[vault_id, item_id]), b)?)
    }

    /// Encrypt one version of an item's content.
    pub fn seal_content(&self, vault_id: &Id, item_id: &Id, version: u64, pt: &[u8]) -> Result<SealedBox> {
        aead::seal(
            &self.0,
            "item-content",
            &ids(&[vault_id, item_id, &version.to_be_bytes()]),
            pt,
        )
    }

    /// Decrypt one version of an item's content.
    pub fn open_content(&self, vault_id: &Id, item_id: &Id, version: u64, b: &SealedBox) -> Result<Zeroizing<Vec<u8>>> {
        aead::open(
            &self.0,
            "item-content",
            &ids(&[vault_id, item_id, &version.to_be_bytes()]),
            b,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_chain_and_binding() {
        let unlock = Key32::generate().unwrap();
        let (acct, vault, item, other) = (
            new_id().unwrap(),
            new_id().unwrap(),
            new_id().unwrap(),
            new_id().unwrap(),
        );

        let ak = AccountKey::generate().unwrap();
        let w_ak = ak.wrap(&unlock, &acct).unwrap();
        let ak = AccountKey::unwrap(&unlock, &acct, &w_ak).unwrap();
        assert!(AccountKey::unwrap(&Key32::generate().unwrap(), &acct, &w_ak).is_err());

        let ident = Identity::generate().unwrap();
        let w_id = ak.seal_identity(&acct, &ident).unwrap();
        let ident2 = ak.open_identity(&acct, &w_id).unwrap();
        assert_eq!(ident.sign.public(), ident2.sign.public());

        let vk = VaultKey::generate().unwrap();
        let w_vk = vk.wrap(&ak, &vault).unwrap();
        let vk = VaultKey::unwrap(&ak, &vault, &w_vk).unwrap();
        assert!(VaultKey::unwrap(&ak, &other, &w_vk).is_err(), "moved to another vault");

        let ik = ItemKey::generate().unwrap();
        let w_ik = ik.wrap(&vk, &vault, &item).unwrap();
        let ik = ItemKey::unwrap(&vk, &vault, &item, &w_ik).unwrap();
        assert!(
            ItemKey::unwrap(&vk, &vault, &other, &w_ik).is_err(),
            "moved to another item"
        );

        let c = ik.seal_content(&vault, &item, 3, b"{\"password\":\"x\"}").unwrap();
        assert_eq!(
            &*ik.open_content(&vault, &item, 3, &c).unwrap(),
            b"{\"password\":\"x\"}"
        );
        assert!(
            ik.open_content(&vault, &item, 2, &c).is_err(),
            "rolled back to another version"
        );

        let bob = Identity::generate().unwrap();
        let shared = vk.share(bob.kem.public(), &vault, &other).unwrap();
        let bob_vk = VaultKey::accept(&bob, &vault, &other, &shared).unwrap();
        assert_eq!(bob_vk.key().expose(), vk.key().expose());
        assert!(
            VaultKey::accept(&ident, &vault, &other, &shared).is_err(),
            "not the recipient"
        );
    }
}
