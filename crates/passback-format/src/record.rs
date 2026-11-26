//! Records: one encrypted version of one item.

use passback_crypto::{
    aead::SealedBox,
    hash,
    keys::{Id, ItemKey, VaultKey},
    wire::{Reader, Writer},
};

use crate::{FormatError, Result};

/// Largest accepted sealed item content (16 MiB; attachments are stored separately).
pub const MAX_CONTENT: usize = 16 * 1024 * 1024;

/// One item version as stored. Everything about the item (title, URLs, fields,
/// tags) is inside `content`; only the ids and version are visible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Vault the item belongs to.
    pub vault_id: Id,
    /// Item id.
    pub item_id: Id,
    /// Monotonic per-item version, starting at 1.
    pub version: u64,
    /// True if this version deletes the item. Deletions are signed like any change.
    pub tombstone: bool,
    /// Item key wrapped by the vault key.
    pub item_key: SealedBox,
    /// Item content sealed by the item key. Empty-plaintext box for tombstones.
    pub content: SealedBox,
}

impl Record {
    /// Encrypt a new item version.
    pub fn seal(
        vk: &VaultKey,
        vault_id: Id,
        item_id: Id,
        version: u64,
        ik: &ItemKey,
        plaintext: &[u8],
    ) -> Result<Self> {
        if version == 0 {
            return Err(FormatError::VersionRegression);
        }
        Ok(Self {
            vault_id,
            item_id,
            version,
            tombstone: false,
            item_key: ik.wrap(vk, &vault_id, &item_id)?,
            content: ik.seal_content(&vault_id, &item_id, version, plaintext)?,
        })
    }

    /// Build a deletion marker.
    pub fn tombstone(vk: &VaultKey, vault_id: Id, item_id: Id, version: u64) -> Result<Self> {
        let ik = ItemKey::generate()?;
        let mut r = Self::seal(vk, vault_id, item_id, version, &ik, b"")?;
        r.tombstone = true;
        Ok(r)
    }

    /// Decrypt. Tombstones return an empty plaintext.
    pub fn open(&self, vk: &VaultKey) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let ik = ItemKey::unwrap(vk, &self.vault_id, &self.item_id, &self.item_key)?;
        Ok(ik.open_content(&self.vault_id, &self.item_id, self.version, &self.content)?)
    }

    /// Canonical encoding.
    pub fn encode(&self, w: &mut Writer) {
        w.u8(1)
            .fixed(&self.vault_id)
            .fixed(&self.item_id)
            .u64(self.version)
            .u8(self.tombstone as u8);
        self.item_key.encode(w);
        self.content.encode(w);
    }

    /// Encode to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w);
        w.finish()
    }

    /// Decode.
    pub fn decode(r: &mut Reader<'_>) -> Result<Self> {
        if r.u8()? != 1 {
            return Err(passback_crypto::Error::Malformed("record version").into());
        }
        let vault_id = r.fixed()?;
        let item_id = r.fixed()?;
        let version = r.u64()?;
        let tombstone = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(passback_crypto::Error::Malformed("tombstone flag").into()),
        };
        let item_key = SealedBox::decode(r, 1024)?;
        let content = SealedBox::decode(r, MAX_CONTENT)?;
        Ok(Self {
            vault_id,
            item_id,
            version,
            tombstone,
            item_key,
            content,
        })
    }

    /// Hash that commits refer to.
    pub fn hash(&self) -> [u8; 32] {
        hash::sha256_labeled("passback/v1/record", &[&self.to_bytes()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use passback_crypto::keys::new_id;

    #[test]
    fn version_zero_is_refused() {
        let vk = VaultKey::generate().unwrap();
        let ik = ItemKey::generate().unwrap();
        let err = Record::seal(&vk, new_id().unwrap(), new_id().unwrap(), 0, &ik, b"x").unwrap_err();
        assert_eq!(err, FormatError::VersionRegression);
    }

    #[test]
    fn decode_rejects_unknown_record_version_and_bad_tombstone_flag() {
        let vk = VaultKey::generate().unwrap();
        let r = Record::seal(
            &vk,
            new_id().unwrap(),
            new_id().unwrap(),
            1,
            &ItemKey::generate().unwrap(),
            b"x",
        )
        .unwrap();
        let enc = r.to_bytes();
        assert_eq!(Record::decode(&mut Reader::new(&enc)).unwrap(), r);

        let mut bad_version = enc.clone();
        bad_version[0] = 2;
        assert!(Record::decode(&mut Reader::new(&bad_version)).is_err());

        // Offset of the tombstone flag: version(1) + vault_id(16) + item_id(16) + version(8).
        let mut bad_flag = enc.clone();
        bad_flag[41] = 2;
        assert!(Record::decode(&mut Reader::new(&bad_flag)).is_err());
    }
}
