//! The `.pbv` single-file vault container.
//!
//! ```text
//! file   = magic "PASSBACK" (8) || format u16 (=1) || len(header) || header
//!          || header_mac (32) || len(body) || body || len(sig) || file_sig
//! header = suite || account_id (16) || salt (32) || kdf (12) || factor_mask (1)
//!          || wrapped_account_key || sealed_identity
//!          || len(kem_pk) || kem_pk || len(sig_pk) || sig_pk || created_ms (8)
//! body   = n_vaults (4) || { vault_id (16) || wrapped_vault_key }*
//!          || n_records (4) || record* || n_commits (4) || commit*
//! header_mac = HMAC-SHA256(HKDF(account_key, "passback/v1/header-mac"), magic..header)
//! file_sig   = composite signature ("vault-file") over SHA-256(magic .. body)
//! ```
//!
//! Opening a file checks, in order: magic and version; KDF limits; the unlock key
//! (wrong factors fail here); the header MAC; that the decrypted identity matches the
//! public keys in the header; the whole-file signature; then every vault's commit
//! chain, Merkle roots and records. Nothing from the file is used until every check
//! has passed.

use std::collections::BTreeMap;

use passback_crypto::{
    aead::SealedBox,
    hash,
    kdf::KdfParams,
    keys::{AccountKey, Id, ItemKey, VaultKey, new_id},
    sign::VerifyingKey,
    unlock::Factor,
    wire::{Reader, Writer},
};
use zeroize::Zeroizing;

pub use crate::account::{Header, factor_mask};
use crate::{
    FormatError, Result,
    account::Account,
    commit::{Checkpoint, Commit, Signers, VaultState},
    record::Record,
};

/// File magic.
pub const MAGIC: &[u8; 8] = b"PASSBACK";
/// Container format version.
pub const FORMAT_VERSION: u16 = 1;
const MAX_HEADER: usize = 64 * 1024;
/// Largest vault body (1 GiB).
pub const MAX_BODY: usize = 1 << 30;

/// Check every replayed vault state against the device's checkpoints.
/// Returns the vaults that had no checkpoint (first use on this device).
pub fn check_checkpoints<'a>(
    states: impl Iterator<Item = &'a VaultState>,
    known: &BTreeMap<Id, Checkpoint>,
) -> Result<Vec<Id>> {
    let mut seen = Vec::new();
    let mut first_use = Vec::new();
    for st in states {
        seen.push(*st.vault_id());
        match known.get(st.vault_id()) {
            Some(cp) => cp.check(st)?,
            None => first_use.push(*st.vault_id()),
        }
    }
    if let Some(missing) = known.keys().find(|id| !seen.contains(id)) {
        return Err(FormatError::VaultMissing(*missing));
    }
    Ok(first_use)
}

/// One vault inside the file.
pub struct Vault {
    id: Id,
    key: VaultKey,
    wrapped_key: SealedBox,
    state: VaultState,
    records: Vec<Record>,
    commits: Vec<Commit>,
}

impl Vault {
    /// Vault id.
    pub fn id(&self) -> &Id {
        &self.id
    }
    /// Verified state.
    pub fn state(&self) -> &VaultState {
        &self.state
    }
    /// All commits, oldest first.
    pub fn commits(&self) -> &[Commit] {
        &self.commits
    }
}

/// An unlocked, fully verified vault file.
pub struct VaultFile {
    account: Account,
    vaults: Vec<Vault>,
}

/// Result of opening a file.
pub struct Opened {
    /// The verified file.
    pub file: VaultFile,
    /// Vaults this device had no checkpoint for (first use). Callers must record a
    /// checkpoint for them and should tell the user.
    pub first_use: Vec<Id>,
}

/// A file whose account is unlocked and whose header and signature verified, but
/// whose body hasn't been decoded or checked yet. Only [`Unlocked::verify`] gives
/// access to vault contents.
pub struct Unlocked<'a> {
    account: Account,
    body: &'a [u8],
}

impl Unlocked<'_> {
    /// The unlocked account (to load device state MACed with its key).
    pub fn account(&self) -> &Account {
        &self.account
    }

    /// Decode the body, replay every vault's commit chain, and check it against `known`
    /// (see [`VaultFile::open`]).
    pub fn verify(self, known: &BTreeMap<Id, Checkpoint>) -> Result<Opened> {
        let vaults = VaultFile::decode_body(
            self.body,
            self.account.account_key(),
            self.account.identity().sign.public(),
        )?;
        let first_use = check_checkpoints(vaults.iter().map(|v| &v.state), known)?;
        Ok(Opened {
            file: VaultFile {
                account: self.account,
                vaults,
            },
            first_use,
        })
    }
}

/// Read the public header without unlocking (to know which factors to ask for).
pub fn peek(bytes: &[u8]) -> Result<Header> {
    let mut r = Reader::new(bytes);
    if r.raw(8).ok() != Some(&MAGIC[..]) || r.u16().ok() != Some(FORMAT_VERSION) {
        return Err(FormatError::NotAVault);
    }
    Header::decode(r.bytes(MAX_HEADER)?)
}

impl VaultFile {
    /// Create a new, empty vault file protected by `factors`.
    /// Must include a password; production callers should include a Secret Key.
    pub fn create(factors: &[Factor<'_>], kdf: KdfParams, now_ms: u64) -> Result<Self> {
        Ok(Self {
            account: Account::create(factors, kdf, now_ms)?,
            vaults: Vec::new(),
        })
    }

    /// Parse, unlock and verify a vault file.
    ///
    /// `known` holds this device's checkpoints. A vault with a checkpoint must not be
    /// older than it or on another history; a known vault that is missing from the
    /// file is an error too. Vaults without one are reported in [`Opened::first_use`].
    /// Pass an empty map only when this device has never seen any of the file's vaults.
    pub fn open(bytes: &[u8], factors: &[Factor<'_>], known: &BTreeMap<Id, Checkpoint>) -> Result<Opened> {
        Self::unlock(bytes, factors)?.verify(known)
    }

    /// First half of [`VaultFile::open`]: unlock the account and verify the header MAC
    /// and the whole-file signature. Nothing in the body is used yet. Callers that need
    /// the account key to load their checkpoints (device state is MACed with it) use
    /// this, then [`Unlocked::verify`].
    pub fn unlock<'a>(bytes: &'a [u8], factors: &[Factor<'_>]) -> Result<Unlocked<'a>> {
        let mut r = Reader::new(bytes);
        if r.raw(8).ok() != Some(&MAGIC[..]) || r.u16().ok() != Some(FORMAT_VERSION) {
            return Err(FormatError::NotAVault);
        }
        let header_bytes = r.bytes(MAX_HEADER)?;
        let mac: [u8; 32] = r.fixed()?;
        let body = r.bytes(MAX_BODY)?;
        let signed_len = bytes.len() - r.remaining();
        let file_sig = r.bytes(passback_crypto::sign::SIGNATURE_LEN)?;
        r.finish()?;

        let account = Account::unlock(header_bytes, &mac, factors)?;
        let digest = hash::sha256(&bytes[..signed_len]);
        account
            .identity()
            .sign
            .public()
            .verify("vault-file", &digest, file_sig)
            .map_err(|_| FormatError::FileSignature)?;
        Ok(Unlocked { account, body })
    }

    fn decode_body(body: &[u8], ak: &AccountKey, signer: &VerifyingKey) -> Result<Vec<Vault>> {
        let mut r = Reader::new(body);
        let mut vaults: BTreeMap<Id, Vault> = BTreeMap::new();
        for _ in 0..r.u32()? {
            let id: Id = r.fixed()?;
            let wrapped_key = SealedBox::decode(&mut r, 256)?;
            let key = VaultKey::unwrap(ak, &id, &wrapped_key)?;
            let v = Vault {
                id,
                key,
                wrapped_key,
                state: VaultState::new(id),
                records: vec![],
                commits: vec![],
            };
            if vaults.insert(id, v).is_some() {
                return Err(passback_crypto::Error::Malformed("duplicate vault").into());
            }
        }
        let mut records: BTreeMap<(Id, Id, u64), Record> = BTreeMap::new();
        for _ in 0..r.u32()? {
            let rec = Record::decode(&mut r)?;
            records.insert((rec.vault_id, rec.item_id, rec.version), rec);
        }
        let mut signers = Signers::new();
        signers.allow(signer.clone());
        for _ in 0..r.u32()? {
            let c = Commit::decode(&mut r)?;
            let v = vaults.get_mut(&c.vault_id).ok_or(FormatError::RecordMismatch)?;
            let recs: Vec<&Record> = c
                .changes
                .iter()
                .map(|ch| {
                    records
                        .get(&(c.vault_id, ch.item_id, ch.version))
                        .ok_or(FormatError::RecordMismatch)
                })
                .collect::<Result<_>>()?;
            v.state.apply(&c, &signers, &recs)?;
            v.commits.push(c);
        }
        r.finish()?;
        let mut used = 0;
        for v in vaults.values_mut() {
            for c in &v.commits {
                for ch in &c.changes {
                    v.records.push(records[&(v.id, ch.item_id, ch.version)].clone());
                    used += 1;
                }
            }
        }
        if used != records.len() {
            return Err(FormatError::RecordMismatch);
        }
        Ok(vaults.into_values().collect())
    }

    /// Serialize, MAC and sign.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let header_bytes = self.account.header_bytes();
        let mut body = Writer::new();
        body.u32(self.vaults.len() as u32);
        for v in &self.vaults {
            body.fixed(&v.id);
            v.wrapped_key.encode(&mut body);
        }
        let all_records: Vec<&Record> = self.vaults.iter().flat_map(|v| v.records.iter()).collect();
        body.u32(all_records.len() as u32);
        for r in all_records {
            r.encode(&mut body);
        }
        let all_commits: Vec<&Commit> = self.vaults.iter().flat_map(|v| v.commits.iter()).collect();
        body.u32(all_commits.len() as u32);
        for c in all_commits {
            c.encode(&mut body);
        }
        let body = body.finish();
        if body.len() > MAX_BODY {
            return Err(FormatError::Limit("vault body too large"));
        }
        let mut w = Writer::new();
        w.fixed(MAGIC).u16(FORMAT_VERSION).bytes(&header_bytes);
        w.fixed(&self.account.header_mac()).bytes(&body);
        let mut out = w.finish();
        let sig = self.account.identity().sign.sign("vault-file", &hash::sha256(&out))?;
        let mut tail = Writer::new();
        tail.bytes(&sig);
        out.extend_from_slice(&tail.finish());
        Ok(out)
    }

    /// Header.
    pub fn header(&self) -> &Header {
        self.account.header()
    }

    /// The unlocked account.
    pub fn account(&self) -> &Account {
        &self.account
    }

    /// Checkpoints of every vault in the file, to record on this device.
    pub fn checkpoints(&self) -> BTreeMap<Id, Checkpoint> {
        self.vaults.iter().map(|v| (v.id, v.state.checkpoint())).collect()
    }

    /// Vaults.
    pub fn vaults(&self) -> &[Vault] {
        &self.vaults
    }

    fn vault_mut(&mut self, id: &Id) -> Result<&mut Vault> {
        self.vaults
            .iter_mut()
            .find(|v| &v.id == id)
            .ok_or(FormatError::RecordMismatch)
    }

    /// Add an empty vault.
    pub fn add_vault(&mut self) -> Result<Id> {
        let id = new_id()?;
        let key = VaultKey::generate()?;
        let wrapped_key = key.wrap(self.account.account_key(), &id)?;
        self.vaults.push(Vault {
            id,
            key,
            wrapped_key,
            state: VaultState::new(id),
            records: vec![],
            commits: vec![],
        });
        Ok(id)
    }

    fn commit_records(&mut self, vault: &Id, recs: Vec<Record>, device: Id, now_ms: u64) -> Result<()> {
        let signers = self.account.signers();
        let sign_key = &self.account.identity().sign;
        let v = self
            .vaults
            .iter_mut()
            .find(|v| &v.id == vault)
            .ok_or(FormatError::RecordMismatch)?;
        let refs: Vec<&Record> = recs.iter().collect();
        let c = v.state.prepare(&refs, device, sign_key, now_ms)?;
        v.state.apply(&c, &signers, &refs)?;
        v.commits.push(c);
        v.records.extend(recs);
        Ok(())
    }

    /// Write a new version of an item (creates it if absent). Returns the new version.
    pub fn put(&mut self, vault: &Id, item: &Id, plaintext: &[u8], device: Id, now_ms: u64) -> Result<u64> {
        let v = self.vault_mut(vault)?;
        let version = v.state.item(item).map(|(n, _)| n + 1).unwrap_or(1);
        let rec = Record::seal(&v.key, *vault, *item, version, &ItemKey::generate()?, plaintext)?;
        self.commit_records(vault, vec![rec], device, now_ms)?;
        Ok(version)
    }

    /// Delete an item (signed tombstone).
    pub fn delete(&mut self, vault: &Id, item: &Id, device: Id, now_ms: u64) -> Result<()> {
        let v = self.vault_mut(vault)?;
        let version = v
            .state
            .item(item)
            .map(|(n, _)| n + 1)
            .ok_or(FormatError::RecordMismatch)?;
        let rec = Record::tombstone(&v.key, *vault, *item, version)?;
        self.commit_records(vault, vec![rec], device, now_ms)
    }

    /// Current plaintext of an item; `None` if absent or deleted.
    pub fn get(&self, vault: &Id, item: &Id) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let Some(v) = self.vaults.iter().find(|v| &v.id == vault) else {
            return Ok(None);
        };
        let Some((version, _)) = v.state.item(item) else {
            return Ok(None);
        };
        let rec = v
            .records
            .iter()
            .find(|r| &r.item_id == item && r.version == version)
            .ok_or(FormatError::RecordMismatch)?;
        if rec.tombstone {
            return Ok(None);
        }
        Ok(Some(rec.open(&v.key)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use passback_crypto::secret_key::SecretKey;

    fn open(bytes: &[u8], f: &[Factor<'_>]) -> Result<VaultFile> {
        VaultFile::open(bytes, f, &BTreeMap::new()).map(|o| o.file)
    }

    fn kdf() -> KdfParams {
        KdfParams::MIN
    }

    #[test]
    fn create_write_reopen() {
        let sk = SecretKey::generate().unwrap();
        let f = [Factor::Password("pw"), Factor::SecretKey(&sk)];
        let dev = new_id().unwrap();
        let mut vf = VaultFile::create(&f, kdf(), 1).unwrap();
        let v = vf.add_vault().unwrap();
        let (a, b) = (new_id().unwrap(), new_id().unwrap());
        vf.put(&v, &a, b"alpha", dev, 2).unwrap();
        vf.put(&v, &b, b"beta", dev, 3).unwrap();
        assert_eq!(vf.put(&v, &a, b"alpha2", dev, 4).unwrap(), 2);
        vf.delete(&v, &b, dev, 5).unwrap();
        let bytes = vf.to_bytes().unwrap();

        assert_eq!(
            peek(&bytes).unwrap().factors,
            factor_mask::PASSWORD | factor_mask::SECRET_KEY
        );
        let re = open(&bytes, &f).unwrap();
        assert_eq!(&*re.get(&v, &a).unwrap().unwrap(), b"alpha2");
        assert!(re.get(&v, &b).unwrap().is_none());
        assert_eq!(re.vaults()[0].state(), vf.vaults()[0].state());
        assert_eq!(re.to_bytes().unwrap().len(), bytes.len());

        assert!(open(&bytes, &[Factor::Password("pw")]).is_err(), "missing secret key");
        let wrong = SecretKey::generate().unwrap();
        assert!(open(&bytes, &[Factor::Password("pw"), Factor::SecretKey(&wrong)]).is_err());
        assert!(open(&bytes, &[Factor::Password("px"), Factor::SecretKey(&sk)]).is_err());
    }

    fn small_file() -> (VaultFile, Id) {
        let mut vf = VaultFile::create(&[Factor::Password("pw")], kdf(), 1).unwrap();
        let v = vf.add_vault().unwrap();
        vf.put(&v, &new_id().unwrap(), b"x", new_id().unwrap(), 2).unwrap();
        (vf, v)
    }

    #[test]
    fn validly_signed_files_with_inconsistent_bodies_are_rejected() {
        let f = [Factor::Password("pw")];

        // Duplicate vault id.
        let (mut vf, v) = small_file();
        let wrapped = vf.vaults[0].wrapped_key.clone();
        let key = VaultKey::unwrap(vf.account.account_key(), &v, &wrapped).unwrap();
        vf.vaults.push(Vault {
            id: v,
            key,
            wrapped_key: wrapped,
            state: VaultState::new(v),
            records: vec![],
            commits: vec![],
        });
        assert_eq!(
            open(&vf.to_bytes().unwrap(), &f).err(),
            Some(passback_crypto::Error::Malformed("duplicate vault").into())
        );

        // A record no commit refers to.
        let (mut vf, v) = small_file();
        let extra = Record::seal(
            &vf.vaults[0].key,
            v,
            new_id().unwrap(),
            1,
            &ItemKey::generate().unwrap(),
            b"y",
        )
        .unwrap();
        vf.vaults[0].records.push(extra);
        assert_eq!(
            open(&vf.to_bytes().unwrap(), &f).err(),
            Some(FormatError::RecordMismatch)
        );

        // A commit whose record is missing.
        let (mut vf, _) = small_file();
        vf.vaults[0].records.clear();
        assert_eq!(
            open(&vf.to_bytes().unwrap(), &f).err(),
            Some(FormatError::RecordMismatch)
        );

        // A commit for a vault the file does not contain.
        let (mut vf, _) = small_file();
        let ghost = new_id().unwrap();
        let gk = VaultKey::generate().unwrap();
        let grec = Record::seal(&gk, ghost, new_id().unwrap(), 1, &ItemKey::generate().unwrap(), b"z").unwrap();
        let gc = VaultState::new(ghost)
            .prepare(&[&grec], new_id().unwrap(), &vf.account.identity().sign, 3)
            .unwrap();
        vf.vaults[0].records.push(grec);
        vf.vaults[0].commits.push(gc);
        assert_eq!(
            open(&vf.to_bytes().unwrap(), &f).err(),
            Some(FormatError::RecordMismatch)
        );
    }

    #[test]
    fn device_checkpoints_are_enforced_on_open() {
        let f = [Factor::Password("pw")];
        let (mut vf, v) = small_file();
        let old_bytes = vf.to_bytes().unwrap();
        let old_cp = vf.checkpoints();
        vf.put(&v, &new_id().unwrap(), b"newer", new_id().unwrap(), 3).unwrap();
        let new_bytes = vf.to_bytes().unwrap();
        let new_cp = vf.checkpoints();

        // Fresh device: every vault is first use.
        let o = VaultFile::open(&new_bytes, &f, &BTreeMap::new()).unwrap();
        assert_eq!(o.first_use, vec![v]);
        // Device saw the old state: newer file is fine, nothing is first use.
        assert!(VaultFile::open(&new_bytes, &f, &old_cp).unwrap().first_use.is_empty());
        // Device saw the new state: the old file is a rollback.
        assert!(matches!(
            VaultFile::open(&old_bytes, &f, &new_cp).err(),
            Some(FormatError::Rollback { seen: 2, got: 1 })
        ));
        // Device knows a vault the file doesn't contain.
        let mut known = new_cp.clone();
        let ghost = new_id().unwrap();
        known.insert(
            ghost,
            Checkpoint {
                vault_id: ghost,
                seq: 1,
                head: [9; 32],
            },
        );
        assert_eq!(
            VaultFile::open(&new_bytes, &f, &known).err(),
            Some(FormatError::VaultMissing(ghost))
        );
    }

    #[test]
    fn header_without_password_factor_or_with_unknown_bits_is_rejected() {
        let (vf, _) = small_file();
        let bytes = vf.to_bytes().unwrap();
        // magic(8) + format(2) + header len(4) + suite(1) + account(16) + salt(32) + kdf(12).
        let at = 8 + 2 + 4 + 1 + 16 + 32 + 12;
        assert_eq!(bytes[at], factor_mask::PASSWORD);
        for mask in [factor_mask::SECRET_KEY, 0x10 | factor_mask::PASSWORD] {
            let mut t = bytes.clone();
            t[at] = mask;
            assert!(peek(&t).is_err(), "mask {mask:#x} accepted");
        }
        assert_eq!(peek(b"NOTAVAULT-at-all").err(), Some(FormatError::NotAVault));
    }

    #[test]
    fn any_byte_flip_is_rejected() {
        let f = [Factor::Password("pw")];
        let mut vf = VaultFile::create(&f, kdf(), 1).unwrap();
        let v = vf.add_vault().unwrap();
        vf.put(&v, &new_id().unwrap(), b"x", new_id().unwrap(), 2).unwrap();
        let bytes = vf.to_bytes().unwrap();
        // Sample positions across the file; KDF params are excluded where a flip
        // would only make Argon2 slower/larger (still rejected, but slow in tests).
        let step = (bytes.len() / 97).max(1);
        for i in (0..bytes.len()).step_by(step) {
            let mut t = bytes.clone();
            t[i] ^= 0x01;
            assert!(open(&t, &f).is_err(), "flip at {i} accepted");
        }
        // Truncation and trailing garbage.
        assert!(open(&bytes[..bytes.len() - 1], &f).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(open(&longer, &f).is_err());
    }
}
