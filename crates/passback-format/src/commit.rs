//! Signed, hash-chained vault commits.
//!
//! Every change to a vault is a [`Commit`]: it names the previous commit's hash,
//! lists the changed items with their record hashes, states the Merkle root of the
//! whole item set *after* the change, and is signed with the author's composite
//! (Ed25519 + ML-DSA-65) key. Replaying commits with [`VaultState::apply`] verifies
//! all of this, so a server or sync folder that stores the vault can't:
//!
//! - change or swap an item (record hash mismatch),
//! - drop or hide an item (Merkle root mismatch),
//! - reorder or rewrite history (prev-hash chain),
//! - forge a change (signature by an authorized key),
//! - serve an older version (sequence number below the device's [`Checkpoint`]),
//! - show different histories to different devices (fork detection).

use std::collections::BTreeMap;

use hmac::{Hmac, KeyInit, Mac};
use passback_crypto::{
    Key32, hash,
    keys::Id,
    sign::{SigningKey, VerifyingKey},
    wire::{Reader, Writer},
};
use sha2::Sha256;

use crate::{
    FormatError, Result,
    merkle::{self, Hash},
    record::Record,
};

/// Most changes accepted in one commit.
pub const MAX_CHANGES: usize = 100_000;

/// One changed item in a commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// Item id.
    pub item_id: Id,
    /// New version.
    pub version: u64,
    /// Hash of the record holding that version.
    pub record_hash: Hash,
}

/// A signed vault commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    /// Vault id.
    pub vault_id: Id,
    /// Sequence number, starting at 1.
    pub seq: u64,
    /// Hash of the previous commit (all zeros for seq 1).
    pub prev: Hash,
    /// Merkle root of the item set after this commit.
    pub root: Hash,
    /// Number of items (including tombstones) after this commit.
    pub item_count: u64,
    /// Changed items, sorted by item id, no duplicates.
    pub changes: Vec<Change>,
    /// Author's clock, milliseconds since the Unix epoch. Informational only.
    pub time_ms: u64,
    /// Device that made the commit.
    pub device: Id,
    /// Fingerprint of the signing key.
    pub signer: Hash,
    /// Composite signature over everything above.
    pub signature: Vec<u8>,
}

impl Commit {
    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(passback_crypto::Suite::CURRENT.id())
            .fixed(&self.vault_id)
            .u64(self.seq)
            .fixed(&self.prev)
            .fixed(&self.root)
            .u64(self.item_count)
            .u32(self.changes.len() as u32);
        for c in &self.changes {
            w.fixed(&c.item_id).u64(c.version).fixed(&c.record_hash);
        }
        w.u64(self.time_ms).fixed(&self.device).fixed(&self.signer);
        w.finish()
    }

    /// Canonical encoding (body + signature).
    pub fn encode(&self, w: &mut Writer) {
        w.fixed(&self.body()).bytes(&self.signature);
    }

    /// Encode to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w);
        w.finish()
    }

    /// Decode.
    pub fn decode(r: &mut Reader<'_>) -> Result<Self> {
        passback_crypto::Suite::from_id(r.u8()?)?;
        let vault_id = r.fixed()?;
        let seq = r.u64()?;
        let prev = r.fixed()?;
        let root = r.fixed()?;
        let item_count = r.u64()?;
        let n = r.u32()? as usize;
        if n > MAX_CHANGES || n * 56 > r.remaining() {
            return Err(FormatError::Limit("changes per commit"));
        }
        let mut changes = Vec::with_capacity(n);
        for _ in 0..n {
            changes.push(Change {
                item_id: r.fixed()?,
                version: r.u64()?,
                record_hash: r.fixed()?,
            });
        }
        let time_ms = r.u64()?;
        let device = r.fixed()?;
        let signer = r.fixed()?;
        let signature = r.bytes(passback_crypto::sign::SIGNATURE_LEN)?.to_vec();
        Ok(Self {
            vault_id,
            seq,
            prev,
            root,
            item_count,
            changes,
            time_ms,
            device,
            signer,
            signature,
        })
    }

    /// Hash identifying this commit (covers the signature too).
    pub fn hash(&self) -> Hash {
        hash::sha256_labeled("passback/v1/commit", &[&self.to_bytes()])
    }

    fn verify_signature(&self, signers: &Signers) -> Result<()> {
        let key = signers.0.get(&self.signer).ok_or(FormatError::UnauthorizedSigner)?;
        Ok(key.verify("vault-commit", &self.body(), &self.signature)?)
    }
}

/// Keys allowed to sign commits for a vault, by fingerprint.
#[derive(Clone, Debug, Default)]
pub struct Signers(BTreeMap<Hash, VerifyingKey>);

impl Signers {
    /// Empty set.
    pub fn new() -> Self {
        Self::default()
    }
    /// Allow `key`.
    pub fn allow(&mut self, key: VerifyingKey) -> &mut Self {
        self.0.insert(key.fingerprint(), key);
        self
    }
}

fn leaf_data(item_id: &Id, version: u64, record_hash: &Hash) -> Hash {
    let mut w = Writer::new();
    w.fixed(item_id).u64(version).fixed(record_hash);
    merkle::leaf(&w.finish())
}

/// The verified state of one vault, built by replaying commits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultState {
    vault_id: Id,
    items: BTreeMap<Id, (u64, Hash)>,
    history: Vec<Hash>,
}

impl VaultState {
    /// Empty state for a new vault.
    pub fn new(vault_id: Id) -> Self {
        Self {
            vault_id,
            items: BTreeMap::new(),
            history: Vec::new(),
        }
    }

    /// Vault id.
    pub fn vault_id(&self) -> &Id {
        &self.vault_id
    }

    /// Sequence number of the head commit (0 if none).
    pub fn seq(&self) -> u64 {
        self.history.len() as u64
    }

    /// Hash of the head commit (zeros if none).
    pub fn head(&self) -> Hash {
        self.history.last().copied().unwrap_or([0; 32])
    }

    /// Current version and record hash of an item.
    pub fn item(&self, id: &Id) -> Option<(u64, Hash)> {
        self.items.get(id).copied()
    }

    /// Iterate current items.
    pub fn items(&self) -> impl Iterator<Item = (&Id, &(u64, Hash))> {
        self.items.iter()
    }

    fn root_of(items: &BTreeMap<Id, (u64, Hash)>) -> Hash {
        let leaves: Vec<Hash> = items.iter().map(|(id, (v, h))| leaf_data(id, *v, h)).collect();
        merkle::root(&leaves)
    }

    /// Merkle root of the current item set.
    pub fn root(&self) -> Hash {
        Self::root_of(&self.items)
    }

    /// Inclusion proof for one item: `(index, tree size, path)`.
    pub fn prove(&self, id: &Id) -> Option<(usize, usize, Vec<Hash>)> {
        let index = self.items.keys().position(|k| k == id)?;
        let leaves: Vec<Hash> = self.items.iter().map(|(id, (v, h))| leaf_data(id, *v, h)).collect();
        Some((index, leaves.len(), merkle::prove(&leaves, index)))
    }

    fn next_items(&self, changes: &[Change]) -> Result<BTreeMap<Id, (u64, Hash)>> {
        if changes.is_empty() || changes.len() > MAX_CHANGES {
            return Err(FormatError::Limit("changes per commit"));
        }
        if changes.windows(2).any(|w| w[0].item_id >= w[1].item_id) {
            return Err(passback_crypto::Error::Malformed("changes not sorted/unique").into());
        }
        let mut next = self.items.clone();
        for c in changes {
            let old = next.get(&c.item_id).map(|(v, _)| *v).unwrap_or(0);
            if c.version <= old {
                return Err(FormatError::VersionRegression);
            }
            next.insert(c.item_id, (c.version, c.record_hash));
        }
        Ok(next)
    }

    /// Build and sign the next commit for `records` (one per changed item).
    pub fn prepare(&self, records: &[&Record], device: Id, key: &SigningKey, time_ms: u64) -> Result<Commit> {
        let mut changes: Vec<Change> = records
            .iter()
            .map(|r| {
                if r.vault_id != self.vault_id {
                    return Err(FormatError::RecordMismatch);
                }
                Ok(Change {
                    item_id: r.item_id,
                    version: r.version,
                    record_hash: r.hash(),
                })
            })
            .collect::<Result<_>>()?;
        changes.sort_by_key(|c| c.item_id);
        let next = self.next_items(&changes)?;
        let mut c = Commit {
            vault_id: self.vault_id,
            seq: self.seq() + 1,
            prev: self.head(),
            root: Self::root_of(&next),
            item_count: next.len() as u64,
            changes,
            time_ms,
            device,
            signer: key.public().fingerprint(),
            signature: Vec::new(),
        };
        c.signature = key.sign("vault-commit", &c.body())?;
        Ok(c)
    }

    /// Verify `commit` against the current head and apply it.
    ///
    /// `records` must hold exactly the records the commit changes.
    pub fn apply(&mut self, commit: &Commit, signers: &Signers, records: &[&Record]) -> Result<()> {
        if commit.vault_id != self.vault_id || commit.seq != self.seq() + 1 || commit.prev != self.head() {
            return Err(FormatError::BrokenChain(commit.seq));
        }
        commit.verify_signature(signers)?;
        if records.len() != commit.changes.len() {
            return Err(FormatError::RecordMismatch);
        }
        for c in &commit.changes {
            let ok = records.iter().any(|r| {
                r.vault_id == self.vault_id
                    && r.item_id == c.item_id
                    && r.version == c.version
                    && r.hash() == c.record_hash
            });
            if !ok {
                return Err(FormatError::RecordMismatch);
            }
        }
        let next = self.next_items(&commit.changes)?;
        if Self::root_of(&next) != commit.root || next.len() as u64 != commit.item_count {
            return Err(FormatError::RootMismatch(commit.seq));
        }
        self.items = next;
        self.history.push(commit.hash());
        Ok(())
    }

    /// Checkpoint of the current head, for rollback/fork detection later.
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            vault_id: self.vault_id,
            seq: self.seq(),
            head: self.head(),
        }
    }
}

/// The highest vault state a device has seen. Stored locally (authenticated with
/// [`Checkpoint::tag`]) and checked every time the vault is loaded from storage or
/// a server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// Vault id.
    pub vault_id: Id,
    /// Sequence number seen.
    pub seq: u64,
    /// Commit hash at that sequence number.
    pub head: Hash,
}

impl Checkpoint {
    /// Fail if `state` is older than this checkpoint or on a different history.
    pub fn check(&self, state: &VaultState) -> Result<()> {
        if state.vault_id != self.vault_id {
            return Err(FormatError::BrokenChain(0));
        }
        if self.seq == 0 {
            return Ok(());
        }
        if state.seq() < self.seq {
            return Err(FormatError::Rollback {
                seen: self.seq,
                got: state.seq(),
            });
        }
        if state.history[(self.seq - 1) as usize] != self.head {
            return Err(FormatError::Fork(self.seq));
        }
        Ok(())
    }

    /// Canonical encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.vault_id).u64(self.seq).fixed(&self.head);
        w.finish()
    }

    /// Decode.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let c = Self {
            vault_id: r.fixed()?,
            seq: r.u64()?,
            head: r.fixed()?,
        };
        r.finish()?;
        Ok(c)
    }

    fn mac(key: &Key32) -> Hmac<Sha256> {
        let k = hash::hkdf_key(key.expose(), b"", b"passback/v1/checkpoint-mac");
        <Hmac<Sha256> as KeyInit>::new_from_slice(k.expose()).expect("any key length")
    }

    /// HMAC tag so a local attacker without the account key can't lower the checkpoint.
    pub fn tag(&self, key: &Key32) -> [u8; 32] {
        let mut m = Self::mac(key);
        m.update(&self.to_bytes());
        m.finalize().into_bytes().into()
    }

    /// Verify a tag from [`Checkpoint::tag`].
    pub fn verify_tag(&self, key: &Key32, tag: &[u8; 32]) -> Result<()> {
        let mut m = Self::mac(key);
        m.update(&self.to_bytes());
        m.verify_slice(tag).map_err(|_| FormatError::HeaderTampered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use passback_crypto::keys::{ItemKey, VaultKey, new_id};

    struct Fx {
        vk: VaultKey,
        vault: Id,
        key: SigningKey,
        signers: Signers,
        dev: Id,
    }

    fn fx() -> Fx {
        let key = SigningKey::generate().unwrap();
        let mut signers = Signers::new();
        signers.allow(key.public().clone());
        Fx {
            vk: VaultKey::generate().unwrap(),
            vault: new_id().unwrap(),
            key,
            signers,
            dev: new_id().unwrap(),
        }
    }

    fn rec(f: &Fx, item: Id, v: u64, body: &[u8]) -> Record {
        Record::seal(&f.vk, f.vault, item, v, &ItemKey::generate().unwrap(), body).unwrap()
    }

    #[test]
    fn replay_verifies_and_detects_tampering() {
        let f = fx();
        let (a, b) = (new_id().unwrap(), new_id().unwrap());
        let mut author = VaultState::new(f.vault);
        let r1 = rec(&f, a, 1, b"a1");
        let r2 = rec(&f, b, 1, b"b1");
        let c1 = author.prepare(&[&r1, &r2], f.dev, &f.key, 1).unwrap();
        author.apply(&c1, &f.signers, &[&r1, &r2]).unwrap();
        let r3 = rec(&f, a, 2, b"a2");
        let c2 = author.prepare(&[&r3], f.dev, &f.key, 2).unwrap();
        author.apply(&c2, &f.signers, &[&r3]).unwrap();
        assert_eq!(author.seq(), 2);
        assert_eq!(&*r3.open(&f.vk).unwrap(), b"a2");

        // A fresh replica replays the same history.
        let mut replica = VaultState::new(f.vault);
        replica.apply(&c1, &f.signers, &[&r1, &r2]).unwrap();
        replica.apply(&c2, &f.signers, &[&r3]).unwrap();
        assert_eq!(replica, author);

        let empty = VaultState::new(f.vault);

        // Swapped record.
        let mut s = empty.clone();
        let evil = rec(&f, b, 1, b"evil");
        assert_eq!(
            s.apply(&c1, &f.signers, &[&r1, &evil]),
            Err(FormatError::RecordMismatch)
        );
        assert_eq!(s, empty);

        // Commit edited after signing (signature no longer valid).
        let mut forged = c1.clone();
        forged.item_count = 1;
        let mut s = empty.clone();
        assert_eq!(
            s.apply(&forged, &f.signers, &[&r1, &r2]),
            Err(passback_crypto::Error::BadSignature.into())
        );
        assert_eq!(s, empty);

        // Unauthorized signer.
        let mallory = SigningKey::generate().unwrap();
        let c_m = empty.prepare(&[&r1], f.dev, &mallory, 1).unwrap();
        let mut s = empty.clone();
        assert_eq!(s.apply(&c_m, &f.signers, &[&r1]), Err(FormatError::UnauthorizedSigner));
        assert_eq!(s, empty);

        // Skipped commit.
        let mut s = empty.clone();
        assert_eq!(s.apply(&c2, &f.signers, &[&r3]), Err(FormatError::BrokenChain(2)));
        assert_eq!(s, empty);

        // Version regression.
        let old = rec(&f, a, 1, b"again");
        assert_eq!(
            author.prepare(&[&old], f.dev, &f.key, 3),
            Err(FormatError::VersionRegression)
        );

        // Encoding roundtrip.
        let enc = c2.to_bytes();
        let mut r = Reader::new(&enc);
        assert_eq!(Commit::decode(&mut r).unwrap(), c2);
        r.finish().unwrap();

        // Inclusion proof.
        let (i, n, path) = author.prove(&a).unwrap();
        let (v, h) = author.item(&a).unwrap();
        assert!(merkle::verify(&leaf_data(&a, v, &h), i, n, &path, &author.root()));
    }

    /// Re-sign an edited commit, as a holder of an authorized key could.
    fn resign(c: &mut Commit, key: &SigningKey) {
        c.signature = key.sign("vault-commit", &c.body()).unwrap();
    }

    #[test]
    fn signed_but_invalid_commits_are_rejected_and_state_is_unchanged() {
        let f = fx();
        let (a, b) = (new_id().unwrap(), new_id().unwrap());
        let mut s = VaultState::new(f.vault);
        let r1 = rec(&f, a, 1, b"a1");
        let c1 = s.prepare(&[&r1], f.dev, &f.key, 1).unwrap();
        s.apply(&c1, &f.signers, &[&r1]).unwrap();
        let before = s.clone();

        let ra2 = rec(&f, a, 2, b"a2");
        let rb1 = rec(&f, b, 1, b"b1");
        let good = s.prepare(&[&ra2, &rb1], f.dev, &f.key, 2).unwrap();
        type Edit = fn(&mut Commit);
        let cases: [(&str, Edit, FormatError); 6] = [
            ("wrong root", |c| c.root[0] ^= 1, FormatError::RootMismatch(2)),
            ("wrong item count", |c| c.item_count += 1, FormatError::RootMismatch(2)),
            (
                "no changes",
                |c| c.changes.clear(),
                FormatError::Limit("changes per commit"),
            ),
            (
                "unsorted changes",
                |c| c.changes.reverse(),
                passback_crypto::Error::Malformed("changes not sorted/unique").into(),
            ),
            (
                "duplicate change",
                |c| {
                    let d = c.changes[0].clone();
                    c.changes[1] = d;
                },
                passback_crypto::Error::Malformed("changes not sorted/unique").into(),
            ),
            ("wrong vault", |c| c.vault_id[0] ^= 1, FormatError::BrokenChain(2)),
        ];
        for (name, edit, want) in cases {
            let mut c = good.clone();
            edit(&mut c);
            resign(&mut c, &f.key);
            let mut t = s.clone();
            // Records: whichever the edited commit still names, so the check under test is the one that fires.
            let recs: Vec<&Record> = c
                .changes
                .iter()
                .filter_map(|ch| [&ra2, &rb1].into_iter().find(|r| r.item_id == ch.item_id))
                .collect();
            let got = t.apply(&c, &f.signers, &recs).unwrap_err();
            assert_eq!(got, want, "{name}");
            assert_eq!(t, before, "{name}: state changed after rejection");
        }

        // Version that does not increase, signed directly (prepare would refuse).
        let stale = rec(&f, a, 1, b"stale");
        let mut c = good.clone();
        c.changes = vec![Change {
            item_id: a,
            version: 1,
            record_hash: stale.hash(),
        }];
        resign(&mut c, &f.key);
        let mut t = s.clone();
        assert_eq!(t.apply(&c, &f.signers, &[&stale]), Err(FormatError::VersionRegression));
        assert_eq!(t, before);

        // An extra record beyond the commit's changes.
        let mut t = s.clone();
        let extra = rec(&f, new_id().unwrap(), 1, b"extra");
        assert_eq!(
            t.apply(&good, &f.signers, &[&ra2, &rb1, &extra]),
            Err(FormatError::RecordMismatch)
        );
        assert_eq!(t, before);

        // A record the commit names is missing.
        let mut t = s.clone();
        assert_eq!(t.apply(&good, &f.signers, &[&ra2]), Err(FormatError::RecordMismatch));
        assert_eq!(t, before);

        // A valid commit by a key that may not write this vault.
        let mallory = SigningKey::generate().unwrap();
        let by_mallory = s.prepare(&[&ra2, &rb1], f.dev, &mallory, 2).unwrap();
        let mut t = s.clone();
        assert_eq!(
            t.apply(&by_mallory, &f.signers, &[&ra2, &rb1]),
            Err(FormatError::UnauthorizedSigner)
        );
        assert_eq!(t, before);

        // Replaying an already-applied commit.
        let mut t = s.clone();
        assert_eq!(t.apply(&c1, &f.signers, &[&r1]), Err(FormatError::BrokenChain(1)));
        assert_eq!(t, before);
    }

    #[test]
    fn checkpoint_detects_rollback_and_fork() {
        let f = fx();
        let a = new_id().unwrap();
        let mut s = VaultState::new(f.vault);
        let r1 = rec(&f, a, 1, b"1");
        let c1 = s.prepare(&[&r1], f.dev, &f.key, 1).unwrap();
        s.apply(&c1, &f.signers, &[&r1]).unwrap();
        let at1 = s.clone();
        let r2 = rec(&f, a, 2, b"2");
        let c2 = s.prepare(&[&r2], f.dev, &f.key, 2).unwrap();
        s.apply(&c2, &f.signers, &[&r2]).unwrap();

        let cp = s.checkpoint();
        cp.check(&s).unwrap();
        assert_eq!(cp.check(&at1), Err(FormatError::Rollback { seen: 2, got: 1 }));
        at1.checkpoint().check(&s).unwrap();

        // Fork: a different seq-2 commit from the same seq-1 base.
        let mut other = at1.clone();
        let r2b = rec(&f, a, 2, b"2b");
        let c2b = other.prepare(&[&r2b], f.dev, &f.key, 2).unwrap();
        other.apply(&c2b, &f.signers, &[&r2b]).unwrap();
        assert_eq!(cp.check(&other), Err(FormatError::Fork(2)));

        let k = Key32::generate().unwrap();
        let tag = cp.tag(&k);
        cp.verify_tag(&k, &tag).unwrap();
        let mut lowered = cp.clone();
        lowered.seq = 1;
        assert!(lowered.verify_tag(&k, &tag).is_err());
        assert_eq!(Checkpoint::from_bytes(&cp.to_bytes()).unwrap(), cp);
    }
}
