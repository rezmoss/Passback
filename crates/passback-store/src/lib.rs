//! Embedded storage on SQLite.
//!
//! The store only ever sees ciphertext and public ids: wrapped keys, sealed
//! records, signed commits and MAC-tagged checkpoints. It is a dumb, durable
//! container; every integrity decision is made by `passback-format` when the data
//! is loaded back. SQLite is built in (bundled), so no system library is needed.
//!
//! Durability settings: WAL journal, `synchronous=FULL`, `secure_delete=ON` (freed
//! pages are overwritten), and on Unix the database file is created mode 0600.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::path::Path;

use passback_crypto::{aead::SealedBox, keys::Id, wire::Reader};
use passback_format::{
    commit::{Checkpoint, Commit},
    record::Record,
};
use rusqlite::{Connection, OptionalExtension, params};

/// Storage errors.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite error.
    #[error("storage: {0}")]
    Sql(#[from] rusqlite::Error),
    /// Stored bytes failed to decode.
    #[error("stored data is corrupt: {0}")]
    Format(#[from] passback_format::FormatError),
    /// Crypto-level decode error.
    #[error("stored data is corrupt: {0}")]
    Crypto(#[from] passback_crypto::Error),
    /// The database was created by a newer Passback.
    #[error("database schema {0} is newer than this binary supports")]
    TooNew(i64),
    /// I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Result alias.
pub type Result<T> = core::result::Result<T, StoreError>;

const MIGRATIONS: &[&str] = &[
    // 1: initial schema
    "CREATE TABLE meta (k TEXT PRIMARY KEY, v BLOB NOT NULL);
     CREATE TABLE vaults (id BLOB PRIMARY KEY CHECK(length(id)=16), wrapped_key BLOB NOT NULL);
     CREATE TABLE records (
        vault_id BLOB NOT NULL REFERENCES vaults(id),
        item_id BLOB NOT NULL CHECK(length(item_id)=16),
        version INTEGER NOT NULL CHECK(version > 0),
        body BLOB NOT NULL,
        PRIMARY KEY (vault_id, item_id, version)) WITHOUT ROWID;
     CREATE TABLE commits (
        vault_id BLOB NOT NULL REFERENCES vaults(id),
        seq INTEGER NOT NULL CHECK(seq > 0),
        hash BLOB NOT NULL CHECK(length(hash)=32),
        body BLOB NOT NULL,
        PRIMARY KEY (vault_id, seq)) WITHOUT ROWID;
     CREATE TABLE checkpoints (
        vault_id BLOB PRIMARY KEY,
        body BLOB NOT NULL,
        tag BLOB NOT NULL CHECK(length(tag)=32));",
];

/// A Passback database.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open or create a database file.
    pub fn open(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        if !path.exists() {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
        }
        Self::init(Connection::open(path)?)
    }

    /// In-memory database (tests, ephemeral sessions).
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;
             PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;",
        )?;
        let mut s = Self { conn };
        s.migrate()?;
        Ok(s)
    }

    fn migrate(&mut self) -> Result<()> {
        let current: i64 = self.conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if current > MIGRATIONS.len() as i64 {
            return Err(StoreError::TooNew(current));
        }
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(current as usize) {
            let tx = self.conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.pragma_update(None, "user_version", (i + 1) as i64)?;
            tx.commit()?;
        }
        Ok(())
    }

    /// Schema version.
    pub fn schema_version(&self) -> Result<i64> {
        Ok(self.conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
    }

    /// Set a metadata blob (e.g. the account header).
    pub fn put_meta(&self, key: &str, value: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta(k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![key, value],
        )?;
        Ok(())
    }

    /// Get a metadata blob.
    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row("SELECT v FROM meta WHERE k = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    /// Add a vault with its wrapped key.
    pub fn add_vault(&self, id: &Id, wrapped_key: &SealedBox) -> Result<()> {
        self.conn.execute(
            "INSERT INTO vaults(id, wrapped_key) VALUES (?1, ?2)",
            params![&id[..], wrapped_key.to_bytes()],
        )?;
        Ok(())
    }

    /// All vaults with their wrapped keys.
    pub fn vaults(&self) -> Result<Vec<(Id, SealedBox)>> {
        let mut st = self.conn.prepare("SELECT id, wrapped_key FROM vaults ORDER BY id")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        rows.map(|row| {
            let (id, key) = row?;
            let id: Id = id
                .try_into()
                .map_err(|_| passback_crypto::Error::Malformed("vault id"))?;
            Ok((id, SealedBox::from_bytes(&key)?))
        })
        .collect()
    }

    /// Atomically store a commit and the records it introduces.
    pub fn append(&mut self, commit: &Commit, records: &[&Record]) -> Result<()> {
        let tx = self.conn.transaction()?;
        for r in records {
            tx.execute(
                "INSERT INTO records(vault_id, item_id, version, body) VALUES (?1, ?2, ?3, ?4)",
                params![&r.vault_id[..], &r.item_id[..], r.version as i64, r.to_bytes()],
            )?;
        }
        tx.execute(
            "INSERT INTO commits(vault_id, seq, hash, body) VALUES (?1, ?2, ?3, ?4)",
            params![
                &commit.vault_id[..],
                commit.seq as i64,
                &commit.hash()[..],
                commit.to_bytes()
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Commits of a vault, oldest first.
    pub fn commits(&self, vault: &Id) -> Result<Vec<Commit>> {
        let mut st = self
            .conn
            .prepare("SELECT body FROM commits WHERE vault_id = ?1 ORDER BY seq")?;
        let rows = st.query_map([&vault[..]], |r| r.get::<_, Vec<u8>>(0))?;
        rows.map(|b| {
            let b = b?;
            let mut r = Reader::new(&b);
            let c = Commit::decode(&mut r)?;
            r.finish()?;
            Ok(c)
        })
        .collect()
    }

    /// One record.
    pub fn record(&self, vault: &Id, item: &Id, version: u64) -> Result<Option<Record>> {
        let body: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT body FROM records WHERE vault_id = ?1 AND item_id = ?2 AND version = ?3",
                params![&vault[..], &item[..], version as i64],
                |r| r.get(0),
            )
            .optional()?;
        body.map(|b| {
            let mut r = Reader::new(&b);
            let rec = Record::decode(&mut r)?;
            r.finish()?;
            Ok(rec)
        })
        .transpose()
    }

    /// Save the device's checkpoint for a vault (tagged with the account key).
    pub fn put_checkpoint(&self, cp: &Checkpoint, tag: &[u8; 32]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO checkpoints(vault_id, body, tag) VALUES (?1, ?2, ?3)
             ON CONFLICT(vault_id) DO UPDATE SET body = excluded.body, tag = excluded.tag",
            params![&cp.vault_id[..], cp.to_bytes(), &tag[..]],
        )?;
        Ok(())
    }

    /// Load the checkpoint and its tag. Verify the tag before trusting it.
    pub fn checkpoint(&self, vault: &Id) -> Result<Option<(Checkpoint, [u8; 32])>> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT body, tag FROM checkpoints WHERE vault_id = ?1",
                [&vault[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        row.map(|(b, t)| {
            let tag: [u8; 32] = t.try_into().map_err(|_| passback_crypto::Error::Malformed("tag"))?;
            Ok((Checkpoint::from_bytes(&b)?, tag))
        })
        .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use passback_crypto::{
        Key32,
        keys::{AccountKey, ItemKey, VaultKey, new_id},
        sign::SigningKey,
    };
    use passback_format::commit::{Signers, VaultState};

    #[test]
    fn persist_and_replay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        let ak = AccountKey::generate().unwrap();
        let vk = VaultKey::generate().unwrap();
        let key = SigningKey::generate().unwrap();
        let mut signers = Signers::new();
        signers.allow(key.public().clone());
        let (vault, item, dev) = (new_id().unwrap(), new_id().unwrap(), new_id().unwrap());

        {
            let mut s = Store::open(&path).unwrap();
            assert_eq!(s.schema_version().unwrap(), 1);
            s.add_vault(&vault, &vk.wrap(&ak, &vault).unwrap()).unwrap();
            let mut st = VaultState::new(vault);
            for v in 1..=3u64 {
                let r = Record::seal(
                    &vk,
                    vault,
                    item,
                    v,
                    &ItemKey::generate().unwrap(),
                    format!("v{v}").as_bytes(),
                )
                .unwrap();
                let c = st.prepare(&[&r], dev, &key, v).unwrap();
                st.apply(&c, &signers, &[&r]).unwrap();
                s.append(&c, &[&r]).unwrap();
            }
            let cp = st.checkpoint();
            s.put_checkpoint(&cp, &cp.tag(ak.key())).unwrap();
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }

        let s = Store::open(&path).unwrap();
        let (id, wrapped) = s.vaults().unwrap().pop().unwrap();
        let vk2 = VaultKey::unwrap(&ak, &id, &wrapped).unwrap();
        let mut st = VaultState::new(id);
        for c in s.commits(&id).unwrap() {
            let recs: Vec<Record> = c
                .changes
                .iter()
                .map(|ch| s.record(&id, &ch.item_id, ch.version).unwrap().unwrap())
                .collect();
            let refs: Vec<&Record> = recs.iter().collect();
            st.apply(&c, &signers, &refs).unwrap();
        }
        let (cp, tag) = s.checkpoint(&id).unwrap().unwrap();
        cp.verify_tag(ak.key(), &tag).unwrap();
        cp.check(&st).unwrap();
        let (v, _) = st.item(&item).unwrap();
        assert_eq!(&*s.record(&id, &item, v).unwrap().unwrap().open(&vk2).unwrap(), b"v3");
        assert!(cp.verify_tag(&Key32::generate().unwrap(), &tag).is_err());
    }

    #[test]
    fn failed_append_leaves_no_records_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        let ak = AccountKey::generate().unwrap();
        let vk = VaultKey::generate().unwrap();
        let key = SigningKey::generate().unwrap();
        let mut signers = Signers::new();
        signers.allow(key.public().clone());
        let (vault, dev) = (new_id().unwrap(), new_id().unwrap());
        let (a, b) = (new_id().unwrap(), new_id().unwrap());
        {
            let mut s = Store::open(&path).unwrap();
            s.add_vault(&vault, &vk.wrap(&ak, &vault).unwrap()).unwrap();
            let mut st = VaultState::new(vault);
            let ra = Record::seal(&vk, vault, a, 1, &ItemKey::generate().unwrap(), b"a").unwrap();
            let c1 = st.prepare(&[&ra], dev, &key, 1).unwrap();
            st.apply(&c1, &signers, &[&ra]).unwrap();
            s.append(&c1, &[&ra]).unwrap();

            // Second append: its record insert succeeds, then the commit insert fails
            // (seq 1 already exists). The record must not survive.
            let rb = Record::seal(&vk, vault, b, 1, &ItemKey::generate().unwrap(), b"b").unwrap();
            assert!(s.append(&c1, &[&rb]).is_err());
        }
        let s = Store::open(&path).unwrap();
        assert!(s.record(&vault, &b, 1).unwrap().is_none(), "partial write survived");
        assert!(s.record(&vault, &a, 1).unwrap().is_some());
        assert_eq!(s.commits(&vault).unwrap().len(), 1);
    }

    #[test]
    fn rejects_newer_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        Store::open(&path).unwrap();
        Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", 99)
            .unwrap();
        assert!(matches!(Store::open(&path), Err(StoreError::TooNew(99))));
    }
}
