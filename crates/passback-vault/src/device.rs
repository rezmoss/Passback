//! Device state: per-account rollback checkpoints and the Secret Key.
//!
//! Lives outside the vault, in a local directory that is never synced, so whoever
//! controls the vault's storage can't roll the checkpoints back with it. Each
//! account's entry carries one HMAC (keyed from the account key) over the device id,
//! account id, Secret Key and *all* of that account's checkpoints, so editing or
//! dropping any single checkpoint is detected. Removing a whole entry looks like
//! first use on this device, which callers always report.
//!
//! Several vaults (and several processes) share one device-state file. Every update
//! goes through [`DeviceState::commit_account`]: it takes the device-state lock,
//! re-reads the file, changes only its own account's entry, refuses to lower any
//! checkpoint another process has already advanced, and writes atomically.

use std::{collections::BTreeMap, path::PathBuf};

use hmac::{Hmac, KeyInit, Mac};
use passback_crypto::{
    hash,
    keys::{AccountKey, Id, new_id},
    secret_key::SecretKey,
    wire::Writer,
};
use passback_format::commit::Checkpoint;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::fsutil;

/// Largest device-state file accepted (it holds a few checkpoints per vault).
pub const MAX_DEVICE_FILE: u64 = 1024 * 1024;

/// Device state errors.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    /// The file exists but can't be parsed (or is too large).
    #[error("device state file {0} is corrupt; run `passback device reset` to start over on this device")]
    Corrupt(PathBuf),
    /// An account entry's MAC doesn't verify: it was edited, or checkpoints were removed.
    #[error("device state for this vault was modified outside Passback; refusing to open")]
    Tampered,
    /// Another process (or another copy of this vault) already advanced a checkpoint
    /// beyond this session's state; writing would lower it.
    #[error("another Passback session already saw a newer state of this vault; reopen it")]
    Stale,
    /// I/O error.
    #[error("device state: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Serialize, Deserialize)]
struct FileV1 {
    v: u32,
    device_id: String,
    #[serde(default)]
    accounts: BTreeMap<String, EntryV1>,
}

#[derive(Serialize, Deserialize, Clone)]
struct EntryV1 {
    #[serde(default)]
    secret_key: Option<Zeroizing<String>>,
    #[serde(default)]
    vaults: BTreeMap<String, CheckpointV1>,
    mac: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct CheckpointV1 {
    seq: u64,
    head: String,
}

/// Verified state of one account on this device.
#[derive(Debug, Default)]
pub struct AccountState {
    /// The account's Secret Key, if this device knows it.
    pub secret_key: Option<SecretKey>,
    /// Highest verified state of each vault.
    pub checkpoints: BTreeMap<Id, Checkpoint>,
}

/// The device state file, loaded.
pub struct DeviceState {
    path: PathBuf,
    device_id: Id,
    accounts: BTreeMap<Id, EntryV1>,
    /// Whether `device_id` came from the file (true) or was generated because the
    /// file didn't exist yet (false, so another process may persist first).
    persisted_id: bool,
}

fn parse_id(s: &str) -> Option<Id> {
    hex::decode(s).ok()?.try_into().ok()
}

fn lock_path(path: &std::path::Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

/// A writer into a pre-allocated buffer that fails instead of reallocating.
struct NoGrow<'a>(&'a mut Vec<u8>);

impl std::io::Write for NoGrow<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.0.len() + data.len() > self.0.capacity() {
            return Err(std::io::Error::other("device state too large"));
        }
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl DeviceState {
    /// Load, or start empty with a new device id if the file doesn't exist yet.
    /// Nothing is written until [`DeviceState::commit_account`].
    pub fn load(path: PathBuf) -> Result<Self, DeviceError> {
        match fsutil::read_bounded(&path, MAX_DEVICE_FILE) {
            Ok(Some(bytes)) => Self::parse(path, &bytes),
            Ok(None) => {
                let device_id = new_id().map_err(std::io::Error::other)?;
                Ok(Self {
                    path,
                    device_id,
                    accounts: BTreeMap::new(),
                    persisted_id: false,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => Err(DeviceError::Corrupt(path)),
            Err(e) => Err(e.into()),
        }
    }

    /// Parse device-state bytes read from `path`.
    pub fn parse(path: PathBuf, bytes: &[u8]) -> Result<Self, DeviceError> {
        let corrupt = || DeviceError::Corrupt(path.clone());
        if bytes.len() as u64 > MAX_DEVICE_FILE {
            return Err(corrupt());
        }
        let f: FileV1 = serde_json::from_slice(bytes).map_err(|_| corrupt())?;
        if f.v != 1 {
            return Err(corrupt());
        }
        let device_id = parse_id(&f.device_id).ok_or_else(corrupt)?;
        let mut accounts = BTreeMap::new();
        for (k, e) in f.accounts {
            accounts.insert(parse_id(&k).ok_or_else(corrupt)?, e);
        }
        Ok(Self {
            path,
            device_id,
            accounts,
            persisted_id: true,
        })
    }

    /// This device's id.
    pub fn device_id(&self) -> Id {
        self.device_id
    }

    /// The stored Secret Key for an account, *before* unlocking (it's needed to
    /// unlock). Unverified: a wrong value just makes unlocking fail.
    pub fn secret_key(&self, account: &Id) -> Option<SecretKey> {
        self.accounts
            .get(account)?
            .secret_key
            .as_deref()
            .and_then(|s| SecretKey::parse(s).ok())
    }

    /// Verified state of an account, or `None` if this device has no entry for it.
    pub fn account(&self, account: &Id, ak: &AccountKey) -> Result<Option<AccountState>, DeviceError> {
        let Some(e) = self.accounts.get(account) else {
            return Ok(None);
        };
        let mut checkpoints = BTreeMap::new();
        for (vid, cp) in &e.vaults {
            let vault_id = parse_id(vid).ok_or(DeviceError::Tampered)?;
            let head: [u8; 32] = hex::decode(&cp.head)
                .ok()
                .and_then(|h| h.try_into().ok())
                .ok_or(DeviceError::Tampered)?;
            checkpoints.insert(
                vault_id,
                Checkpoint {
                    vault_id,
                    seq: cp.seq,
                    head,
                },
            );
        }
        let secret_key = match &e.secret_key {
            Some(s) => Some(SecretKey::parse(s).map_err(|_| DeviceError::Tampered)?),
            None => None,
        };
        let state = AccountState {
            secret_key,
            checkpoints,
        };
        let want = self.mac(account, &state, ak);
        let got = hex::decode(&e.mac).map_err(|_| DeviceError::Tampered)?;
        if !bool::from(subtle::ConstantTimeEq::ct_eq(&want[..], &got[..])) {
            return Err(DeviceError::Tampered);
        }
        Ok(Some(state))
    }

    /// Replace an account's entry in memory only. Use [`DeviceState::commit_account`]
    /// to persist.
    pub fn set_account(&mut self, account: &Id, ak: &AccountKey, state: &AccountState) {
        let entry = EntryV1 {
            secret_key: state.secret_key.as_ref().map(|k| k.to_display()),
            vaults: state
                .checkpoints
                .values()
                .map(|c| {
                    (
                        hex::encode(c.vault_id),
                        CheckpointV1 {
                            seq: c.seq,
                            head: hex::encode(c.head),
                        },
                    )
                })
                .collect(),
            mac: hex::encode(self.mac(account, state, ak)),
        };
        self.accounts.insert(*account, entry);
    }

    /// Persist an account's state safely next to other processes and vaults: lock the
    /// device-state file, re-read it, require every checkpoint already on disk for this
    /// account to be part of this session's verified history (`in_history`), replace
    /// only this account's entry, write atomically. A checkpoint some other session
    /// advanced past us, or onto a different history, makes this fail with `Stale`.
    pub fn commit_account(
        &mut self,
        account: &Id,
        ak: &AccountKey,
        state: &AccountState,
        in_history: &dyn Fn(&Checkpoint) -> bool,
    ) -> Result<(), DeviceError> {
        if let Some(dir) = self.path.parent() {
            fsutil::create_private_dir(dir)?;
        }
        let lock = passback_harden::fs::open_lock_private(&lock_path(&self.path))?;
        lock.lock()?;

        let mut fresh = Self::load(self.path.clone())?;
        if fresh.persisted_id && fresh.device_id != self.device_id {
            if self.persisted_id {
                // The file we loaded was replaced under us (reset elsewhere, or tampering).
                return Err(DeviceError::Tampered);
            }
            // We started before any device state existed and another process saved
            // first: adopt its device id (our entry's MAC is recomputed below).
        } else {
            fresh.device_id = self.device_id;
        }
        if let Some(on_disk) = fresh.account(account, ak)?
            && on_disk.checkpoints.values().any(|cp| !in_history(cp))
        {
            return Err(DeviceError::Stale);
        }
        fresh.set_account(account, ak, state);
        let bytes = fresh.to_bytes()?;
        if bytes.len() as u64 > MAX_DEVICE_FILE {
            return Err(DeviceError::Corrupt(self.path.clone()));
        }
        fsutil::write_atomic(&self.path, &bytes)?;
        fresh.persisted_id = true;
        *self = fresh;
        Ok(())
        // `lock` is released on drop.
    }

    /// Serialized file contents (zeroized when dropped: they include Secret Keys).
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, DeviceError> {
        let f = FileV1 {
            v: 1,
            device_id: hex::encode(self.device_id),
            accounts: self.accounts.iter().map(|(k, e)| (hex::encode(k), e.clone())).collect(),
        };
        // Serialize into a buffer that is allocated once and never grows: a reallocation
        // would leave a copy of the Secret Keys in freed memory. Anything larger than
        // the read limit is refused anyway.
        let mut buf = Zeroizing::new(Vec::with_capacity(MAX_DEVICE_FILE as usize + 1));
        serde_json::to_writer_pretty(NoGrow(&mut buf), &f).map_err(|_| DeviceError::Corrupt(self.path.clone()))?;
        Ok(buf)
    }

    fn mac(&self, account: &Id, state: &AccountState, ak: &AccountKey) -> [u8; 32] {
        // Sized up front: the buffer holds the Secret Key and must never be reallocated
        // (a reallocation would leave a copy in freed memory).
        let mut w = Writer::with_capacity(16 + 16 + 1 + 16 + 4 + state.checkpoints.len() * 56);
        w.fixed(&self.device_id).fixed(account);
        match &state.secret_key {
            Some(k) => w.u8(1).fixed(k.expose()),
            None => w.u8(0),
        };
        w.u32(state.checkpoints.len() as u32);
        for c in state.checkpoints.values() {
            w.fixed(&c.to_bytes());
        }
        let input = Zeroizing::new(w.finish());
        let key = hash::hkdf_key(ak.key().expose(), b"", b"passback/v1/device-state-mac");
        let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key.expose()).expect("any key length");
        m.update(&input);
        m.finalize().into_bytes().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn always(_: &Checkpoint) -> bool {
        true
    }

    #[test]
    fn processes_starting_before_any_device_state_exists_both_keep_their_entries() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("device/device.json");
        // Both load while the file doesn't exist yet, so each generates its own id.
        let mut first = DeviceState::load(path.clone()).unwrap();
        let mut second = DeviceState::load(path.clone()).unwrap();
        assert_ne!(first.device_id(), second.device_id());
        let (a, b) = ([1u8; 16], [2u8; 16]);
        let (ka, kb) = (AccountKey::generate().unwrap(), AccountKey::generate().unwrap());
        first
            .commit_account(&a, &ka, &AccountState::default(), &always)
            .unwrap();
        second
            .commit_account(&b, &kb, &AccountState::default(), &always)
            .expect("must adopt, not report tampering");
        assert_eq!(second.device_id(), first.device_id(), "second adopted the persisted id");

        let on_disk = DeviceState::load(path).unwrap();
        assert!(on_disk.account(&a, &ka).unwrap().is_some());
        assert!(on_disk.account(&b, &kb).unwrap().is_some());
    }

    #[test]
    fn debug_output_of_account_state_does_not_show_the_secret_key() {
        let sk = SecretKey::from_bytes([0xab; 16]);
        let text = sk.to_display().to_string();
        let state = AccountState {
            secret_key: Some(sk),
            checkpoints: BTreeMap::new(),
        };
        let printed = format!("{state:?}");
        assert!(!printed.contains(&text) && !printed.contains("171"), "{printed}");
        assert!(printed.contains("redacted"));
    }

    #[test]
    fn writes_above_the_read_limit_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("device/device.json");
        let mut state = DeviceState::load(path.clone()).unwrap();
        let ak = AccountKey::generate().unwrap();
        // Enough checkpoints that the file would exceed MAX_DEVICE_FILE.
        let checkpoints = (0..12_000u32)
            .map(|i| {
                let mut id = [0u8; 16];
                id[..4].copy_from_slice(&i.to_be_bytes());
                (
                    id,
                    Checkpoint {
                        vault_id: id,
                        seq: 1,
                        head: [7; 32],
                    },
                )
            })
            .collect();
        let big = AccountState {
            secret_key: None,
            checkpoints,
        };
        assert!(matches!(
            state.commit_account(&[1; 16], &ak, &big, &always),
            Err(DeviceError::Corrupt(_))
        ));
        assert!(!path.exists(), "an unreadable device file must never be written");
    }
}
