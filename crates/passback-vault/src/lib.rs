//! The unlocked vault: what the CLI (and later the daemon, MCP server and sync
//! server) work with.
//!
//! The whole vault is one `.pbv` file (see `passback_format::file`), plus a small
//! local device-state file (checkpoints and Secret Key, never synced).
//!
//! Opening a vault always: unlocks the account (header MAC, identity, whole-file
//! signature), replays and verifies every vault's signed commit chain, and checks
//! each vault against this device's checkpoint, so a rolled-back, forked or partly
//! hidden vault is refused.
//!
//! Writes go in a fixed order: the new file is written atomically first (temp file,
//! fsync, rename, fsync directory); only then is the device checkpoint advanced. A
//! crash in between leaves the checkpoint one commit behind, which the next open
//! repairs: no false alarm and no missed rollback. An exclusive lock file is held for
//! the whole session, so two processes can't overwrite each other's changes.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod device;
mod fsutil;
pub mod paths;

use std::{collections::BTreeMap, fs::File, path::PathBuf};

use passback_crypto::{kdf::KdfParams, keys::Id, secret_key::SecretKey, unlock::Factor};
use passback_format::{
    FormatError,
    commit::{Checkpoint, VaultState},
    file::{VaultFile, factor_mask, peek},
};
use zeroize::Zeroizing;

use crate::{
    device::{AccountState, DeviceError, DeviceState},
    paths::Paths,
};

/// What kind of failure, for exit codes and for callers that branch on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// Wrong password, Secret Key or key file, or a factor is missing.
    Auth,
    /// Data was tampered with, rolled back, forked or is inconsistent.
    Integrity,
    /// The vault or item doesn't exist.
    NotFound,
    /// Anything else (I/O, busy, already exists...).
    Other,
}

/// Vault errors.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// No vault at this path.
    #[error("no vault at {0}; run `passback init` first")]
    NotInitialized(PathBuf),
    /// A vault already exists at this path.
    #[error("a vault already exists at {0}")]
    AlreadyInitialized(PathBuf),
    /// Another Passback process has this vault open.
    #[error("the vault is in use by another Passback process")]
    Busy,
    /// A previous write on this handle failed; its in-memory state can't be trusted.
    #[error("an earlier write failed; reopen the vault")]
    Poisoned,
    /// The configured paths are unusable (e.g. the vault and device state collide).
    #[error("invalid paths: {0}")]
    BadPaths(&'static str),
    /// This vault needs a Secret Key and this device doesn't have it.
    #[error("this device doesn't know the vault's Secret Key; provide it (it's in your emergency kit)")]
    NeedSecretKey,
    /// Wrong password, Secret Key or key file.
    #[error("wrong password, Secret Key or key file")]
    WrongFactors,
    /// The vault failed verification.
    #[error("vault integrity check failed: {0}")]
    Integrity(FormatError),
    /// The device state failed verification or can't be read.
    #[error(transparent)]
    Device(#[from] DeviceError),
    /// No such vault.
    #[error("no such vault")]
    NoSuchVault,
    /// Crypto error outside unlocking (e.g. RNG failure).
    #[error(transparent)]
    Crypto(#[from] passback_crypto::Error),
    /// I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Test-only: a simulated crash after the vault write and before the checkpoint.
    #[cfg(test)]
    #[error("simulated crash")]
    SimulatedCrash,
}

impl VaultError {
    /// Classify the error.
    pub fn kind(&self) -> ErrorKind {
        match self {
            VaultError::NeedSecretKey | VaultError::WrongFactors => ErrorKind::Auth,
            VaultError::Integrity(_)
            | VaultError::Device(DeviceError::Tampered | DeviceError::Corrupt(_) | DeviceError::Stale) => {
                ErrorKind::Integrity
            }
            VaultError::NotInitialized(_) | VaultError::NoSuchVault => ErrorKind::NotFound,
            _ => ErrorKind::Other,
        }
    }
}

impl From<FormatError> for VaultError {
    fn from(e: FormatError) -> Self {
        VaultError::Integrity(e)
    }
}

/// Result alias.
pub type Result<T> = core::result::Result<T, VaultError>;

/// Unlock inputs. The Secret Key normally comes from device state; pass one only
/// to open the vault on a new device (it's then saved on this device).
pub struct Unlock<'a> {
    /// Master password.
    pub password: &'a str,
    /// Key file contents, if the vault uses one.
    pub key_file: Option<&'a [u8]>,
    /// Secret Key, when this device doesn't have it yet.
    pub secret_key: Option<SecretKey>,
}

/// Something the user should be told about after opening.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    /// This device had never seen this vault; its current state is now trusted.
    FirstUse {
        /// Vault id.
        vault: Id,
        /// Sequence number now trusted.
        seq: u64,
    },
    /// The Secret Key was saved on this device.
    SecretKeySaved,
}

/// An unlocked, verified vault file.
pub struct Vault {
    paths: Paths,
    file: VaultFile,
    device: DeviceState,
    secret_key: Option<SecretKey>,
    _lock: File,
    poisoned: bool,
    #[cfg(test)]
    crash_before_checkpoint: bool,
}

/// Largest vault file accepted before reading it into memory (the format's own body
/// limit plus room for the header and signature).
pub const MAX_VAULT_FILE: u64 = (1 << 30) + (1 << 20);

fn copy_key(k: &SecretKey) -> SecretKey {
    SecretKey::from_bytes(*k.expose())
}

fn factors<'a>(password: &'a str, sk: Option<&'a SecretKey>, key_file: Option<&'a [u8]>) -> Vec<Factor<'a>> {
    let mut f = vec![Factor::Password(password)];
    if let Some(sk) = sk {
        f.push(Factor::SecretKey(sk));
    }
    if let Some(kf) = key_file {
        f.push(Factor::KeyFile(kf));
    }
    f
}

/// Take the vault's exclusive lock (`<vault>.lock`), failing fast if it's held.
fn lock(paths: &Paths) -> Result<File> {
    let mut name = paths.vault.clone().into_os_string();
    name.push(".lock");
    let f = passback_harden::fs::open_lock_private(&PathBuf::from(name))?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(std::fs::TryLockError::WouldBlock) => Err(VaultError::Busy),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

impl Vault {
    /// Create a new vault file with one empty vault. Returns the Secret Key, which the
    /// caller must show the user once (it's also saved on this device).
    pub fn init(
        paths: Paths,
        password: &str,
        key_file: Option<&[u8]>,
        with_secret_key: bool,
        kdf: KdfParams,
        now_ms: u64,
    ) -> Result<(Self, Option<SecretKey>)> {
        paths.validate()?;
        let exists = |p: &Paths| {
            if p.vault.exists() {
                Err(VaultError::AlreadyInitialized(p.vault.clone()))
            } else {
                Ok(())
            }
        };
        exists(&paths)?;
        if let Some(dir) = paths.vault.parent().filter(|d| !d.as_os_str().is_empty()) {
            fsutil::create_private_dir(dir)?;
        }
        let lock = lock(&paths)?;
        // Again under the lock, in case another process created it meanwhile.
        exists(&paths)?;
        let device = DeviceState::load(paths.device.clone())?;
        let sk = if with_secret_key {
            Some(SecretKey::generate()?)
        } else {
            None
        };
        let file = VaultFile::create(&factors(password, sk.as_ref(), key_file), kdf, now_ms)?;
        let mut v = Self {
            paths,
            file,
            device,
            secret_key: sk.as_ref().map(copy_key),
            _lock: lock,
            poisoned: false,
            #[cfg(test)]
            crash_before_checkpoint: false,
        };
        if let Err(e) = v.create_vault() {
            // Don't leave behind a vault whose Secret Key the caller never received.
            let _ = std::fs::remove_file(&v.paths.vault);
            return Err(e);
        }
        Ok((v, sk))
    }

    /// Unlock and fully verify the vault file. See the crate docs for what is checked.
    pub fn open(paths: Paths, unlock: Unlock<'_>) -> Result<(Self, Vec<Notice>)> {
        paths.validate()?;
        match std::fs::metadata(&paths.vault) {
            Ok(m) if m.is_file() => {}
            Ok(_) => return Err(VaultError::BadPaths("the vault path is not a regular file")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(VaultError::NotInitialized(paths.vault.clone()));
            }
            Err(e) => return Err(e.into()),
        }
        let lock = lock(&paths)?;
        let bytes = match fsutil::read_bounded(&paths.vault, MAX_VAULT_FILE) {
            Ok(Some(b)) => b,
            Ok(None) => return Err(VaultError::NotInitialized(paths.vault.clone())),
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                return Err(VaultError::Integrity(FormatError::Limit("vault file too large")));
            }
            Err(e) => return Err(e.into()),
        };
        let header = peek(&bytes)?;
        let account_id = *header.account_id();

        let device = DeviceState::load(paths.device.clone())?;
        let provided = unlock.secret_key.is_some();
        let needs_sk = header.factors & factor_mask::SECRET_KEY != 0;
        let sk = unlock
            .secret_key
            .or_else(|| device.secret_key(&account_id))
            .filter(|_| needs_sk);
        if needs_sk && sk.is_none() {
            return Err(VaultError::NeedSecretKey);
        }
        let unlocked = match VaultFile::unlock(&bytes, &factors(unlock.password, sk.as_ref(), unlock.key_file)) {
            Ok(u) => u,
            Err(FormatError::Crypto(passback_crypto::Error::Decrypt | passback_crypto::Error::Factors(_))) => {
                return Err(VaultError::WrongFactors);
            }
            Err(e) => return Err(e.into()),
        };
        let known = device.account(&account_id, unlocked.account().account_key())?;
        let had_entry = known.is_some();
        let known_cps = known.map(|s| s.checkpoints).unwrap_or_default();
        let opened = unlocked.verify(&known_cps)?;

        let current = opened.file.checkpoints();
        let mut notices: Vec<Notice> = opened
            .first_use
            .iter()
            .map(|id| Notice::FirstUse {
                vault: *id,
                seq: current[id].seq,
            })
            .collect();
        if provided && sk.is_some() {
            notices.push(Notice::SecretKeySaved);
        }
        let advanced = current
            .iter()
            .any(|(id, cp)| known_cps.get(id).map(|k| k.seq) != Some(cp.seq));
        let mut v = Self {
            paths,
            file: opened.file,
            device,
            secret_key: sk,
            _lock: lock,
            poisoned: false,
            #[cfg(test)]
            crash_before_checkpoint: false,
        };
        if !had_entry || advanced || provided {
            v.save_checkpoints()?;
        }
        Ok((v, notices))
    }

    fn save_checkpoints(&mut self) -> Result<()> {
        let state = AccountState {
            secret_key: self.secret_key.as_ref().map(copy_key),
            checkpoints: self.file.checkpoints(),
        };
        let account = self.file.account();
        let file = &self.file;
        let in_history = |cp: &Checkpoint| {
            file.vaults()
                .iter()
                .find(|v| v.id() == &cp.vault_id)
                .is_some_and(|v| cp.check(v.state()).is_ok())
        };
        self.device
            .commit_account(account.account_id(), account.account_key(), &state, &in_history)?;
        Ok(())
    }

    /// Persist the in-memory file: atomic file write first, then the checkpoint.
    /// Any failure poisons the handle: the in-memory change may or may not be on disk.
    fn persist(&mut self) -> Result<()> {
        self.poisoned = true;
        fsutil::write_atomic(&self.paths.vault, &self.file.to_bytes()?)?;
        #[cfg(test)]
        if self.crash_before_checkpoint {
            return Err(VaultError::SimulatedCrash);
        }
        self.save_checkpoints()?;
        self.poisoned = false;
        Ok(())
    }

    fn usable(&self) -> Result<()> {
        if self.poisoned {
            Err(VaultError::Poisoned)
        } else {
            Ok(())
        }
    }

    /// File locations.
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// The unlocked account.
    pub fn account(&self) -> &passback_format::account::Account {
        self.file.account()
    }

    /// The Secret Key, for `secret-key show` and the emergency kit.
    pub fn secret_key(&self) -> Option<&SecretKey> {
        self.secret_key.as_ref()
    }

    /// Ids of all vaults.
    pub fn vault_ids(&self) -> Vec<Id> {
        self.file.vaults().iter().map(|v| *v.id()).collect()
    }

    /// Verified state of a vault.
    pub fn state(&self, vault: &Id) -> Option<&VaultState> {
        self.file.vaults().iter().find(|v| v.id() == vault).map(|v| v.state())
    }

    /// Checkpoint of each vault as currently verified.
    pub fn checkpoints(&self) -> BTreeMap<Id, Checkpoint> {
        self.file.checkpoints()
    }

    /// Add an empty vault.
    pub fn create_vault(&mut self) -> Result<Id> {
        self.usable()?;
        let id = self.file.add_vault()?;
        self.persist()?;
        Ok(id)
    }

    /// Write a new version of an item (creates it if absent). Returns the new version.
    pub fn put(&mut self, vault: &Id, item: &Id, plaintext: &[u8], now_ms: u64) -> Result<u64> {
        self.usable()?;
        if self.state(vault).is_none() {
            return Err(VaultError::NoSuchVault);
        }
        let version = self.file.put(vault, item, plaintext, self.device.device_id(), now_ms)?;
        self.persist()?;
        Ok(version)
    }

    /// Permanently delete an item (signed tombstone).
    pub fn delete(&mut self, vault: &Id, item: &Id, now_ms: u64) -> Result<()> {
        self.usable()?;
        if self.state(vault).and_then(|s| s.item(item)).is_none() {
            return Err(VaultError::NoSuchVault);
        }
        self.file.delete(vault, item, self.device.device_id(), now_ms)?;
        self.persist()
    }

    /// Current plaintext of an item; `None` if absent or deleted.
    pub fn get(&self, vault: &Id, item: &Id) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.usable()?;
        if self.state(vault).is_none() {
            return Err(VaultError::NoSuchVault);
        }
        Ok(self.file.get(vault, item)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unlock() -> Unlock<'static> {
        Unlock {
            password: "pw",
            key_file: None,
            secret_key: None,
        }
    }

    #[test]
    fn crash_between_vault_write_and_checkpoint_recovers_without_false_alarm() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::under(d.path(), false);
        let item = [7u8; 16];
        let (mut v, _) = Vault::init(paths.clone(), "pw", None, true, KdfParams::MIN, 1).unwrap();
        let vault = v.vault_ids()[0];
        v.put(&vault, &item, b"one", 2).unwrap();

        v.crash_before_checkpoint = true;
        assert!(matches!(
            v.put(&vault, &item, b"two", 3),
            Err(VaultError::SimulatedCrash)
        ));
        drop(v);

        // The device checkpoint is one commit behind the durable vault file.
        let (v, notices) = Vault::open(paths.clone(), unlock()).unwrap();
        assert!(notices.is_empty(), "no false alarm: {notices:?}");
        assert_eq!(&*v.get(&vault, &item).unwrap().unwrap(), b"two");
        assert_eq!(v.state(&vault).unwrap().seq(), 2);
        let account_id = *v.account().account_id();
        let dev = DeviceState::load(paths.device.clone()).unwrap();
        let cp = dev.account(&account_id, v.account().account_key()).unwrap().unwrap();
        assert_eq!(cp.checkpoints[&vault].seq, 2, "checkpoint repaired on open");
    }

    const CHILD_VAULT: &str = "PASSBACK_TEST_LOCK_CHILD_VAULT";

    /// Child entry point: open the vault, report "ready", hold it until stdin closes.
    #[test]
    #[ignore]
    fn lock_child_entry() {
        let Ok(dir) = std::env::var(CHILD_VAULT) else { return };
        let paths = Paths::under(std::path::Path::new(&dir), false);
        let (_v, _) = Vault::open(paths, unlock()).unwrap();
        println!("ready");
        use std::io::Read;
        let _ = std::io::stdin().read_to_end(&mut Vec::new());
    }

    /// Kills and reaps the child on every exit path (including a failed assertion).
    struct KillOnDrop(std::process::Child);

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn another_process_holding_the_vault_makes_open_fail_with_busy() {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        const DEADLINE: Duration = Duration::from_secs(60);

        let d = tempfile::tempdir().unwrap();
        let paths = Paths::under(d.path(), false);
        drop(Vault::init(paths.clone(), "pw", None, true, KdfParams::MIN, 1).unwrap());

        let mut child = KillOnDrop(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::lock_child_entry",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_VAULT, d.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        // Wait for "ready" on a helper thread, so a hung child can't hang the test.
        let stdout = child.0.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // Keep draining after "ready": the child's test harness writes a summary on
            // exit, and a closed pipe would make it fail.
            for line in std::io::BufReader::new(stdout).lines() {
                match line {
                    Ok(l) if l.contains("ready") => {
                        let _ = tx.send(());
                    }
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
        });
        rx.recv_timeout(DEADLINE)
            .expect("child never reported that it holds the vault");

        assert!(matches!(
            Vault::open(paths.clone(), unlock()).err(),
            Some(VaultError::Busy)
        ));
        drop(child.0.stdin.take()); // let the child exit, releasing the lock
        let start = Instant::now();
        let status = loop {
            if let Some(st) = child.0.try_wait().unwrap() {
                break st;
            }
            assert!(start.elapsed() < DEADLINE, "child did not exit");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(status.success());
        Vault::open(paths, unlock()).unwrap();
    }

    #[test]
    fn a_failed_write_poisons_the_handle() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::under(d.path(), false);
        let (mut v, _) = Vault::init(paths, "pw", None, true, KdfParams::MIN, 1).unwrap();
        let vault = v.vault_ids()[0];
        v.crash_before_checkpoint = true;
        assert!(v.put(&vault, &[1; 16], b"x", 2).is_err());
        v.crash_before_checkpoint = false;
        assert!(matches!(v.get(&vault, &[1; 16]), Err(VaultError::Poisoned)));
        assert!(matches!(v.put(&vault, &[2; 16], b"y", 3), Err(VaultError::Poisoned)));
    }
}
