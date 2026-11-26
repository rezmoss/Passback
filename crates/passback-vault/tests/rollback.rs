//! Rollback protection and device-state rules, tested through the public API with
//! real files.

use std::path::Path;

use passback_crypto::{kdf::KdfParams, secret_key::SecretKey};
use passback_format::FormatError;
use passback_vault::{ErrorKind, Notice, Unlock, Vault, VaultError, device::DeviceError, paths::Paths};

const PW: &str = "correct horse";
const ITEM: [u8; 16] = [0x11; 16];

fn init(dir: &Path) -> (Paths, SecretKey) {
    let paths = Paths::under(dir, false);
    let (_, sk) = Vault::init(paths.clone(), PW, None, true, KdfParams::MIN, 1).unwrap();
    (paths, sk.unwrap())
}

fn open(paths: &Paths) -> Result<(Vault, Vec<Notice>), VaultError> {
    Vault::open(
        paths.clone(),
        Unlock {
            password: PW,
            key_file: None,
            secret_key: None,
        },
    )
}

fn open_with_key(paths: &Paths, sk: &SecretKey) -> Result<(Vault, Vec<Notice>), VaultError> {
    let sk = SecretKey::from_bytes(*sk.expose());
    Vault::open(
        paths.clone(),
        Unlock {
            password: PW,
            key_file: None,
            secret_key: Some(sk),
        },
    )
}

fn put(paths: &Paths, body: &[u8]) {
    let (mut v, _) = open(paths).unwrap();
    let vault = v.vault_ids()[0];
    v.put(&vault, &ITEM, body, 2).unwrap();
}

/// Copy the vault file (what a backup, a stale sync copy or a malicious storage
/// provider would hold).
fn snapshot(paths: &Paths, to: &Path) {
    std::fs::copy(&paths.vault, to).unwrap();
}

/// Put an older copy back behind Passback's back.
fn restore(paths: &Paths, from: &Path) {
    std::fs::copy(from, &paths.vault).unwrap();
}

fn expect_integrity(r: Result<(Vault, Vec<Notice>), VaultError>) -> VaultError {
    let e = r.err().expect("open must fail");
    assert_eq!(e.kind(), ErrorKind::Integrity, "{e}");
    e
}

#[test]
fn init_open_write_read_roundtrip() {
    let d = tempfile::tempdir().unwrap();
    let (paths, _) = init(d.path());
    put(&paths, b"v1");
    let (v, notices) = open(&paths).unwrap();
    assert!(notices.is_empty(), "same device, known state: {notices:?}");
    assert_eq!(&*v.get(&v.vault_ids()[0], &ITEM).unwrap().unwrap(), b"v1");
    assert!(matches!(
        Vault::init(paths.clone(), PW, None, true, KdfParams::MIN, 1).err(),
        Some(VaultError::AlreadyInitialized(_))
    ));
}

#[test]
fn wrong_password_and_missing_secret_key_are_auth_errors() {
    let d = tempfile::tempdir().unwrap();
    let (paths, _) = init(d.path());
    let e = Vault::open(
        paths.clone(),
        Unlock {
            password: "nope",
            key_file: None,
            secret_key: None,
        },
    )
    .err()
    .unwrap();
    assert!(matches!(e, VaultError::WrongFactors));
    assert_eq!(e.kind(), ErrorKind::Auth);

    // A different device (empty device state) without the Secret Key.
    let other = Paths {
        device: d.path().join("other-device/device.json"),
        ..paths.clone()
    };
    let e = open(&other).err().unwrap();
    assert!(matches!(e, VaultError::NeedSecretKey));
    assert_eq!(e.kind(), ErrorKind::Auth);
}

#[test]
fn new_device_with_secret_key_is_first_use_and_remembers_the_key() {
    let d = tempfile::tempdir().unwrap();
    let (paths, sk) = init(d.path());
    put(&paths, b"v1");
    let other = Paths {
        device: d.path().join("other-device/device.json"),
        ..paths.clone()
    };
    let (v, notices) = open_with_key(&other, &sk).unwrap();
    let vault = v.vault_ids()[0];
    assert!(notices.contains(&Notice::FirstUse { vault, seq: 1 }));
    assert!(notices.contains(&Notice::SecretKeySaved));
    drop(v);
    let (_, notices) = open(&other).unwrap();
    assert!(notices.is_empty(), "second open on that device is not first use");
}

#[test]
fn restoring_an_old_copy_of_the_database_is_a_rollback() {
    let d = tempfile::tempdir().unwrap();
    let (paths, _) = init(d.path());
    put(&paths, b"v1");
    let old = d.path().join("old.pbv");
    snapshot(&paths, &old);
    put(&paths, b"v2");
    restore(&paths, &old);
    let e = expect_integrity(open(&paths));
    assert!(
        matches!(e, VaultError::Integrity(FormatError::Rollback { seen: 2, got: 1 })),
        "{e}"
    );
}

#[test]
fn a_diverging_history_is_a_fork() {
    let d = tempfile::tempdir().unwrap();
    let (paths, sk) = init(d.path());
    put(&paths, b"v1");
    let base = d.path().join("base.pbv");
    snapshot(&paths, &base);
    put(&paths, b"device A's v2"); // this device has now seen seq 2 = A

    // Device B starts from the same base and writes a different seq 2.
    let b_dir = d.path().join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let b = Paths {
        vault: b_dir.join("vault.pbv"),
        device: b_dir.join("device/device.json"),
        ..paths.clone()
    };
    std::fs::copy(&base, &b.vault).unwrap();
    {
        let (mut v, _) = open_with_key(&b, &sk).unwrap();
        let vault = v.vault_ids()[0];
        v.put(&vault, &ITEM, b"device B's v2", 3).unwrap();
    }
    // Storage now serves B's history to device A.
    restore(&paths, &b.vault);
    let e = expect_integrity(open(&paths));
    assert!(matches!(e, VaultError::Integrity(FormatError::Fork(2))), "{e}");
}

#[test]
fn edited_or_partly_removed_device_state_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let (paths, _) = init(d.path());
    {
        let (mut v, _) = open(&paths).unwrap();
        let second = v.create_vault().unwrap();
        v.put(&second, &ITEM, b"x", 2).unwrap();
    }
    let original = std::fs::read_to_string(&paths.device).unwrap();

    // Lowering a checkpoint's seq (to make an old copy look acceptable).
    let lowered = original.replacen("\"seq\": 1", "\"seq\": 0", 1);
    assert_ne!(lowered, original);
    std::fs::write(&paths.device, &lowered).unwrap();
    assert!(matches!(
        open(&paths).err().unwrap(),
        VaultError::Device(DeviceError::Tampered)
    ));

    // Dropping one vault's checkpoint (so that vault looks like first use).
    let mut json: serde_json::Value = serde_json::from_str(&original).unwrap();
    let account = json["accounts"].as_object_mut().unwrap().values_mut().next().unwrap();
    let vaults = account["vaults"].as_object_mut().unwrap();
    let first = vaults.keys().next().unwrap().clone();
    vaults.remove(&first);
    std::fs::write(&paths.device, serde_json::to_string(&json).unwrap()).unwrap();
    let e = open(&paths).err().unwrap();
    assert!(matches!(e, VaultError::Device(DeviceError::Tampered)));
    assert_eq!(e.kind(), ErrorKind::Integrity);

    // Garbage: corrupt, with a pointer to `device reset`.
    std::fs::write(&paths.device, b"not json").unwrap();
    assert!(matches!(
        open(&paths).err().unwrap(),
        VaultError::Device(DeviceError::Corrupt(_))
    ));
}

#[test]
fn removing_the_whole_device_entry_is_reported_as_first_use() {
    let d = tempfile::tempdir().unwrap();
    let (paths, sk) = init(d.path());
    put(&paths, b"v1");
    std::fs::remove_file(&paths.device).unwrap();
    let (v, notices) = open_with_key(&paths, &sk).unwrap();
    assert!(notices.iter().any(|n| matches!(n, Notice::FirstUse { seq: 1, .. })));
    drop(v);
}

#[test]
fn a_vault_hidden_by_storage_is_detected() {
    let d = tempfile::tempdir().unwrap();
    let (paths, _) = init(d.path());
    let before = d.path().join("before-second-vault.pbv");
    snapshot(&paths, &before);
    let hidden = {
        let (mut v, _) = open(&paths).unwrap();
        let id = v.create_vault().unwrap();
        v.put(&id, &ITEM, b"secret vault", 2).unwrap();
        id
    };
    // Storage serves a copy that never had the second vault.
    restore(&paths, &before);
    let e = expect_integrity(open(&paths));
    assert!(
        matches!(e, VaultError::Integrity(FormatError::VaultMissing(id)) if id == hidden),
        "{e}"
    );
}

#[test]
fn device_state_and_vault_files_are_owner_only() {
    let d = tempfile::tempdir().unwrap();
    let (paths, _) = init(d.path());
    let lock = std::path::PathBuf::from(format!("{}.lock", paths.vault.display()));
    let device_lock = std::path::PathBuf::from(format!("{}.lock", paths.device.display()));
    for p in [
        &paths.device,
        &paths.vault,
        &lock,
        &device_lock,
        &paths.device.parent().unwrap().to_path_buf(),
    ] {
        assert!(
            passback_harden::fs::is_owner_only(p).unwrap(),
            "{} is readable by others",
            p.display()
        );
    }
}

fn device_json(paths: &Paths) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(&paths.device).unwrap()).unwrap()
}

#[test]
fn a_rejected_open_changes_nothing_on_disk() {
    let d = tempfile::tempdir().unwrap();
    let (paths, _) = init(d.path());
    put(&paths, b"v1");
    let old = d.path().join("old.pbv");
    snapshot(&paths, &old);
    put(&paths, b"v2");
    restore(&paths, &old);
    let (vault_before, device_before) = (
        std::fs::read(&paths.vault).unwrap(),
        std::fs::read(&paths.device).unwrap(),
    );
    expect_integrity(open(&paths));
    assert_eq!(std::fs::read(&paths.vault).unwrap(), vault_before, "vault file changed");
    assert_eq!(
        std::fs::read(&paths.device).unwrap(),
        device_before,
        "device state changed (checkpoint lowered?)"
    );
}

#[test]
fn device_id_and_secret_key_are_bound_by_the_mac() {
    let d = tempfile::tempdir().unwrap();
    let (paths, _) = init(d.path());
    let original = device_json(&paths);

    let mut other_device = original.clone();
    other_device["device_id"] = serde_json::json!("00".repeat(16));
    std::fs::write(&paths.device, other_device.to_string()).unwrap();
    let e = open(&paths).err().unwrap();
    assert!(matches!(e, VaultError::Device(DeviceError::Tampered)), "{e}");

    // A different (valid) Secret Key in the entry: refused (unlock fails before the MAC check).
    let mut other_key = original.clone();
    let entry = other_key["accounts"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap();
    entry["secret_key"] = serde_json::json!(SecretKey::from_bytes([9; 16]).to_display().to_string());
    std::fs::write(&paths.device, other_key.to_string()).unwrap();
    assert!(open(&paths).is_err());
}

#[test]
fn an_entry_copied_from_another_account_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let shared_device = d.path().join("device/device.json");
    let a = Paths {
        device: shared_device.clone(),
        ..Paths::under(&d.path().join("a"), false)
    };
    let b = Paths {
        device: shared_device.clone(),
        ..Paths::under(&d.path().join("b"), false)
    };
    Vault::init(a.clone(), PW, None, true, KdfParams::MIN, 1).unwrap();
    Vault::init(b.clone(), PW, None, true, KdfParams::MIN, 1).unwrap();
    let mut json = device_json(&a);
    let accounts = json["accounts"].as_object_mut().unwrap();
    assert_eq!(accounts.len(), 2, "both accounts kept in one device file");
    let ids: Vec<String> = accounts.keys().cloned().collect();
    let first = accounts[&ids[0]].clone();
    accounts.insert(ids[1].clone(), first);
    std::fs::write(&shared_device, json.to_string()).unwrap();
    let (ra, rb) = (open(&a), open(&b));
    let refused = [ra.is_err(), rb.is_err()];
    assert!(
        refused.contains(&true),
        "the account whose entry was replaced must be refused"
    );
}

#[test]
fn two_vaults_sharing_device_state_do_not_erase_each_other() {
    let d = tempfile::tempdir().unwrap();
    let shared_device = d.path().join("device/device.json");
    let a = Paths {
        device: shared_device.clone(),
        ..Paths::under(&d.path().join("a"), false)
    };
    let b = Paths {
        device: shared_device,
        ..Paths::under(&d.path().join("b"), false)
    };
    Vault::init(a.clone(), PW, None, true, KdfParams::MIN, 1).unwrap();
    let (mut va, _) = open(&a).unwrap(); // A's session started before B existed
    Vault::init(b.clone(), PW, None, true, KdfParams::MIN, 1).unwrap();
    let vault = va.vault_ids()[0];
    va.put(&vault, &ITEM, b"a", 2).unwrap(); // A saves its device state after B was created
    drop(va);
    let (_, notices) = open(&b).expect("B's Secret Key and checkpoints must survive A's write");
    assert!(notices.is_empty(), "{notices:?}");
}

#[test]
fn a_second_copy_advancing_the_same_account_makes_the_other_session_stale() {
    let d = tempfile::tempdir().unwrap();
    let (paths, _) = init(d.path());
    put(&paths, b"v1");
    let copy = Paths {
        vault: d.path().join("copy/vault.pbv"),
        ..paths.clone()
    };
    std::fs::create_dir_all(copy.vault.parent().unwrap()).unwrap();
    snapshot(&paths, &copy.vault);

    let (mut original, _) = open(&paths).unwrap();
    let (mut other, _) = open(&copy).unwrap();
    let vault = other.vault_ids()[0];
    other.put(&vault, &ITEM, b"from the copy", 3).unwrap();
    let e = original.put(&vault, &ITEM, b"from the original", 4).err().unwrap();
    assert!(matches!(e, VaultError::Device(DeviceError::Stale)), "{e}");
    assert_eq!(e.kind(), ErrorKind::Integrity);
    assert!(
        matches!(original.get(&vault, &ITEM), Err(VaultError::Poisoned)),
        "failed write must poison the handle"
    );
}

#[test]
fn a_password_only_vault_works_and_ignores_a_supplied_secret_key() {
    let d = tempfile::tempdir().unwrap();
    let paths = Paths::under(d.path(), false);
    let (_, sk) = Vault::init(paths.clone(), PW, None, false, KdfParams::MIN, 1).unwrap();
    assert!(sk.is_none());
    put(&paths, b"v1");
    let (v, notices) = open_with_key(&paths, &SecretKey::from_bytes([1; 16])).unwrap();
    assert!(notices.is_empty(), "{notices:?}");
    assert!(v.secret_key().is_none());
    let entry = &device_json(&paths)["accounts"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    assert!(entry["secret_key"].is_null());
}

#[test]
fn a_temp_file_left_by_a_crash_is_harmless() {
    let d = tempfile::tempdir().unwrap();
    let (paths, _) = init(d.path());
    std::fs::write(
        paths.vault.with_file_name(".vault.pbv.0011223344556677.tmp"),
        b"half-written junk",
    )
    .unwrap();
    put(&paths, b"v1");
    let (v, _) = open(&paths).unwrap();
    assert_eq!(&*v.get(&v.vault_ids()[0], &ITEM).unwrap().unwrap(), b"v1");
}

#[test]
fn failed_init_leaves_no_vault_behind() {
    let d = tempfile::tempdir().unwrap();
    let blocker = d.path().join("not-a-dir");
    std::fs::write(&blocker, b"").unwrap();
    // Device state can't be written (its parent is a file), so init must fail and clean up.
    let paths = Paths {
        device: blocker.join("device.json"),
        ..Paths::under(&d.path().join("v"), false)
    };
    assert!(Vault::init(paths.clone(), PW, None, true, KdfParams::MIN, 1).is_err());
    assert!(
        !paths.vault.exists(),
        "a vault whose Secret Key was never shown must not remain"
    );
}

#[test]
fn error_kinds_for_missing_and_corrupt_state() {
    let d = tempfile::tempdir().unwrap();
    let nowhere = Paths::under(&d.path().join("does/not/exist"), false);
    let e = open(&nowhere).err().unwrap();
    assert_eq!(e.kind(), ErrorKind::NotFound, "{e}");

    let (paths, _) = init(d.path());
    std::fs::write(&paths.device, b"not json").unwrap();
    assert_eq!(open(&paths).err().unwrap().kind(), ErrorKind::Integrity);
    std::fs::write(
        &paths.device,
        vec![b' '; (passback_vault::device::MAX_DEVICE_FILE + 1) as usize],
    )
    .unwrap();
    assert!(matches!(
        open(&paths).err().unwrap(),
        VaultError::Device(DeviceError::Corrupt(_))
    ));
}

#[cfg(unix)]
#[test]
fn an_oversized_vault_file_is_refused_before_reading_it() {
    let d = tempfile::tempdir().unwrap();
    let (paths, _) = init(d.path());
    let f = std::fs::OpenOptions::new().write(true).open(&paths.vault).unwrap();
    f.set_len(passback_vault::MAX_VAULT_FILE + 1).unwrap(); // sparse: no real allocation
    drop(f);
    let e = expect_integrity(open(&paths));
    assert!(matches!(e, VaultError::Integrity(FormatError::Limit(_))), "{e}");
}

#[test]
fn delete_hides_the_item_permanently() {
    let d = tempfile::tempdir().unwrap();
    let (paths, _) = init(d.path());
    put(&paths, b"v1");
    {
        let (mut v, _) = open(&paths).unwrap();
        let vault = v.vault_ids()[0];
        v.delete(&vault, &ITEM, 3).unwrap();
        assert!(v.get(&vault, &ITEM).unwrap().is_none());
        assert!(
            matches!(v.delete(&vault, &[0x99; 16], 4), Err(VaultError::NoSuchVault)),
            "deleting a missing item"
        );
    }
    let (v, _) = open(&paths).unwrap();
    assert!(
        v.get(&v.vault_ids()[0], &ITEM).unwrap().is_none(),
        "deletion survives reopening"
    );
}

#[test]
fn oversized_item_is_refused_before_anything_changes() {
    let d = tempfile::tempdir().unwrap();
    let (paths, _) = init(d.path());
    put(&paths, b"v1");
    let before = std::fs::read(&paths.vault).unwrap();
    let (mut v, _) = open(&paths).unwrap();
    let vault = v.vault_ids()[0];
    let too_big = vec![0u8; passback_format::record::MAX_CONTENT - 15];
    let e = v.put(&vault, &ITEM, &too_big, 3).err().unwrap();
    assert!(matches!(e, VaultError::Integrity(FormatError::Limit(_))), "{e}");
    assert_eq!(std::fs::read(&paths.vault).unwrap(), before, "vault file changed");
    // Not poisoned: the refusal happened before any change, so the handle stays usable.
    v.put(&vault, &ITEM, b"v2", 4).unwrap();
}

#[test]
fn secrets_never_appear_in_plaintext_on_disk() {
    const CANARY: &[u8] = b"PB-CANARY-9f2c41d7e8b3";
    let d = tempfile::tempdir().unwrap();
    let (paths, sk) = init(d.path());
    put(&paths, CANARY);
    {
        let (mut v, _) = open(&paths).unwrap();
        let vault = v.create_vault().unwrap();
        v.put(&vault, &[0x22; 16], CANARY, 3).unwrap();
        v.delete(&vault, &[0x22; 16], 4).unwrap();
    }
    let sk_text = sk.to_display().to_string();
    let mut files = Vec::new();
    let mut stack = vec![d.path().to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() { stack.push(p) } else { files.push(p) }
        }
    }
    assert!(files.len() >= 3, "{files:?}");
    for f in files {
        let bytes = std::fs::read(&f).unwrap();
        assert!(
            !bytes.windows(CANARY.len()).any(|w| w == CANARY),
            "plaintext secret in {}",
            f.display()
        );
        if f != paths.device {
            // The Secret Key is only ever in device state (decision D7), never next to the vault.
            assert!(
                !String::from_utf8_lossy(&bytes).contains(&sk_text),
                "Secret Key in {}",
                f.display()
            );
        }
    }
}
