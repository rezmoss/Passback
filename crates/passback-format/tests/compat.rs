//! Compatibility fixtures: vault files written by earlier versions must keep
//! opening with the same contents. Fixtures are never edited or deleted; a new
//! format or suite version adds a new fixture next to the old ones.

use passback_crypto::{kdf::KdfParams, secret_key::SecretKey, unlock::Factor};
use passback_format::file::VaultFile;

const PASSWORD: &str = "compat-fixture";
const SECRET_KEY: [u8; 16] = [0x42; 16];
const DEVICE: [u8; 16] = [0xd0; 16];
const ITEM_A: [u8; 16] = [0x01; 16];
const ITEM_B: [u8; 16] = [0x02; 16];
const ITEM_C: [u8; 16] = [0x03; 16];

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn format1_suite1_fixture_opens_with_original_contents() {
    let bytes = std::fs::read(fixture("format1-suite1.pbv")).expect("fixture present");
    let sk = SecretKey::from_bytes(SECRET_KEY);
    let vf = VaultFile::open(&bytes, &[Factor::Password(PASSWORD), Factor::SecretKey(&sk)]).unwrap();
    let v = *vf.vaults()[0].id();
    assert_eq!(vf.vaults().len(), 1);
    assert_eq!(
        vf.get(&v, &ITEM_A).unwrap().as_deref().map(|b| &b[..]),
        Some(&b"alpha v2"[..])
    );
    assert!(
        vf.get(&v, &ITEM_B).unwrap().is_none(),
        "tombstoned item must stay deleted"
    );
    assert_eq!(
        vf.get(&v, &ITEM_C).unwrap().as_deref().map(|b| &b[..]),
        Some(&b"charlie"[..])
    );
    assert_eq!(vf.vaults()[0].state().seq(), 5);
}

/// Writes the fixture. Run once per new format/suite version with `--ignored`,
/// under a new file name; never overwrite an existing fixture.
#[test]
#[ignore]
fn write_format1_suite1_fixture() {
    let path = fixture("format1-suite1.pbv");
    assert!(!std::path::Path::new(&path).exists(), "fixtures are never regenerated");
    let sk = SecretKey::from_bytes(SECRET_KEY);
    let mut vf = VaultFile::create(&[Factor::Password(PASSWORD), Factor::SecretKey(&sk)], KdfParams::MIN, 1).unwrap();
    let v = vf.add_vault().unwrap();
    vf.put(&v, &ITEM_A, b"alpha v1", DEVICE, 2).unwrap();
    vf.put(&v, &ITEM_B, b"bravo", DEVICE, 3).unwrap();
    vf.put(&v, &ITEM_A, b"alpha v2", DEVICE, 4).unwrap();
    vf.delete(&v, &ITEM_B, DEVICE, 5).unwrap();
    vf.put(&v, &ITEM_C, b"charlie", DEVICE, 6).unwrap();
    std::fs::write(&path, vf.to_bytes().unwrap()).unwrap();
}
