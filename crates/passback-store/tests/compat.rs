//! Compatibility fixture: a store database written by schema 1 must keep opening,
//! migrating if needed, and replaying to the same verified contents. Never edited
//! or deleted; a new schema version adds a new fixture.

use passback_crypto::{
    Key32,
    keys::{AccountKey, ItemKey, VaultKey},
    sign::SigningKey,
};
use passback_format::{
    commit::{Signers, VaultState},
    record::Record,
};
use passback_store::Store;

const UNLOCK: [u8; 32] = [0x61; 32];
const ACCOUNT_ID: [u8; 16] = [0x62; 16];
const SIGNER_SEED: [u8; 32] = [0x63; 32];
const VAULT: [u8; 16] = [0x64; 16];
const ITEM: [u8; 16] = [0x65; 16];
const DEVICE: [u8; 16] = [0x66; 16];

fn fixture() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/schema1.db")
}

#[test]
fn schema1_fixture_opens_and_replays() {
    // Work on a copy: opening a database may migrate it.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("copy.db");
    std::fs::copy(fixture(), &path).expect("fixture present");

    let s = Store::open(&path).unwrap();
    assert_eq!(s.schema_version().unwrap(), 1);
    let ak = AccountKey::unwrap(
        &Key32::from_bytes(UNLOCK),
        &ACCOUNT_ID,
        &passback_crypto::aead::SealedBox::from_bytes(&s.get_meta("wrapped_account_key").unwrap().unwrap()).unwrap(),
    )
    .unwrap();
    let (id, wrapped) = s.vaults().unwrap().pop().unwrap();
    assert_eq!(id, VAULT);
    let vk = VaultKey::unwrap(&ak, &id, &wrapped).unwrap();

    let signer = SigningKey::from_seed(Key32::from_bytes(SIGNER_SEED));
    let mut signers = Signers::new();
    signers.allow(signer.public().clone());
    let mut st = VaultState::new(id);
    for c in s.commits(&id).unwrap() {
        let recs: Vec<Record> = c
            .changes
            .iter()
            .map(|ch| s.record(&id, &ch.item_id, ch.version).unwrap().unwrap())
            .collect();
        st.apply(&c, &signers, &recs.iter().collect::<Vec<_>>()).unwrap();
    }
    let (cp, tag) = s.checkpoint(&id).unwrap().unwrap();
    cp.verify_tag(ak.key(), &tag).unwrap();
    cp.check(&st).unwrap();
    let (v, _) = st.item(&ITEM).unwrap();
    assert_eq!(v, 2);
    assert_eq!(&*s.record(&id, &ITEM, v).unwrap().unwrap().open(&vk).unwrap(), b"v2");
}

/// Writes the fixture once with `--ignored`; never overwrites it.
#[test]
#[ignore]
fn write_schema1_fixture() {
    let path = fixture();
    assert!(!path.exists(), "fixtures are never regenerated");
    let ak = AccountKey::generate().unwrap();
    let vk = VaultKey::generate().unwrap();
    let signer = SigningKey::from_seed(Key32::from_bytes(SIGNER_SEED));
    let mut signers = Signers::new();
    signers.allow(signer.public().clone());
    {
        let mut s = Store::open(&path).unwrap();
        s.put_meta(
            "wrapped_account_key",
            &ak.wrap(&Key32::from_bytes(UNLOCK), &ACCOUNT_ID).unwrap().to_bytes(),
        )
        .unwrap();
        s.add_vault(&VAULT, &vk.wrap(&ak, &VAULT).unwrap()).unwrap();
        let mut st = VaultState::new(VAULT);
        for (v, body) in [(1u64, &b"v1"[..]), (2, b"v2")] {
            let r = Record::seal(&vk, VAULT, ITEM, v, &ItemKey::generate().unwrap(), body).unwrap();
            let c = st.prepare(&[&r], DEVICE, &signer, v).unwrap();
            st.apply(&c, &signers, &[&r]).unwrap();
            s.append(&c, &[&r]).unwrap();
        }
        let cp = st.checkpoint();
        s.put_checkpoint(&cp, &cp.tag(ak.key())).unwrap();
    }
    // Closing the last connection checkpoints the WAL into the main file.
    for ext in ["db-wal", "db-shm"] {
        assert!(!path.with_extension(ext).exists(), "WAL not folded into the fixture");
    }
}
