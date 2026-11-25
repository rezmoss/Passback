//! Stable-toolchain counterpart of the fuzz targets: random and mutated inputs to
//! every decoder must fail cleanly, never panic.

use passback_crypto::{aead::SealedBox, kdf::KdfParams, keys::new_id, unlock::Factor, wire::Reader};
use passback_format::{
    commit::{Checkpoint, Commit},
    file::{self, VaultFile},
    record::Record,
};
use proptest::prelude::*;

fn sample_file() -> Vec<u8> {
    let f = [Factor::Password("fuzz")];
    let mut vf = VaultFile::create(&f, KdfParams::MIN, 0).unwrap();
    let v = vf.add_vault().unwrap();
    let dev = new_id().unwrap();
    vf.put(&v, &new_id().unwrap(), b"item one", dev, 1).unwrap();
    vf.put(&v, &new_id().unwrap(), b"item two", dev, 2).unwrap();
    vf.to_bytes().unwrap()
}

fn all_decoders(data: &[u8]) {
    let _ = SealedBox::from_bytes(data);
    let _ = Record::decode(&mut Reader::new(data));
    let _ = Commit::decode(&mut Reader::new(data));
    let _ = Checkpoint::from_bytes(data);
    let _ = file::peek(data);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]
    #[test]
    fn random_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        all_decoders(&data);
    }
}

#[test]
fn mutated_files_never_panic() {
    let base = sample_file();
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..5000 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let mut t = base.clone();
        let i = (seed as usize) % t.len();
        t[i] = (seed >> 32) as u8;
        if seed.is_multiple_of(5) {
            t.truncate(i);
        }
        all_decoders(&t);
    }
}

/// Writes `fuzz/corpus/vault_file/seed.pbv`. Run with `--ignored`.
#[test]
#[ignore]
fn write_fuzz_seed() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fuzz/corpus/vault_file");
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(format!("{dir}/seed.pbv"), sample_file()).unwrap();
}
