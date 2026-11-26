//! Stable-toolchain twin of the `decoders` fuzz target: random bytes and mutated
//! valid encodings for every untrusted-input surface must be rejected cleanly,
//! never panic, and never be accepted where a forgery is impossible.

use passback_testkit::{Surface, exercise, sample_vault_file, seeds};
use proptest::prelude::*;

fn xorshift(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]
    #[test]
    fn random_bytes_never_panic(sel in any::<u8>(), data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let s = Surface::from_byte(sel);
        // Random bytes never parse as a vault header with minimum KDF parameters,
        // so the VaultFile surface is exercised through mutated seeds below.
        if s != Surface::VaultFile {
            exercise(s, &data);
        }
    }
}

#[test]
fn every_surface_has_a_seed_and_mutated_seeds_never_panic() {
    let seeds = seeds();
    assert_eq!(seeds.len(), Surface::ALL.len());
    let mut rng = 0x9e37_79b9_7f4a_7c15u64;
    for (surface, seed) in &seeds {
        exercise(*surface, seed);
        // Each full vault open runs Argon2; a few are enough here, the fuzz target
        // covers the rest.
        let rounds = if *surface == Surface::VaultFile { 8 } else { 2000 };
        for _ in 0..rounds {
            let mut t = seed.clone();
            let r = xorshift(&mut rng);
            let i = (r as usize) % t.len();
            t[i] = (r >> 32) as u8;
            if r.is_multiple_of(5) {
                t.truncate(i);
            }
            exercise(*surface, &t);
        }
    }
}

/// Writes seed corpora for the fuzz targets into `fuzz/corpus/`. Run with `--ignored`.
#[test]
#[ignore]
fn write_fuzz_seed() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fuzz/corpus");
    let (dec, vf, so) = (
        format!("{root}/decoders"),
        format!("{root}/vault_file"),
        format!("{root}/sealed_open"),
    );
    for d in [&dec, &vf, &so] {
        std::fs::create_dir_all(d).unwrap();
    }
    for (surface, seed) in seeds() {
        let mut bytes = vec![surface as u8];
        bytes.extend_from_slice(&seed);
        std::fs::write(format!("{dec}/{surface:?}.bin"), bytes).unwrap();
        if surface == Surface::SealedBox {
            std::fs::write(format!("{so}/seed.bin"), &seed).unwrap();
        }
    }
    std::fs::write(format!("{vf}/seed.pbv"), sample_vault_file()).unwrap();
}
