//! Mutated vault files must be rejected without panicking. Seed the corpus with a
//! real file from `cargo test -p passback-format -- --ignored write_fuzz_seed`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use passback_crypto::unlock::Factor;
use passback_format::file::{VaultFile, peek};

fuzz_target!(|data: &[u8]| {
    // Only run the (slow, by design) KDF when the header parses with minimum
    // parameters; everything else exercises the parser.
    if let Ok(h) = peek(data) {
        if h.unlock.kdf == passback_crypto::kdf::KdfParams::MIN {
            let _ = VaultFile::open(data, &[Factor::Password("fuzz")]);
        }
    }
});
