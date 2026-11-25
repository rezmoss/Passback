//! Opening attacker-controlled sealed boxes with a known key must never succeed
//! unless the box was produced by `seal`, and must never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use passback_crypto::{Key32, aead};

fuzz_target!(|data: &[u8]| {
    let key = Key32::from_bytes([0x5a; 32]);
    if let Ok(b) = aead::SealedBox::from_bytes(data) {
        assert!(aead::open(&key, "fuzz", b"aad", &b).is_err(), "forged box accepted");
    }
});
