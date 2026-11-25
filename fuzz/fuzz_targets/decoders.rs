//! Every decoder of untrusted bytes must return an error, never panic, hang or
//! allocate without bound. The first byte picks the decoder.
#![no_main]

use libfuzzer_sys::fuzz_target;
use passback_crypto::{aead::SealedBox, kem, secret_key::SecretKey, sign, wire::Reader};
use passback_format::{commit::{Checkpoint, Commit}, file, record::Record};

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else { return };
    match sel % 9 {
        0 => { let _ = SealedBox::from_bytes(rest); }
        1 => { let _ = Record::decode(&mut Reader::new(rest)); }
        2 => { let _ = Commit::decode(&mut Reader::new(rest)); }
        3 => { let _ = Checkpoint::from_bytes(rest); }
        4 => { let _ = file::peek(rest); }
        5 => { let _ = core::str::from_utf8(rest).map(SecretKey::parse); }
        6 => { let _ = kem::KemPublicKey::from_bytes(rest); }
        7 => {
            if let Ok(vk) = sign::VerifyingKey::from_bytes(rest.get(..sign::PUBLIC_KEY_LEN).unwrap_or(rest)) {
                let _ = vk.verify("fuzz", b"m", rest.get(sign::PUBLIC_KEY_LEN..).unwrap_or(&[]));
            }
        }
        _ => { let _ = kem::KemBox::decode(&mut Reader::new(rest), 1 << 20); }
    }
});
