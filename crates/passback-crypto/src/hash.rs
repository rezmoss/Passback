//! Domain-separated hashing helpers (SHA-256, HKDF-SHA256).

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::Key32;

/// SHA-256 over the concatenation of `parts`, prefixed with a domain label.
/// Each part is length-prefixed so different splits can't collide.
pub fn sha256_labeled(label: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((label.len() as u32).to_be_bytes());
    h.update(label.as_bytes());
    for p in parts {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    h.finalize().into()
}

/// Plain SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// HKDF-SHA256 extract+expand into `out`.
///
/// `out` must be at most 8160 bytes; every caller in this crate uses 32 or 64.
pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .expect("HKDF output length within limit");
}

/// HKDF-SHA256 producing a single 256-bit key.
pub fn hkdf_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> Key32 {
    let mut out = [0u8; 32];
    hkdf(ikm, salt, info, &mut out);
    Key32::from_bytes(out)
}
