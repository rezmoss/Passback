//! Committing authenticated encryption.
//!
//! ```text
//! nonce            = 24 random bytes
//! k_enc || commit  = HKDF-SHA256(ikm = key, salt = nonce, info = "passback/v1/aead"), 64 bytes
//! aad'             = suite || len(purpose) || purpose || len(aad) || aad
//! ct               = XChaCha20-Poly1305(k_enc, nonce, plaintext, aad')
//! box              = suite(1) || nonce(24) || commit(32) || len(ct)(4) || ct
//! ```
//!
//! `commit` binds the ciphertext to exactly one key (Poly1305 alone does not), and
//! deriving a fresh `k_enc` per message means a repeated nonce never reuses a
//! ChaCha20 keystream under the long-term key. `purpose` is a fixed label such as
//! `"item-key"`; `aad` carries the ids the object belongs to. Opening with the wrong
//! purpose or ids fails the same way as a wrong key.

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    Error, Key32, Result, Suite, hash,
    wire::{Reader, Writer},
};

const NONCE: usize = 24;
const COMMIT: usize = 32;
/// Fixed overhead of a sealed box over its plaintext.
pub const OVERHEAD: usize = 1 + NONCE + COMMIT + 4 + 16;

/// An encrypted, authenticated, key-committed blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBox {
    suite: Suite,
    nonce: [u8; NONCE],
    commit: [u8; COMMIT],
    ct: Vec<u8>,
}

fn subkeys(key: &Key32, nonce: &[u8; NONCE]) -> (Zeroizing<[u8; 32]>, [u8; COMMIT]) {
    let mut okm = Zeroizing::new([0u8; 64]);
    hash::hkdf(key.expose(), nonce, b"passback/v1/aead", &mut okm[..]);
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&okm[..32]);
    let mut c = [0u8; COMMIT];
    c.copy_from_slice(&okm[32..]);
    (k, c)
}

fn full_aad(suite: Suite, purpose: &str, aad: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(suite.id()).bytes(purpose.as_bytes()).bytes(aad);
    w.finish()
}

/// Encrypt `plaintext` under `key` for `purpose`, bound to `aad`.
pub fn seal(key: &Key32, purpose: &str, aad: &[u8], plaintext: &[u8]) -> Result<SealedBox> {
    let nonce: [u8; NONCE] = crate::rand::array()?;
    seal_with_nonce(key, purpose, aad, plaintext, nonce)
}

/// Seal with a caller-chosen nonce. Only for known-answer tests: a repeated nonce
/// with the same key leaks plaintext relations. Use [`seal`].
#[doc(hidden)]
pub fn seal_with_nonce(
    key: &Key32,
    purpose: &str,
    aad: &[u8],
    plaintext: &[u8],
    nonce: [u8; NONCE],
) -> Result<SealedBox> {
    let suite = Suite::CURRENT;
    let (k, commit) = subkeys(key, &nonce);
    let cipher = XChaCha20Poly1305::new((&*k).into());
    let ct = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &full_aad(suite, purpose, aad),
            },
        )
        .map_err(|_| Error::Malformed("plaintext too long"))?;
    Ok(SealedBox {
        suite,
        nonce,
        commit,
        ct,
    })
}

/// Decrypt and authenticate. Returns the plaintext in a zeroizing buffer.
pub fn open(key: &Key32, purpose: &str, aad: &[u8], sealed: &SealedBox) -> Result<Zeroizing<Vec<u8>>> {
    let (k, commit) = subkeys(key, &sealed.nonce);
    if !bool::from(commit.ct_eq(&sealed.commit)) {
        return Err(Error::Decrypt);
    }
    let cipher = XChaCha20Poly1305::new((&*k).into());
    cipher
        .decrypt(
            &XNonce::from(sealed.nonce),
            Payload {
                msg: &sealed.ct,
                aad: &full_aad(sealed.suite, purpose, aad),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

impl SealedBox {
    /// Suite this box was made with.
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// Canonical encoding.
    pub fn encode(&self, w: &mut Writer) {
        w.u8(self.suite.id())
            .fixed(&self.nonce)
            .fixed(&self.commit)
            .bytes(&self.ct);
    }

    /// Encode to a standalone byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w);
        w.finish()
    }

    /// Decode from a reader. `max_ct` bounds the ciphertext size.
    pub fn decode(r: &mut Reader<'_>, max_ct: usize) -> Result<Self> {
        let suite = Suite::from_id(r.u8()?)?;
        let nonce = r.fixed()?;
        let commit = r.fixed()?;
        let ct = r.bytes(max_ct)?;
        if ct.len() < 16 {
            return Err(Error::Malformed("ciphertext shorter than tag"));
        }
        Ok(Self {
            suite,
            nonce,
            commit,
            ct: ct.to_vec(),
        })
    }

    /// Decode a standalone encoding; trailing bytes are rejected.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let s = Self::decode(&mut r, crate::wire::MAX_FIELD)?;
        r.finish()?;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn roundtrip_and_binding() {
        let k = Key32::generate().unwrap();
        let b = seal(&k, "item", b"id-1", b"hello").unwrap();
        assert_eq!(&*open(&k, "item", b"id-1", &b).unwrap(), b"hello");
        assert_eq!(open(&k, "item", b"id-2", &b), Err(Error::Decrypt));
        assert_eq!(open(&k, "note", b"id-1", &b), Err(Error::Decrypt));
        let other = Key32::generate().unwrap();
        assert_eq!(open(&other, "item", b"id-1", &b), Err(Error::Decrypt));
        let enc = b.to_bytes();
        assert_eq!(enc.len(), OVERHEAD + 5);
        assert_eq!(SealedBox::from_bytes(&enc).unwrap(), b);
    }

    #[test]
    fn purpose_and_aad_boundaries_do_not_collide() {
        let k = Key32::generate().unwrap();
        let b = seal(&k, "ab", b"c", b"x").unwrap();
        assert!(open(&k, "a", b"bc", &b).is_err());
    }

    proptest! {
        #[test]
        fn any_bit_flip_is_rejected(pt in proptest::collection::vec(any::<u8>(), 0..256), idx in any::<usize>(), bit in 0u8..8) {
            let k = Key32::from_bytes([5; 32]);
            let b = seal(&k, "p", b"a", &pt).unwrap();
            let mut enc = b.to_bytes();
            let i = idx % enc.len();
            enc[i] ^= 1 << bit;
            if let Ok(t) = SealedBox::from_bytes(&enc) {
                prop_assert!(open(&k, "p", b"a", &t).is_err());
            }
        }
    }
}
