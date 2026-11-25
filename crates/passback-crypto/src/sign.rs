//! Composite signatures: Ed25519 + ML-DSA-65.
//!
//! A signature is valid only if *both* component signatures verify, so forging one
//! requires breaking both Ed25519 and ML-DSA-65. Both components sign the same
//! domain-separated message:
//!
//! ```text
//! M' = len("passback/v1/sig") || "passback/v1/sig" || len(context) || context || len(msg) || msg
//! sig = Ed25519.Sign(M') (64 bytes) || ML-DSA-65.Sign(M', ctx = "passback/v1") (3309 bytes)
//! ```
//!
//! Keys come from one 32-byte seed: `SHAKE256("passback/v1/sig-seed" || seed)` gives
//! the Ed25519 seed and the ML-DSA seed.

use ed25519_dalek::{Signer as _, Verifier as _};
use ml_dsa::{KeyExport as _, Keypair as _, MlDsa65};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroizing;

use crate::{Error, Key32, Result, hash, wire::Writer};

const ED_PK: usize = 32;
const ED_SIG: usize = 64;
const ML_PK: usize = 1952;
const ML_SIG: usize = 3309;
/// Encoded public key size.
pub const PUBLIC_KEY_LEN: usize = ED_PK + ML_PK;
/// Encoded signature size.
pub const SIGNATURE_LEN: usize = ED_SIG + ML_SIG;
const ML_CTX: &[u8] = b"passback/v1";

/// A composite signing key.
pub struct SigningKey {
    seed: Key32,
    ed: ed25519_dalek::SigningKey,
    ml: ml_dsa::SigningKey<MlDsa65>,
    public: VerifyingKey,
}

/// A composite verifying key (`ed25519_pk || mldsa65_pk`).
#[derive(Clone)]
pub struct VerifyingKey {
    bytes: Vec<u8>,
    ed: ed25519_dalek::VerifyingKey,
    ml: ml_dsa::VerifyingKey<MlDsa65>,
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}
impl Eq for VerifyingKey {}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningKey(<redacted>)")
    }
}

impl core::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VerifyingKey({:02x?})", &self.fingerprint()[..8])
    }
}

fn message(context: &str, msg: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(b"passback/v1/sig").bytes(context.as_bytes()).bytes(msg);
    w.finish()
}

impl SigningKey {
    /// Generate a new key.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_seed(Key32::generate()?))
    }

    /// Rebuild from a stored seed.
    pub fn from_seed(seed: Key32) -> Self {
        let mut expanded = Zeroizing::new([0u8; 64]);
        let mut xof = Shake256::default();
        xof.update(b"passback/v1/sig-seed");
        xof.update(seed.expose());
        xof.finalize_xof().read(&mut expanded[..]);

        let mut ed_seed = Zeroizing::new([0u8; 32]);
        ed_seed.copy_from_slice(&expanded[..32]);
        let ed = ed25519_dalek::SigningKey::from_bytes(&ed_seed);
        let mut ml_seed = Zeroizing::new([0u8; 32]);
        ml_seed.copy_from_slice(&expanded[32..]);
        let ml = ml_dsa::SigningKey::<MlDsa65>::from_seed(&(*ml_seed).into());

        let ed_pub = ed.verifying_key();
        let ml_pub = ml.verifying_key();
        let mut bytes = ed_pub.to_bytes().to_vec();
        bytes.extend_from_slice(&ml_pub.to_bytes());
        let public = VerifyingKey {
            bytes,
            ed: ed_pub,
            ml: ml_pub,
        };
        Self { seed, ed, ml, public }
    }

    /// The seed, for storage inside an encrypted envelope.
    pub fn seed(&self) -> &Key32 {
        &self.seed
    }

    /// Public half.
    pub fn public(&self) -> &VerifyingKey {
        &self.public
    }

    /// Sign `msg` under a context label (e.g. `"commit"`, `"device-cert"`).
    pub fn sign(&self, context: &str, msg: &[u8]) -> Result<Vec<u8>> {
        let m = message(context, msg);
        let ed_sig = self.ed.sign(&m);
        let ml_sig = self
            .ml
            .expanded_key()
            .sign_deterministic(&m, ML_CTX)
            .map_err(|_| Error::Malformed("ml-dsa signing failed"))?;
        let mut out = ed_sig.to_bytes().to_vec();
        out.extend_from_slice(&ml_sig.encode());
        debug_assert_eq!(out.len(), SIGNATURE_LEN);
        Ok(out)
    }
}

impl VerifyingKey {
    /// Parse an encoded public key.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != PUBLIC_KEY_LEN {
            return Err(Error::Malformed("verifying key length"));
        }
        let ed_bytes: [u8; ED_PK] = b[..ED_PK].try_into().expect("length checked");
        let ed = ed25519_dalek::VerifyingKey::from_bytes(&ed_bytes).map_err(|_| Error::Malformed("ed25519 key"))?;
        if ed.is_weak() {
            return Err(Error::Malformed("weak ed25519 key"));
        }
        let enc = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(&b[ED_PK..])
            .map_err(|_| Error::Malformed("ml-dsa key"))?;
        let ml = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc);
        Ok(Self {
            bytes: b.to_vec(),
            ed,
            ml,
        })
    }

    /// Encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// SHA-256 fingerprint.
    pub fn fingerprint(&self) -> [u8; 32] {
        hash::sha256_labeled("passback/v1/sig-pk", &[&self.bytes])
    }

    /// Verify a composite signature. Both halves must verify.
    pub fn verify(&self, context: &str, msg: &[u8], sig: &[u8]) -> Result<()> {
        if sig.len() != SIGNATURE_LEN {
            return Err(Error::BadSignature);
        }
        let m = message(context, msg);
        let ed_sig = ed25519_dalek::Signature::from_bytes(sig[..ED_SIG].try_into().expect("len"));
        let ed_ok = self.ed.verify_strict(&m, &ed_sig).is_ok();
        let ml_ok = ml_dsa::EncodedSignature::<MlDsa65>::try_from(&sig[ED_SIG..])
            .ok()
            .and_then(|e| ml_dsa::Signature::<MlDsa65>::decode(&e))
            .is_some_and(|s| self.ml.verify_with_context(&m, ML_CTX, &s));
        if ed_ok & ml_ok {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }

    /// Verify with the standard Ed25519 verifier only. Exposed for tests of the
    /// composite rule; never use for real verification.
    #[doc(hidden)]
    pub fn verify_ed25519_only(&self, context: &str, msg: &[u8], sig: &[u8]) -> bool {
        let m = message(context, msg);
        sig.len() == SIGNATURE_LEN
            && self
                .ed
                .verify(
                    &m,
                    &ed25519_dalek::Signature::from_bytes(sig[..ED_SIG].try_into().expect("len")),
                )
                .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_composite_rule() {
        let k = SigningKey::generate().unwrap();
        let sig = k.sign("commit", b"hello").unwrap();
        assert_eq!(sig.len(), SIGNATURE_LEN);
        k.public().verify("commit", b"hello", &sig).unwrap();
        assert!(k.public().verify("commit", b"hellp", &sig).is_err());
        assert!(k.public().verify("device", b"hello", &sig).is_err());

        // Valid Ed25519 half + corrupted ML-DSA half must be rejected.
        let mut half = sig.clone();
        half[ED_SIG + 10] ^= 1;
        assert!(k.public().verify_ed25519_only("commit", b"hello", &half));
        assert!(k.public().verify("commit", b"hello", &half).is_err());
        // And the other way round.
        let mut half = sig.clone();
        half[3] ^= 1;
        assert!(k.public().verify("commit", b"hello", &half).is_err());

        let other = SigningKey::generate().unwrap();
        assert!(other.public().verify("commit", b"hello", &sig).is_err());

        let pk = VerifyingKey::from_bytes(k.public().as_bytes()).unwrap();
        pk.verify("commit", b"hello", &sig).unwrap();
        let again = SigningKey::from_seed(Key32::from_bytes(*k.seed().expose()));
        assert_eq!(again.public(), k.public());
    }
}
