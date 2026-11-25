//! Hybrid post-quantum key encapsulation: X-Wing (ML-KEM-768 + X25519).
//!
//! Follows draft-connolly-cfrg-xwing-kem: a 32-byte seed is expanded with SHAKE256
//! into the ML-KEM-768 and X25519 private keys, and the two shared secrets are
//! combined with SHA3-256. The result is secure as long as *either* ML-KEM-768 or
//! X25519 holds.
//!
//! On top of the KEM, [`seal_to`] / [`open_from`] encrypt a message to a public key
//! (used to share vault keys with another account or device).

use ml_kem::{
    B32, KeyExport as _, MlKem768,
    kem::{Decapsulate as _, FromSeed as _},
};
use sha3::{
    Sha3_256, Shake256,
    digest::{Digest, ExtendableOutput, Update, XofReader},
};
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::Zeroizing;

use crate::{
    Error, Key32, Result, aead, hash,
    wire::{Reader, Writer},
};

const MLKEM_PK: usize = 1184;
const MLKEM_CT: usize = 1088;
/// Encoded X-Wing public key size.
pub const PUBLIC_KEY_LEN: usize = MLKEM_PK + 32;
/// Encoded X-Wing ciphertext size.
pub const CIPHERTEXT_LEN: usize = MLKEM_CT + 32;
const LABEL: &[u8; 6] = b"\\.//^\\";

/// An X-Wing private key. Only the 32-byte seed needs to be stored.
pub struct KemSecretKey {
    seed: Key32,
    dk: ml_kem::DecapsulationKey768,
    x: XSecret,
    public: KemPublicKey,
}

/// An X-Wing public key (`pk_M || pk_X`).
#[derive(Clone, PartialEq, Eq)]
pub struct KemPublicKey(Vec<u8>);

impl core::fmt::Debug for KemSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KemSecretKey(<redacted>)")
    }
}

impl core::fmt::Debug for KemPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KemPublicKey({:02x?})", &self.fingerprint()[..8])
    }
}

impl KemSecretKey {
    /// Generate a new key.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_seed(Key32::generate()?))
    }

    /// Rebuild from a stored seed.
    pub fn from_seed(seed: Key32) -> Self {
        let mut expanded = Zeroizing::new([0u8; 96]);
        let mut xof = Shake256::default();
        xof.update(seed.expose());
        xof.finalize_xof().read(&mut expanded[..]);

        let mut mseed = Zeroizing::new([0u8; 64]);
        mseed.copy_from_slice(&expanded[..64]);
        let (dk, ek) = MlKem768::from_seed(&(*mseed).into());
        let mut xs = [0u8; 32];
        xs.copy_from_slice(&expanded[64..]);
        let x = XSecret::from(xs);
        zeroize::Zeroize::zeroize(&mut xs);

        let mut pk = ek.to_bytes().to_vec();
        pk.extend_from_slice(XPublic::from(&x).as_bytes());
        Self {
            seed,
            dk,
            x,
            public: KemPublicKey(pk),
        }
    }

    /// The seed, for storage inside an encrypted envelope.
    pub fn seed(&self) -> &Key32 {
        &self.seed
    }

    /// Public half.
    pub fn public(&self) -> &KemPublicKey {
        &self.public
    }

    /// Recover the shared secret from a ciphertext.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<Key32> {
        if ct.len() != CIPHERTEXT_LEN {
            return Err(Error::Malformed("kem ciphertext length"));
        }
        let ct_m = ml_kem::Ciphertext::<MlKem768>::try_from(&ct[..MLKEM_CT])
            .map_err(|_| Error::Malformed("kem ciphertext"))?;
        let ss_m = Zeroizing::new(self.dk.decapsulate(&ct_m));
        let ct_x: [u8; 32] = ct[MLKEM_CT..].try_into().expect("length checked");
        let ss_x = self.x.diffie_hellman(&XPublic::from(ct_x));
        Ok(combine(&ss_m, ss_x.as_bytes(), &ct_x, self.public.x()))
    }
}

fn combine(ss_m: &[u8], ss_x: &[u8; 32], ct_x: &[u8; 32], pk_x: &[u8; 32]) -> Key32 {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ct_x);
    Digest::update(&mut h, pk_x);
    Digest::update(&mut h, LABEL);
    Key32::from_bytes(h.finalize().into())
}

impl KemPublicKey {
    /// Parse and validate an encoded public key.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != PUBLIC_KEY_LEN {
            return Err(Error::Malformed("kem public key length"));
        }
        let arr = ml_kem::Key::<ml_kem::EncapsulationKey768>::try_from(&b[..MLKEM_PK])
            .map_err(|_| Error::Malformed("kem public key"))?;
        ml_kem::EncapsulationKey768::new(&arr).map_err(|_| Error::Malformed("kem public key"))?;
        Ok(Self(b.to_vec()))
    }

    /// Encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn x(&self) -> &[u8; 32] {
        self.0[MLKEM_PK..].try_into().expect("length checked")
    }

    /// SHA-256 fingerprint, used for display and to bind ciphertexts to a recipient.
    pub fn fingerprint(&self) -> [u8; 32] {
        hash::sha256_labeled("passback/v1/kem-pk", &[&self.0])
    }

    /// Encapsulate: returns `(ciphertext, shared_secret)`.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Key32)> {
        let m: Zeroizing<[u8; 32]> = Zeroizing::new(crate::rand::array()?);
        let ek_x: Zeroizing<[u8; 32]> = Zeroizing::new(crate::rand::array()?);
        self.encapsulate_derand(&m, &ek_x)
    }

    /// Deterministic encapsulation for test vectors. Never call with non-random inputs.
    #[doc(hidden)]
    pub fn encapsulate_derand(&self, m: &[u8; 32], ek_x: &[u8; 32]) -> Result<(Vec<u8>, Key32)> {
        let arr = ml_kem::Key::<ml_kem::EncapsulationKey768>::try_from(&self.0[..MLKEM_PK])
            .map_err(|_| Error::Malformed("kem public key"))?;
        let ek = ml_kem::EncapsulationKey768::new(&arr).map_err(|_| Error::Malformed("kem public key"))?;
        let (ct_m, ss_m) = ek.encapsulate_deterministic(&B32::from(*m));
        let ss_m = Zeroizing::new(ss_m);
        let eph = XSecret::from(*ek_x);
        let ct_x = *XPublic::from(&eph).as_bytes();
        let ss_x = eph.diffie_hellman(&XPublic::from(*self.x()));
        let ss = combine(&ss_m, ss_x.as_bytes(), &ct_x, self.x());
        let mut ct = ct_m.to_vec();
        ct.extend_from_slice(&ct_x);
        Ok((ct, ss))
    }
}

/// A message encrypted to a public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KemBox {
    /// X-Wing ciphertext.
    pub kem_ct: Vec<u8>,
    /// Payload sealed with the derived key.
    pub sealed: aead::SealedBox,
}

fn wrap_key(ss: &Key32, kem_ct: &[u8], purpose: &str) -> Key32 {
    let salt = hash::sha256_labeled("passback/v1/kem-ct", &[kem_ct]);
    hash::hkdf_key(ss.expose(), &salt, format!("passback/v1/kem-seal/{purpose}").as_bytes())
}

fn bound_aad(recipient: &KemPublicKey, aad: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.fixed(&recipient.fingerprint()).bytes(aad);
    w.finish()
}

/// Encrypt `plaintext` so only the holder of `recipient`'s private key can read it.
pub fn seal_to(recipient: &KemPublicKey, purpose: &str, aad: &[u8], plaintext: &[u8]) -> Result<KemBox> {
    let (kem_ct, ss) = recipient.encapsulate()?;
    let k = wrap_key(&ss, &kem_ct, purpose);
    let sealed = aead::seal(&k, purpose, &bound_aad(recipient, aad), plaintext)?;
    Ok(KemBox { kem_ct, sealed })
}

/// Open a [`KemBox`] with our private key.
pub fn open_from(sk: &KemSecretKey, purpose: &str, aad: &[u8], b: &KemBox) -> Result<Zeroizing<Vec<u8>>> {
    let ss = sk.decapsulate(&b.kem_ct).map_err(|_| Error::Decrypt)?;
    let k = wrap_key(&ss, &b.kem_ct, purpose);
    aead::open(&k, purpose, &bound_aad(sk.public(), aad), &b.sealed)
}

impl KemBox {
    /// Canonical encoding.
    pub fn encode(&self, w: &mut Writer) {
        w.fixed(&self.kem_ct);
        self.sealed.encode(w);
    }
    /// Decode.
    pub fn decode(r: &mut Reader<'_>, max_ct: usize) -> Result<Self> {
        let kem_ct = r.raw(CIPHERTEXT_LEN)?.to_vec();
        let sealed = aead::SealedBox::decode(r, max_ct)?;
        Ok(Self { kem_ct, sealed })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_roundtrip() {
        let sk = KemSecretKey::generate().unwrap();
        let (ct, ss) = sk.public().encapsulate().unwrap();
        assert_eq!(ct.len(), CIPHERTEXT_LEN);
        assert_eq!(sk.decapsulate(&ct).unwrap().expose(), ss.expose());
        let again = KemSecretKey::from_seed(Key32::from_bytes(*sk.seed().expose()));
        assert_eq!(again.public(), sk.public());
        KemPublicKey::from_bytes(sk.public().as_bytes()).unwrap();
    }

    #[test]
    fn seal_to_roundtrip_and_recipient_binding() {
        let alice = KemSecretKey::generate().unwrap();
        let mallory = KemSecretKey::generate().unwrap();
        let b = seal_to(alice.public(), "vault-key-share", b"vault-1", b"secret").unwrap();
        assert_eq!(
            &*open_from(&alice, "vault-key-share", b"vault-1", &b).unwrap(),
            b"secret"
        );
        assert!(open_from(&alice, "vault-key-share", b"vault-2", &b).is_err());
        assert!(open_from(&mallory, "vault-key-share", b"vault-1", &b).is_err());
        let mut w = Writer::new();
        b.encode(&mut w);
        let enc = w.finish();
        let mut r = Reader::new(&enc);
        assert_eq!(KemBox::decode(&mut r, 1 << 20).unwrap(), b);
    }
}
