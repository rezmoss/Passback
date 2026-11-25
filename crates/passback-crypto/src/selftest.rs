//! Power-on self-tests.
//!
//! The binary runs [`run`] at startup and refuses to touch any vault if it fails, so
//! a miscompiled or tampered build can't silently produce bad ciphertexts. Every
//! test uses a published known-answer vector, except where noted.

use ed25519_dalek::Signer as _;

use crate::{Error, Key32, Result, aead, hash, kem::KemSecretKey, sign::SigningKey};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn check(ok: bool, what: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(Error::SelfTest(what)) }
}

/// RFC 9106 section 5.3, Argon2id.
fn argon2id() -> Result<()> {
    use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(AssociatedData::new(&[4u8; 12]).map_err(|_| Error::SelfTest("argon2 ad"))?)
        .build()
        .map_err(|_| Error::SelfTest("argon2 params"))?;
    let a = Argon2::new_with_secret(&[3u8; 8], Algorithm::Argon2id, Version::V0x13, params)
        .map_err(|_| Error::SelfTest("argon2 init"))?;
    let mut out = [0u8; 32];
    a.hash_password_into(&[1u8; 32], &[2u8; 16], &mut out)
        .map_err(|_| Error::SelfTest("argon2 run"))?;
    check(
        out[..] == unhex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")[..],
        "argon2id KAT",
    )
}

/// RFC 5869 test case 1, HKDF-SHA256.
fn hkdf_sha256() -> Result<()> {
    let mut okm = [0u8; 42];
    hash::hkdf(
        &[0x0b; 22],
        &unhex("000102030405060708090a0b0c"),
        &unhex("f0f1f2f3f4f5f6f7f8f9"),
        &mut okm,
    );
    check(
        okm[..] == unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")[..],
        "hkdf KAT",
    )
}

/// draft-irtf-cfrg-xchacha-03 appendix A.3.1, XChaCha20-Poly1305.
fn xchacha() -> Result<()> {
    use chacha20poly1305::{
        KeyInit, XChaCha20Poly1305,
        aead::{Aead, Payload},
    };
    let key: [u8; 32] = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        .try_into()
        .expect("32");
    let nonce: [u8; 24] = unhex("404142434445464748494a4b4c4d4e4f5051525354555657")
        .try_into()
        .expect("24");
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let ct = XChaCha20Poly1305::new(&key.into())
        .encrypt(
            &nonce.into(),
            Payload {
                msg: pt,
                aad: &unhex("50515253c0c1c2c3c4c5c6c7"),
            },
        )
        .map_err(|_| Error::SelfTest("xchacha encrypt"))?;
    let want = unhex(concat!(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
        "21f9664c97637da9768812f615c68b13b52e",
        "c0875924c1c7987947deafd8780acf49"
    ));
    check(ct == want, "xchacha20-poly1305 KAT")
}

/// RFC 8032 section 7.1 test 1, Ed25519.
fn ed25519() -> Result<()> {
    let sk: [u8; 32] = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        .try_into()
        .expect("32");
    let k = ed25519_dalek::SigningKey::from_bytes(&sk);
    check(
        k.verifying_key().to_bytes()[..]
            == unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")[..],
        "ed25519 public key KAT",
    )?;
    let sig = k.sign(b"");
    check(
        sig.to_bytes()[..]
            == unhex(concat!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            ))[..],
        "ed25519 signature KAT",
    )
}

/// draft-connolly-cfrg-xwing-kem test vector 1 (digests of pk and ct, full ss).
fn xwing() -> Result<()> {
    let sk = KemSecretKey::from_seed(Key32::from_slice(&unhex(
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
    ))?);
    check(
        hash::sha256(sk.public().as_bytes())[..]
            == unhex("2e816deebcd76c5c80d0cd2d174478871658e8e2ff42bc9d4a6e486372e856bb")[..],
        "x-wing public key KAT",
    )?;
    let eseed = unhex(concat!(
        "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2",
        "35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2"
    ));
    let (ct, ss) = sk
        .public()
        .encapsulate_derand(eseed[..32].try_into().expect("32"), eseed[32..].try_into().expect("32"))?;
    check(
        hash::sha256(&ct)[..] == unhex("17cd532d657e44c897ca6583e548a5424fc70bf54f99515a4d2bcf99e3469f33")[..],
        "x-wing ciphertext KAT",
    )?;
    check(
        ss.expose()[..] == unhex("d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384")[..],
        "x-wing shared secret KAT",
    )?;
    check(sk.decapsulate(&ct)?.expose() == ss.expose(), "x-wing decapsulate")
}

/// Composite signature: sign/verify, and rejection of a tampered ML-DSA half.
/// (No external vector: the composite is Passback-specific; pinned vectors live in
/// the crate's integration tests.)
fn composite_signature() -> Result<()> {
    let k = SigningKey::from_seed(Key32::from_bytes([0x42; 32]));
    let sig = k.sign("selftest", b"passback")?;
    check(
        k.public().verify("selftest", b"passback", &sig).is_ok(),
        "signature verify",
    )?;
    let mut bad = sig;
    let last = bad.len() - 1;
    bad[last] ^= 1;
    check(
        k.public().verify("selftest", b"passback", &bad).is_err(),
        "signature tamper rejected",
    )
}

/// Committing AEAD: roundtrip, wrong-key, wrong-purpose.
fn committing_aead() -> Result<()> {
    let k = Key32::from_bytes([7; 32]);
    let b = aead::seal_with_nonce(&k, "selftest", b"aad", b"plaintext", [9; 24])?;
    check(
        &**aead::open(&k, "selftest", b"aad", &b)? == b"plaintext",
        "aead roundtrip",
    )?;
    check(
        aead::open(&Key32::from_bytes([8; 32]), "selftest", b"aad", &b).is_err(),
        "aead wrong key",
    )?;
    check(aead::open(&k, "other", b"aad", &b).is_err(), "aead wrong purpose")
}

/// Run every self-test. Takes a few milliseconds.
pub fn run() -> Result<()> {
    argon2id()?;
    hkdf_sha256()?;
    xchacha()?;
    ed25519()?;
    xwing()?;
    composite_signature()?;
    committing_aead()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn selftest_passes() {
        super::run().unwrap();
    }
}
