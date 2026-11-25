//! Pinned vectors for Passback-specific constructions (suite 1).
//!
//! These are not from an external standard. They exist so any change that would
//! make existing vaults unreadable fails CI.

use passback_crypto::{
    Key32, aead, hash,
    kdf::KdfParams,
    secret_key::SecretKey,
    sign::SigningKey,
    unlock::{Factor, UnlockParams, derive_unlock_key},
};

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

const UNLOCK_PW_ONLY: &str = "2408f238ee87b79a0679be2a53a8c0f78d58e24a2e53cdeca6b77b7c387507c7";
const UNLOCK_TWO_SECRET: &str = "2e4af3b0b242e991a523a26ebd280cf80e541fbae3e51c267df7191219a28f26";
const AEAD_BOX: &str = "01444444444444444444444444444444444444444444444444c41127baec216e8c4d36d1f20a243540382ece674df1c1243ed53cfac071fb7200000015ee552fe57187e4e8d25e3bac67adbebace052e0f2b";
const SIG_SHA256: &str = "c5106eb3463201280b6f07aa251b60109d60adf258d5e7f502125f899318a53c";
const SECRET_KEY_TEXT: &str = "PB1-1G64-S36D-1N6R-VKGE-B1C9-HP8S-B6FE";

fn params() -> UnlockParams {
    UnlockParams {
        account_id: [0x11; 16],
        salt: [0x22; 32],
        kdf: KdfParams::MIN,
    }
}

#[test]
fn v1_pinned() {
    let sk = SecretKey::from_bytes(*b"0123456789abcdef");
    let pw = derive_unlock_key(&params(), &[Factor::Password("correct horse battery staple")]).unwrap();
    let two = derive_unlock_key(
        &params(),
        &[Factor::Password("correct horse battery staple"), Factor::SecretKey(&sk)],
    )
    .unwrap();
    let b = aead::seal_with_nonce(
        &Key32::from_bytes([0x33; 32]),
        "item-content",
        b"aad",
        b"hello",
        [0x44; 24],
    )
    .unwrap();
    let sig = SigningKey::from_seed(Key32::from_bytes([0x55; 32]))
        .sign("commit", b"msg")
        .unwrap();

    let got = [
        ("UNLOCK_PW_ONLY", hx(pw.expose()), UNLOCK_PW_ONLY),
        ("UNLOCK_TWO_SECRET", hx(two.expose()), UNLOCK_TWO_SECRET),
        ("AEAD_BOX", hx(&b.to_bytes()), AEAD_BOX),
        ("SIG_SHA256", hx(&hash::sha256(&sig)), SIG_SHA256),
        ("SECRET_KEY_TEXT", sk.to_display().to_string(), SECRET_KEY_TEXT),
    ];
    let mut bad = false;
    for (name, have, want) in &got {
        if have != want {
            eprintln!("{name} = \"{have}\"");
            bad = true;
        }
    }
    assert!(!bad, "pinned vectors changed");
}
