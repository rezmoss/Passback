//! Shared by the libFuzzer targets in `fuzz/` and the stable robustness tests, so
//! both exercise exactly the same untrusted-input surface.

#![forbid(unsafe_code)]

use passback_crypto::{
    Key32,
    aead::{self, SealedBox},
    kdf::KdfParams,
    kem::{self, KemBox, KemPublicKey, KemSecretKey},
    keys::{ItemKey, VaultKey, new_id},
    secret_key::SecretKey,
    sign::{self, SigningKey, VerifyingKey},
    unlock::Factor,
    wire::{Reader, Writer},
};
use passback_format::{
    commit::{Checkpoint, Commit, Signers, VaultState},
    file::{self, VaultFile},
    record::Record,
};

/// Fixed key used to open fuzzed sealed boxes and KEM boxes.
pub const FUZZ_KEY: [u8; 32] = [0x5a; 32];
/// Password of the seed vault file.
pub const FUZZ_PASSWORD: &str = "fuzz";

/// Every decoder of untrusted bytes, by selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Surface {
    /// `SealedBox::from_bytes`.
    SealedBox = 0,
    /// Decode, then `aead::open` with the fixed key under a purpose no seed uses.
    SealedOpen,
    /// `Record::decode`.
    Record,
    /// `Commit::decode`.
    Commit,
    /// `Checkpoint::from_bytes`.
    Checkpoint,
    /// `file::peek`.
    FileHeader,
    /// `SecretKey::parse`.
    SecretKeyText,
    /// `KemPublicKey::from_bytes`, then encapsulate.
    KemPublicKey,
    /// `VerifyingKey::from_bytes`, then verify the remaining bytes as a signature.
    VerifyingKeyAndSignature,
    /// `KemBox::decode`, then open with the fixed key.
    KemBox,
    /// Full `VaultFile::open`. Runs Argon2 (64 MiB) when the header has minimum
    /// parameters, so it is slow by design.
    VaultFile,
}

impl Surface {
    /// All surfaces.
    pub const ALL: [Surface; 11] = [
        Surface::SealedBox,
        Surface::SealedOpen,
        Surface::Record,
        Surface::Commit,
        Surface::Checkpoint,
        Surface::FileHeader,
        Surface::SecretKeyText,
        Surface::KemPublicKey,
        Surface::VerifyingKeyAndSignature,
        Surface::KemBox,
        Surface::VaultFile,
    ];

    /// Selector byte to surface.
    pub fn from_byte(b: u8) -> Surface {
        Self::ALL[b as usize % Self::ALL.len()]
    }
}

/// Feed `data` to one decoder. Must never panic, hang or allocate without bound.
/// Panics only if a forged input is *accepted* where acceptance is impossible.
pub fn exercise(surface: Surface, data: &[u8]) {
    match surface {
        Surface::SealedBox => {
            let _ = SealedBox::from_bytes(data);
        }
        Surface::SealedOpen => {
            if let Ok(b) = SealedBox::from_bytes(data) {
                // Seeds are sealed for "fuzz-seed"; opening for "fuzz" must always fail.
                let key = Key32::from_bytes(FUZZ_KEY);
                assert!(
                    aead::open(&key, "fuzz", b"aad", &b).is_err(),
                    "forged sealed box accepted"
                );
            }
        }
        Surface::Record => {
            let _ = Record::decode(&mut Reader::new(data));
        }
        Surface::Commit => {
            let _ = Commit::decode(&mut Reader::new(data));
        }
        Surface::Checkpoint => {
            let _ = Checkpoint::from_bytes(data);
        }
        Surface::FileHeader => {
            let _ = file::peek(data);
        }
        Surface::SecretKeyText => {
            if let Ok(s) = core::str::from_utf8(data) {
                let _ = SecretKey::parse(s);
            }
        }
        Surface::KemPublicKey => {
            if let Ok(pk) = KemPublicKey::from_bytes(data) {
                let _ = pk.encapsulate();
            }
        }
        Surface::VerifyingKeyAndSignature => {
            let (pk, sig) = data.split_at(data.len().min(sign::PUBLIC_KEY_LEN));
            if let Ok(vk) = VerifyingKey::from_bytes(pk) {
                let _ = vk.verify("fuzz", b"message", sig);
            }
        }
        Surface::KemBox => {
            if let Ok(b) = KemBox::decode(&mut Reader::new(data), 1 << 20) {
                let sk = KemSecretKey::from_seed(Key32::from_bytes(FUZZ_KEY));
                let _ = kem::open_from(&sk, "fuzz", b"aad", &b);
            }
        }
        Surface::VaultFile => {
            if let Ok(h) = file::peek(data)
                && h.unlock.kdf == KdfParams::MIN
            {
                let _ = VaultFile::open(data, &[Factor::Password(FUZZ_PASSWORD)]);
            }
        }
    }
}

/// One valid encoding per surface, so mutations get past the first length check.
pub fn seeds() -> Vec<(Surface, Vec<u8>)> {
    let key = Key32::from_bytes(FUZZ_KEY);
    let sealed = aead::seal(&key, "fuzz-seed", b"aad", b"seed plaintext").expect("seal");

    let signer = SigningKey::from_seed(Key32::from_bytes([0x11; 32]));
    let vk = VaultKey::generate().expect("rng");
    let (vault, item, dev) = (new_id().expect("rng"), new_id().expect("rng"), new_id().expect("rng"));
    let rec = Record::seal(&vk, vault, item, 1, &ItemKey::generate().expect("rng"), b"seed").expect("seal");
    let mut state = VaultState::new(vault);
    let commit = state.prepare(&[&rec], dev, &signer, 1).expect("prepare");
    let mut signers = Signers::new();
    signers.allow(signer.public().clone());
    state.apply(&commit, &signers, &[&rec]).expect("apply");

    let kem_sk = KemSecretKey::from_seed(Key32::from_bytes(FUZZ_KEY));
    let kbox = kem::seal_to(kem_sk.public(), "fuzz", b"aad", b"seed").expect("seal_to");
    let mut kbox_enc = Writer::new();
    kbox.encode(&mut kbox_enc);

    let sig = signer.sign("fuzz", b"message").expect("sign");
    let vault_file = sample_vault_file();

    vec![
        (Surface::SealedBox, sealed.to_bytes()),
        (Surface::SealedOpen, sealed.to_bytes()),
        (Surface::Record, rec.to_bytes()),
        (Surface::Commit, commit.to_bytes()),
        (Surface::Checkpoint, state.checkpoint().to_bytes()),
        (Surface::FileHeader, vault_file.clone()),
        (
            Surface::SecretKeyText,
            SecretKey::from_bytes([3; 16]).to_display().as_bytes().to_vec(),
        ),
        (Surface::KemPublicKey, kem_sk.public().as_bytes().to_vec()),
        (
            Surface::VerifyingKeyAndSignature,
            [signer.public().as_bytes(), sig.as_slice()].concat(),
        ),
        (Surface::KemBox, kbox_enc.finish()),
        (Surface::VaultFile, vault_file),
    ]
}

/// A small valid vault file (password [`FUZZ_PASSWORD`], minimum KDF parameters).
pub fn sample_vault_file() -> Vec<u8> {
    let f = [Factor::Password(FUZZ_PASSWORD)];
    let mut vf = VaultFile::create(&f, KdfParams::MIN, 0).expect("create");
    let v = vf.add_vault().expect("vault");
    let dev = new_id().expect("rng");
    vf.put(&v, &new_id().expect("rng"), b"item one", dev, 1).expect("put");
    vf.put(&v, &new_id().expect("rng"), b"item two", dev, 2).expect("put");
    vf.to_bytes().expect("encode")
}
