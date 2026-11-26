//! Secret-bearing types must never print key material in debug output (logs,
//! panics, error reports).

use passback_crypto::{
    Key32,
    kem::KemSecretKey,
    keys::{AccountKey, ItemKey, VaultKey},
    secret_key::SecretKey,
    sign::SigningKey,
};

#[test]
fn debug_output_of_secret_types_is_exactly_the_redacted_form() {
    let seed = || Key32::from_bytes([0xab; 32]);
    let cases = [
        (format!("{:?}", seed()), "Key32(<redacted>)"),
        (
            format!("{:?}", SecretKey::from_bytes([0xab; 16])),
            "SecretKey(<redacted>)",
        ),
        (
            format!("{:?}", KemSecretKey::from_seed(seed())),
            "KemSecretKey(<redacted>)",
        ),
        (format!("{:?}", SigningKey::from_seed(seed())), "SigningKey(<redacted>)"),
        (
            format!("{:?}", AccountKey::generate().unwrap()),
            "AccountKey(Key32(<redacted>))",
        ),
        (
            format!("{:?}", VaultKey::generate().unwrap()),
            "VaultKey(Key32(<redacted>))",
        ),
        (
            format!("{:?}", ItemKey::generate().unwrap()),
            "ItemKey(Key32(<redacted>))",
        ),
    ];
    for (got, want) in cases {
        assert_eq!(got, want);
    }
}
