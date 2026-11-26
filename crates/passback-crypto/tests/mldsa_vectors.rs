//! Independent ML-DSA-65 known-answer tests (NIST ACVP, FIPS 204).
//!
//! Catches: a wrong or changed ML-DSA implementation. The composite signature tests
//! only check self-consistency; these check agreement with NIST.

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKeyBytes, KeyExport, Keypair, MlDsa65, Signature, SigningKey,
    VerifyingKey,
};

fn cases(kind: &str) -> Vec<std::collections::HashMap<String, Vec<u8>>> {
    let text = include_str!("vectors/mldsa65-acvp.txt");
    // Blocks are separated by blank lines; parse line by line so CRLF checkouts work too.
    let mut blocks: Vec<Vec<&str>> = vec![vec![]];
    for line in text.lines().map(str::trim_end) {
        if line.is_empty() {
            blocks.push(vec![]);
        } else if !line.starts_with('#') {
            blocks.last_mut().unwrap().push(line);
        }
    }
    let out: Vec<_> = blocks
        .into_iter()
        .filter(|b| b.first().is_some_and(|h| h.starts_with(kind)))
        .map(|b| {
            b[1..]
                .iter()
                .map(|l| {
                    let (k, v) = l.split_once(' ').unwrap_or((l, ""));
                    (k.to_string(), hex::decode(v.trim()).unwrap())
                })
                .collect()
        })
        .collect();
    assert_eq!(out.len(), 3, "{kind} cases");
    out
}

#[test]
fn keygen_from_seed_matches_nist() {
    for c in cases("keygen") {
        let seed: [u8; 32] = c["seed"].as_slice().try_into().unwrap();
        let sk = SigningKey::<MlDsa65>::from_seed(&seed.into());
        assert_eq!(sk.verifying_key().to_bytes().as_slice(), c["pk"].as_slice());
    }
}

#[test]
fn deterministic_signature_with_context_matches_nist() {
    for c in cases("siggen") {
        let sk_bytes = ExpandedSigningKeyBytes::<MlDsa65>::try_from(c["sk"].as_slice()).unwrap();
        // ACVP sigGen vectors give only the expanded private key, so the expanded-key
        // constructor is the only way to use them.
        #[allow(deprecated)]
        let sk = ml_dsa::ExpandedSigningKey::<MlDsa65>::from_expanded(&sk_bytes);
        let sig = sk.sign_deterministic(&c["message"], &c["context"]).unwrap();
        assert_eq!(sig.encode().as_slice(), c["signature"].as_slice());

        let vk =
            VerifyingKey::<MlDsa65>::decode(&EncodedVerifyingKey::<MlDsa65>::try_from(c["pk"].as_slice()).unwrap());
        let parsed =
            Signature::<MlDsa65>::decode(&EncodedSignature::<MlDsa65>::try_from(c["signature"].as_slice()).unwrap())
                .unwrap();
        assert!(vk.verify_with_context(&c["message"], &c["context"], &parsed));
        let mut other_ctx = c["context"].clone();
        other_ctx.push(0);
        assert!(
            !vk.verify_with_context(&c["message"], &other_ctx, &parsed),
            "context must be bound"
        );
    }
}
