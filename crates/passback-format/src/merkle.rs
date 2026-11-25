//! RFC 6962 (Certificate Transparency) Merkle tree hash with SHA-256.
//!
//! `MTH({}) = SHA-256()`, `MTH({d}) = SHA-256(0x00 || d)`, and for `n > 1`, with `k` the
//! largest power of two below `n`: `MTH(D) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))`.

use sha2::{Digest, Sha256};

/// A 32-byte hash.
pub type Hash = [u8; 32];

/// Leaf hash.
pub fn leaf(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}

fn node(l: &Hash, r: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

fn split(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Root over already-hashed leaves.
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// Audit path proving `leaves[index]` is in the tree.
pub fn prove(leaves: &[Hash], index: usize) -> Vec<Hash> {
    assert!(index < leaves.len());
    let mut path = Vec::new();
    fn go(leaves: &[Hash], i: usize, path: &mut Vec<Hash>) {
        if leaves.len() <= 1 {
            return;
        }
        let k = split(leaves.len());
        if i < k {
            go(&leaves[..k], i, path);
            path.push(root(&leaves[k..]));
        } else {
            go(&leaves[k..], i - k, path);
            path.push(root(&leaves[..k]));
        }
    }
    go(leaves, index, &mut path);
    path
}

/// Verify an audit path (RFC 9162 section 2.1.3.2).
pub fn verify(leaf_hash: &Hash, index: usize, size: usize, path: &[Hash], expected_root: &Hash) -> bool {
    if index >= size {
        return false;
    }
    let (mut fn_, mut sn) = (index, size - 1);
    let mut r = *leaf_hash;
    for p in path {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node(p, &r);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && &r == expected_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofs_verify_for_all_sizes() {
        for n in 1..40usize {
            let leaves: Vec<Hash> = (0..n).map(|i| leaf(&[i as u8])).collect();
            let r = root(&leaves);
            for i in 0..n {
                let p = prove(&leaves, i);
                assert!(verify(&leaves[i], i, n, &p, &r), "n={n} i={i}");
                assert!(!verify(&leaf(b"x"), i, n, &p, &r));
                if n > 1 {
                    assert!(!verify(&leaves[i], (i + 1) % n, n, &p, &r));
                }
            }
        }
    }

    #[test]
    fn known_root() {
        // RFC 6962 empty-tree hash is SHA-256 of the empty string.
        assert_eq!(
            root(&[]),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27,
                0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
            ]
        );
    }
}
