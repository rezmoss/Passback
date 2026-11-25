//! Secret byte containers.

use core::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A 256-bit secret key. Heap allocated so moves don't leave copies on the stack,
/// zeroized on drop, never printed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key32(Box<[u8; 32]>);

impl Key32 {
    /// Generate a fresh random key.
    pub fn generate() -> crate::Result<Self> {
        let mut k = Box::new([0u8; 32]);
        crate::rand::fill(&mut k[..])?;
        Ok(Self(k))
    }

    /// Take ownership of key bytes. The caller's copy is zeroized.
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let k = Box::new(bytes);
        bytes.zeroize();
        Self(k)
    }

    /// Build from a slice of exactly 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> crate::Result<Self> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| crate::Error::Malformed("key length"))?;
        Ok(Self::from_bytes(arr))
    }

    /// Borrow the raw key bytes. Keep the borrow short.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// Copy into a zeroizing buffer, for serialization into an encrypted envelope.
    pub fn to_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_vec())
    }
}

impl ConstantTimeEq for Key32 {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&*other.0)
    }
}

impl fmt::Debug for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key32(<redacted>)")
    }
}
