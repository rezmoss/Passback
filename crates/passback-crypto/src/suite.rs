//! Algorithm suites (crypto agility).
//!
//! Every encrypted or signed object carries the suite id it was made with.
//! Readers reject unknown suites. When the default suite changes, objects made with
//! an older accepted suite still open and are re-encrypted on next write
//! (see [`Suite::needs_upgrade`]).

use crate::{Error, Result};

/// A versioned set of algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Suite {
    /// Suite 1:
    /// Argon2id; HKDF-SHA256; XChaCha20-Poly1305 with HKDF key commitment;
    /// X-Wing (ML-KEM-768 + X25519) KEM; Ed25519 + ML-DSA-65 composite signatures;
    /// SHA-256 Merkle trees and hash chains.
    V1 = 1,
}

impl Suite {
    /// The suite used for all new objects.
    pub const CURRENT: Suite = Suite::V1;

    /// Parse a suite id byte.
    pub fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(Suite::V1),
            other => Err(Error::UnsupportedSuite(other)),
        }
    }

    /// Wire id.
    pub fn id(self) -> u8 {
        self as u8
    }

    /// True when objects in this suite should be re-encrypted with [`Suite::CURRENT`].
    pub fn needs_upgrade(self) -> bool {
        self != Suite::CURRENT
    }
}
