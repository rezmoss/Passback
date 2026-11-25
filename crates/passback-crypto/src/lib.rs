//! Passback cryptographic core.
//!
//! Everything secret lives in types that zeroize on drop and never print their
//! contents. All ciphertexts are bound to a purpose label and caller-supplied
//! associated data, so a ciphertext produced for one place can't be replayed in another.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod aead;
mod error;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod keys;
pub mod rand;
pub mod secret;
pub mod secret_key;
pub mod selftest;
pub mod sign;
pub mod suite;
pub mod unlock;
pub mod wire;

pub use error::{Error, Result};
pub use secret::Key32;
pub use suite::Suite;
