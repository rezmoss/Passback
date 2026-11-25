//! Passback data format.
//!
//! - [`record`]: one encrypted item version (wrapped item key + sealed content).
//! - [`merkle`]: RFC 6962 Merkle trees over a vault's current items.
//! - [`commit`]: signed, hash-chained vault commits; [`commit::VaultState`] replays
//!   and verifies them; [`commit::Checkpoint`] detects rollback and forks.
//! - [`file`]: the single-file container (`.pbv`) used for portable vaults,
//!   backups and file-based sync.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod commit;
mod error;
pub mod file;
pub mod merkle;
pub mod record;

pub use error::{FormatError, Result};
