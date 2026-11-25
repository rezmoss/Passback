//! Randomness from the operating system CSPRNG only.

use crate::{Error, Result};

/// Fill `buf` with random bytes from the OS.
pub fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Rng)
}

/// Return `N` random bytes.
pub fn array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}
