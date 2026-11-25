//! Password key derivation (Argon2id).

use argon2::{Algorithm, Argon2, Params, Version};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::{Error, Key32, Result};

/// Argon2id cost parameters, stored next to the data they protect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl KdfParams {
    /// Default for new vaults: 256 MiB, 3 passes, 4 lanes.
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: 256 * 1024,
        t: 3,
        p: 4,
    };
    /// Floor accepted when opening anything (OWASP 2025 lower bound is 46 MiB / t=1).
    pub const MIN: KdfParams = KdfParams {
        m_kib: 64 * 1024,
        t: 2,
        p: 1,
    };
    /// Ceiling accepted from untrusted headers, so a crafted file can't exhaust memory or CPU.
    pub const MAX: KdfParams = KdfParams {
        m_kib: 4 * 1024 * 1024,
        t: 64,
        p: 64,
    };

    /// Reject parameters outside `[MIN, MAX]`.
    pub fn validate(&self) -> Result<()> {
        if self.m_kib < Self::MIN.m_kib || self.t < Self::MIN.t || self.p < Self::MIN.p {
            return Err(Error::WeakKdf("below minimum"));
        }
        if self.m_kib > Self::MAX.m_kib || self.t > Self::MAX.t || self.p > Self::MAX.p {
            return Err(Error::WeakKdf("above maximum"));
        }
        if self.m_kib < 8 * self.p {
            return Err(Error::WeakKdf("memory below 8*p"));
        }
        Ok(())
    }

    /// True when these parameters are weaker than [`KdfParams::DEFAULT`] and should be raised.
    pub fn below_default(&self) -> bool {
        self.m_kib < Self::DEFAULT.m_kib || self.t < Self::DEFAULT.t
    }

    /// Encode as 12 bytes (m, t, p big-endian).
    pub fn encode(&self, w: &mut crate::wire::Writer) {
        w.u32(self.m_kib).u32(self.t).u32(self.p);
    }

    /// Decode and validate.
    pub fn decode(r: &mut crate::wire::Reader<'_>) -> Result<Self> {
        let p = KdfParams {
            m_kib: r.u32()?,
            t: r.u32()?,
            p: r.u32()?,
        };
        p.validate()?;
        Ok(p)
    }
}

/// Normalize a password to Unicode NFKC so the same password typed on different
/// keyboards or OSes derives the same key.
pub fn normalize_password(password: &str) -> Zeroizing<Vec<u8>> {
    let s: Zeroizing<String> = Zeroizing::new(password.nfkc().collect());
    Zeroizing::new(s.as_bytes().to_vec())
}

/// Argon2id(password, salt) -> 32 bytes, after NFKC normalization.
pub fn derive(password: &str, salt: &[u8; 32], params: &KdfParams) -> Result<Key32> {
    params.validate()?;
    let pw = normalize_password(password);
    raw_argon2id(&pw, salt, params)
}

pub(crate) fn raw_argon2id(pw: &[u8], salt: &[u8], params: &KdfParams) -> Result<Key32> {
    let p =
        Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| Error::WeakKdf("rejected by argon2"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(pw, salt, &mut out[..])
        .map_err(|_| Error::WeakKdf("argon2 failed"))?;
    Ok(Key32::from_bytes(*out))
}

/// Pick the largest iteration count that stays under `target` on this machine,
/// keeping memory at `m_kib`. Never returns less than [`KdfParams::MIN`].
pub fn calibrate(m_kib: u32, p: u32, target: std::time::Duration) -> Result<KdfParams> {
    let base = KdfParams { m_kib, t: 1, p };
    let start = std::time::Instant::now();
    raw_argon2id(b"calibration", &[0u8; 32], &base)?;
    let one = start.elapsed().max(std::time::Duration::from_millis(1));
    let t = (target.as_nanos() / one.as_nanos()).clamp(1, KdfParams::MAX.t as u128) as u32;
    let params = KdfParams {
        m_kib,
        t: t.max(KdfParams::MIN.t),
        p,
    };
    params.validate()?;
    Ok(params)
}
