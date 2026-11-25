//! Facts about this build.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Network capability of this binary. Phase 0 links no networking code at all;
/// CI enforces this (`scripts/check-no-network.sh`).
pub const NETWORK: &str = "none compiled in (no sockets, no update checks, no telemetry)";

#[derive(Serialize)]
pub struct BuildInfo {
    pub version: &'static str,
    pub commit: &'static str,
    pub target: &'static str,
    pub profile: &'static str,
    pub features: Vec<&'static str>,
    pub format_version: u16,
    pub crypto_suite: u8,
}

pub fn get() -> BuildInfo {
    let mut features = Vec::new();
    for (on, name) in [
        (cfg!(feature = "cli"), "cli"),
        (cfg!(feature = "daemon"), "daemon"),
        (cfg!(feature = "web-ui"), "web-ui"),
        (cfg!(feature = "server"), "server"),
        (cfg!(feature = "browser"), "browser"),
        (cfg!(feature = "agent"), "agent"),
    ] {
        if on {
            features.push(name);
        }
    }
    BuildInfo {
        version: env!("CARGO_PKG_VERSION"),
        commit: env!("PASSBACK_GIT_COMMIT"),
        target: env!("PASSBACK_TARGET"),
        profile: env!("PASSBACK_PROFILE"),
        features,
        format_version: passback_format::file::FORMAT_VERSION,
        crypto_suite: passback_crypto::Suite::CURRENT.id(),
    }
}

pub fn self_hash() -> std::io::Result<(String, String)> {
    let path = std::env::current_exe()?;
    let bytes = std::fs::read(&path)?;
    Ok((path.display().to_string(), hex::encode(Sha256::digest(&bytes))))
}
