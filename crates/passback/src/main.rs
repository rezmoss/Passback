//! The `passback` binary.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::Serialize;

mod build_info;

#[derive(Parser)]
#[command(
    name = "passback",
    version,
    about = "Open-source password and secrets manager",
    propagate_version = true
)]
struct Cli {
    /// Machine-readable JSON output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show version, build target and compiled-in features.
    Version,
    /// Run the cryptographic self-tests and report the result.
    Selftest,
    /// Show the security posture of this process and build: hardening, network, crypto suite.
    Security,
    /// Print the SHA-256 of this executable, to compare with the published release checksums.
    SelfHash,
    /// Measure Argon2id on this machine and suggest parameters.
    BenchKdf {
        /// Memory in MiB.
        #[arg(long, default_value_t = 256)]
        memory_mib: u32,
        /// Target unlock time in milliseconds.
        #[arg(long, default_value_t = 1000)]
        target_ms: u64,
    },
}

fn emit<T: Serialize>(json: bool, value: &T, human: impl FnOnce(&T)) {
    if json {
        println!("{}", serde_json::to_string_pretty(value).expect("serializable"));
    } else {
        human(value);
    }
}

#[derive(Serialize)]
struct Security {
    selftest: &'static str,
    hardening_applied: Vec<&'static str>,
    hardening_missing: Vec<&'static str>,
    secure_memory_locked: bool,
    network: &'static str,
    telemetry: &'static str,
    suite: Suite,
}

#[derive(Serialize)]
struct Suite {
    id: u8,
    kdf: &'static str,
    kdf_default: String,
    aead: &'static str,
    kem: &'static str,
    signature: &'static str,
    hash: &'static str,
}

fn suite() -> Suite {
    let d = passback_crypto::kdf::KdfParams::DEFAULT;
    Suite {
        id: passback_crypto::Suite::CURRENT.id(),
        kdf: "Argon2id",
        kdf_default: format!("m={} MiB, t={}, p={}", d.m_kib / 1024, d.t, d.p),
        aead: "XChaCha20-Poly1305 + HKDF-SHA256 key commitment",
        kem: "X-Wing (ML-KEM-768 + X25519)",
        signature: "Ed25519 + ML-DSA-65 (both required)",
        hash: "SHA-256, HKDF-SHA256, SHA3-256",
    }
}

fn main() -> ExitCode {
    let hardening = passback_harden::harden_process();
    let cli = Cli::parse();

    if let Err(e) = passback_crypto::selftest::run() {
        eprintln!("passback: {e}. This binary is not safe to use.");
        return ExitCode::from(70);
    }

    match cli.cmd {
        Cmd::Version => {
            let info = build_info::get();
            emit(cli.json, &info, |i| {
                println!("passback {} ({}, {})", i.version, i.target, i.commit);
                println!("features: {}", i.features.join(", "));
            });
        }
        Cmd::Selftest => emit(cli.json, &serde_json::json!({"selftest": "passed"}), |_| {
            println!(
                "self-tests passed: Argon2id, HKDF-SHA256, XChaCha20-Poly1305, Ed25519, X-Wing, composite signature, committing AEAD"
            );
        }),
        Cmd::Security => {
            let locked = passback_harden::SecureBuf::new(32).map(|b| b.locked()).unwrap_or(false);
            let s = Security {
                selftest: "passed",
                hardening_applied: hardening.applied,
                hardening_missing: hardening.missing,
                secure_memory_locked: locked,
                network: build_info::NETWORK,
                telemetry: "none",
                suite: suite(),
            };
            emit(cli.json, &s, |s| {
                println!("self-test:   {}", s.selftest);
                for a in &s.hardening_applied {
                    println!("hardening:   + {a}");
                }
                for m in &s.hardening_missing {
                    println!("hardening:   - {m}");
                }
                println!(
                    "memory lock: {}",
                    if s.secure_memory_locked {
                        "yes"
                    } else {
                        "no (raise RLIMIT_MEMLOCK)"
                    }
                );
                println!("network:     {}", s.network);
                println!("telemetry:   {}", s.telemetry);
                println!(
                    "suite {}:     {} | {} | {} | {}",
                    s.suite.id, s.suite.kdf, s.suite.aead, s.suite.kem, s.suite.signature
                );
            });
        }
        Cmd::SelfHash => match build_info::self_hash() {
            Ok((path, hash)) => emit(cli.json, &serde_json::json!({"path": path, "sha256": hash}), |_| {
                println!("{hash}  {path}");
            }),
            Err(e) => {
                eprintln!("passback: cannot read own executable: {e}");
                return ExitCode::FAILURE;
            }
        },
        Cmd::BenchKdf { memory_mib, target_ms } => {
            let target = std::time::Duration::from_millis(target_ms);
            match passback_crypto::kdf::calibrate(memory_mib.saturating_mul(1024), 4, target) {
                Ok(p) => {
                    let start = std::time::Instant::now();
                    let _ = passback_crypto::kdf::derive("benchmark", &[0u8; 32], &p);
                    let ms = start.elapsed().as_millis();
                    emit(
                        cli.json,
                        &serde_json::json!({"m_mib": p.m_kib / 1024, "t": p.t, "p": p.p, "measured_ms": ms}),
                        |_| {
                            println!("Argon2id m={} MiB t={} p={} -> {} ms", p.m_kib / 1024, p.t, p.p, ms);
                        },
                    );
                }
                Err(e) => {
                    eprintln!("passback: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
    }
    ExitCode::SUCCESS
}
