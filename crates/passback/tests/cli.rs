//! Contract tests for the `passback` binary: exit codes, JSON output that scripts
//! and agents rely on, stdout/stderr separation, resource limits, and no stray files.

use std::time::Duration;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Runs the binary with an empty, isolated home/config dir and a timeout.
struct Env {
    home: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::cargo_bin("passback").unwrap();
        let h = self.home.path();
        // Run inside the temp dir too, so relative-path writes are caught by the
        // stray-file check in `Drop`.
        c.args(args)
            .current_dir(h)
            .env_clear()
            .env("HOME", h)
            .env("XDG_CONFIG_HOME", h.join("config"))
            .env("XDG_DATA_HOME", h.join("data"))
            .env("APPDATA", h.join("appdata"))
            .env("LOCALAPPDATA", h.join("localappdata"))
            .timeout(Duration::from_secs(30));
        // Windows needs SystemRoot for process start-up.
        if let Ok(root) = std::env::var("SystemRoot") {
            c.env("SystemRoot", root);
        }
        c
    }

    fn json(&self, args: &[&str]) -> Value {
        let out = self.cmd(args).assert().success().stderr("").get_output().stdout.clone();
        serde_json::from_slice(&out).expect("stdout is one JSON document")
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let left: Vec<_> = std::fs::read_dir(self.home.path()).unwrap().collect();
            assert!(left.is_empty(), "command wrote files into the home dir: {left:?}");
        }
    }
}

#[test]
fn version_json_contract() {
    let v = Env::new().json(&["version", "--json"]);
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    assert!(!v["target"].as_str().unwrap().is_empty());
    let has_cli = v["features"].as_array().unwrap().iter().any(|f| f == "cli");
    assert_eq!(has_cli, cfg!(feature = "cli"), "features must match the build");
    assert_eq!(v["format_version"], 1);
    assert_eq!(v["crypto_suite"], 1);
}

#[test]
fn security_json_reports_self_test_network_and_platform_hardening() {
    let s = Env::new().json(&["security", "--json"]);
    assert_eq!(s["selftest"], "passed");
    assert!(s["network"].as_str().unwrap().starts_with("none"));
    assert_eq!(s["telemetry"], "none");
    assert_eq!(s["suite"]["id"], 1);
    let applied: Vec<&str> = s["hardening_applied"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let required: &[&str] = if cfg!(any(target_os = "linux", target_os = "android")) {
        &["core dumps disabled", "non-dumpable"]
    } else if cfg!(unix) {
        &["core dumps disabled"]
    } else {
        &["SetErrorMode"]
    };
    for r in required {
        assert!(applied.iter().any(|a| a.contains(r)), "missing {r:?} in {applied:?}");
    }
}

#[test]
fn self_hash_matches_the_executable_on_disk() {
    let j = Env::new().json(&["self-hash", "--json"]);
    let bin = assert_cmd::cargo::cargo_bin("passback");
    let want = hex::encode(Sha256::digest(std::fs::read(bin).unwrap()));
    assert_eq!(j["sha256"], want);
}

#[test]
fn bench_kdf_json_contract() {
    let j = Env::new().json(&["bench-kdf", "--memory-mib", "64", "--target-ms", "1", "--json"]);
    assert_eq!(j["m_mib"], 64);
    assert!(j["t"].as_u64().unwrap() >= 2, "never below the minimum iterations");
    assert!(j["p"].as_u64().is_some() && j["measured_ms"].as_u64().is_some());
}

#[test]
fn oversized_kdf_memory_is_rejected_before_any_work_on_stderr() {
    // ~100 GB request. Validation must reject it before Argon2 allocates; the
    // timeout bounds the run if a regression starts the work first.
    Env::new()
        .cmd(&["bench-kdf", "--memory-mib", "100000"])
        .timeout(Duration::from_secs(10))
        .assert()
        .code(1)
        .stdout("")
        .stderr(predicate::str::contains("rejected"));
}

#[test]
fn usage_errors_exit_2() {
    let env = Env::new();
    for args in [&[][..], &["no-such-command"], &["bench-kdf", "--memory-mib", "lots"]] {
        env.cmd(args).assert().code(2).stdout("");
    }
}
