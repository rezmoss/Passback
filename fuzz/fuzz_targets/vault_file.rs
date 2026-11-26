//! Mutated vault files must be rejected without panicking.
#![no_main]

use libfuzzer_sys::fuzz_target;
use passback_testkit::{Surface, exercise};

fuzz_target!(|data: &[u8]| exercise(Surface::VaultFile, data));
