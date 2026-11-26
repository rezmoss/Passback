//! A fuzzed sealed box must never open under the fixed key.
#![no_main]

use libfuzzer_sys::fuzz_target;
use passback_testkit::{Surface, exercise};

fuzz_target!(|data: &[u8]| exercise(Surface::SealedOpen, data));
