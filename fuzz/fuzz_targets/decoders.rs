//! Every decoder of untrusted bytes must reject bad input without panicking,
//! hanging or allocating without bound. The first byte selects the decoder; the
//! dispatch is shared with the stable robustness test in `passback-testkit`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use passback_testkit::{Surface, exercise};

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else { return };
    exercise(Surface::from_byte(sel), rest);
});
