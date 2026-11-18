//! Arbitrary bytes as a pinned `trusted_root.json` must never panic, and bytes that parse must parse the same again.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::trusted_root(data));
