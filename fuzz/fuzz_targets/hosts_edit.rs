//! Arbitrary bytes as a hosts.toml that configure edits must never panic, and an edited file must edit to itself.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::hosts_edit(data));
