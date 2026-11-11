//! Arbitrary bytes as a containerd `hosts.toml` must never panic, and hosts that parse must be consistent.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::hosts_toml(data));
