//! Arbitrary bytes as a CRI-O `registries.conf` must never panic, and a file that parses must resolve its own prefixes.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::registries_conf(data));
