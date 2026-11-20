//! Arbitrary bytes as `cache.bin` must never panic, and what loads saves bytes that load and save the same.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::cache_bin(data));
