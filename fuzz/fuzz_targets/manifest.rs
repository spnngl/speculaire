//! A manifest the relay reads must never panic, and every digest in it prints as it parses.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::manifest(data));
