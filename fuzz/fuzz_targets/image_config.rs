//! Arbitrary bytes as an image config must never panic, and a chain ID read prints as it parses.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::image_config(data));
