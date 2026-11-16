//! A referrers index, a referrer and an image index discovery reads must never panic, and every digest in them prints as it parses.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::referrers(data));
