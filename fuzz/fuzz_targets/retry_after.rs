//! Reading `Retry-After` must never panic, and whole seconds are the delay they say.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::retry_after(data));
