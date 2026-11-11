//! Arbitrary bytes as the agent's config file must never panic, and a parsed config must survive a round trip.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::config(data));
