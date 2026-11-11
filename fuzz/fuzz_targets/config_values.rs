//! Config files written from the config's keys, with literals that each value parser accepts or refuses, must never
//! panic, and a parsed config must survive a round trip.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::config_values(data));
