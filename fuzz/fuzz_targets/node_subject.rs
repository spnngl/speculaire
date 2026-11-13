//! Arbitrary bytes as a peer certificate must never panic, and a node it names must be its common name's.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::node_subject(data));
