//! Arbitrary bytes as an event of containerd must never panic, and only content of `k8s.io` is a change.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::containerd_event(data));
