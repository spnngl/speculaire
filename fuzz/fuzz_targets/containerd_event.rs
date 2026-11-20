//! Arbitrary bytes as an event of containerd must never panic, only content of `k8s.io` is a change, and only
//! images of `k8s.io` are image events.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::containerd_event(data));
