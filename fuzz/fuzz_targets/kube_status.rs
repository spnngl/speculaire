//! What the Kubernetes API server answers the uninstall hook's wait must never panic when read and weighed.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::kube_status(data));
