//! Arbitrary bytes as containerd's `config.toml`, with its imports, must never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::containerd_config(data));
