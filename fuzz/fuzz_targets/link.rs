//! The next link of a `Link` header must never panic, and lies in the header between its `<` and `>`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::link(data));
