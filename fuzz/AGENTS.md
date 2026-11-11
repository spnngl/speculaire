# fuzz

libFuzzer targets, in their own workspace; `src/lib.rs` says how they run. A new target is a function of `src/lib.rs`
named after what it parses and listed in its `TARGETS`, with a one-line shim in `fuzz_targets/`, a `[[bin]]` in
`Cargo.toml` and seeds in `seeds/<target>/`. `just fuzz <target> <seconds>` runs it on the pinned nightly; `just
fuzz-seeds` derives the config target's extra seed and dictionary from `packaging/config.toml`.
