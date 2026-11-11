//! Fuzz entry points: one function per parser of outside data, each fed arbitrary bytes and required never to panic.
//!
//! `cargo-fuzz` (nightly) reaches them through the shims in `fuzz_targets/`; `cargo test --lib` (stable,
//! `just fuzz-smoke`) replays the seeds plus mutated variants through [`TARGETS`].

#![forbid(unsafe_code)]
#![expect(
    clippy::panic,
    reason = "a fuzz target, and the smoke test replaying it, report a bug by panicking"
)]

#[cfg(test)]
mod smoke;

use speculaire_agent::config;

/// A fuzz entry point.
pub type Entry = fn(&[u8]);

/// Every target by name; `fuzz_targets/<name>.rs` and this list stay in step (checked by the smoke test).
pub const TARGETS: &[(&str, Entry)] = &[("config", config)];

/// The agent's config file, as `check-config` and the agent read it (D30, D60).
///
/// Text that parses serializes to TOML that parses back to the same config: every value prints as it parses.
///
/// # Panics
///
/// When parsing panics, or a parsed config does not survive the round trip.
pub fn config(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(parsed) = config::parse(text) else {
        return;
    };
    let printed = toml::to_string(&parsed)
        .unwrap_or_else(|err| panic!("a parsed config serializes: {err}\n{text}"));
    match config::parse(&printed) {
        Ok(again) => assert_eq!(again, parsed, "round trip through\n{printed}"),
        Err(err) => panic!("a serialized config parses: {err}\n{printed}"),
    }
}
