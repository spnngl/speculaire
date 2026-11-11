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
mod values;

use speculaire_agent::config;

/// A fuzz entry point.
pub type Entry = fn(&[u8]);

/// Every target by name; `fuzz_targets/<name>.rs` and this list stay in step (checked by the smoke test).
pub const TARGETS: &[(&str, Entry)] = &[("config", config), ("config_values", config_values)];

/// The agent's config file, as `check-config` and the agent read it (D30, D60).
///
/// Text that parses serializes to TOML that parses back to the same config: every value prints as it parses.
///
/// # Panics
///
/// When parsing panics, or a parsed config does not survive the round trip.
pub fn config(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        round_trip(text);
    }
}

/// The agent's config file, written from its keys: a few of them, each with a literal that its parser accepts or
/// refuses, or a string of raw bytes. `config` reaches the values that raw bytes seldom spell (D75).
///
/// # Panics
///
/// As [`config`].
pub fn config_values(data: &[u8]) {
    if let Ok(text) = values::document(data) {
        round_trip(&text);
    }
}

/// Parses `text`, and a config that parses must print to text that parses back to it.
fn round_trip(text: &str) {
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
