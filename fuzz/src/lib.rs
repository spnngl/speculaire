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

use std::path::Path;

use speculaire_agent::config;
use speculaire_registry_config::containerd::config::{self as containerd_config_file, Registry};
use speculaire_registry_config::containerd::hosts;
use speculaire_registry_config::crio::{auth, registries};

/// A fuzz entry point.
pub type Entry = fn(&[u8]);

/// Every target by name; `fuzz_targets/<name>.rs` and this list stay in step (checked by the smoke test).
pub const TARGETS: &[(&str, Entry)] = &[
    ("config", config),
    ("config_values", config_values),
    ("containerd_config", containerd_config),
    ("hosts_toml", hosts_toml),
    ("registries_conf", registries_conf),
    ("auth_json", auth_json),
];

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

/// containerd's `config.toml` and the files it imports, as the agent reads them (D17).
///
/// The input is the file; its imports resolve in a temporary directory, or wherever the input points them. Text that
/// loads yields registry settings that validate or are refused, without a panic.
///
/// # Panics
///
/// When loading panics, or the temporary directory cannot be made.
pub fn containerd_config(data: &[u8]) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, data).expect("a writable temporary directory");
    if let Ok(raw) = containerd_config_file::load_raw(&path) {
        let _ = Registry::try_from(raw);
    }
}

/// A CRI-O `registries.conf` or drop-in (D66).
///
/// A file that parses has one registry per prefix, sorted by prefix; every registry that is not a wildcard is the
/// registry of its own prefix, and its pull sources end with its own endpoint.
///
/// # Panics
///
/// When parsing panics, or a parsed file breaks one of those.
pub fn registries_conf(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(file) = registries::parse_file(text) else {
        return;
    };
    assert!(
        file.registries
            .windows(2)
            .all(|pair| pair[0].prefix < pair[1].prefix),
        "registries are sorted and unique by prefix: {text}"
    );
    let config = registries::Config {
        registries: file.registries,
        credential_helpers: Vec::new(),
    };
    for registry in &config.registries {
        if registry.prefix.starts_with("*.") {
            continue;
        }
        assert_eq!(
            config.find_registry(&registry.prefix),
            Some(registry),
            "{text}"
        );
        if let Ok(sources) = registry.pull_sources(&format!("{}/app:1", registry.prefix)) {
            assert_eq!(
                sources.last().map(|source| &source.endpoint),
                Some(&registry.endpoint),
                "{text}"
            );
        }
    }
}

/// A credential file of CRI-O's image library (D66), in either format.
///
/// # Panics
///
/// When parsing panics.
pub fn auth_json(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    for legacy in [false, true] {
        let _ = auth::parse_auth_file(&text, legacy);
    }
}

/// A containerd `hosts.toml` (D17).
///
/// A file that parses lists its hosts and ends with its own `server`.
///
/// # Panics
///
/// When parsing panics, or a parsed file lists no host.
pub fn hosts_toml(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let dir = Path::new("/etc/containerd/certs.d/docker.io");
    if let Ok(parsed) = hosts::parse_hosts_file(dir, text) {
        assert!(
            !parsed.is_empty(),
            "a parsed file ends with its own `server`: {text}"
        );
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
