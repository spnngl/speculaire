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
use speculaire_oci::platform::{self as oci_platform, Host, Matcher};
use speculaire_oci::reference::Reference;
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
    ("hosts_edit", hosts_edit),
    ("registries_conf", registries_conf),
    ("auth_json", auth_json),
    ("crio_inspect", crio_inspect),
    ("runtime_version", runtime_version),
    ("mirror_request", mirror_request),
    ("reference", reference),
    ("platform", platform),
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
    let _ = containerd_config_file::load_plugins(&path);
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

/// An image reference as the CRI plugin parses it (D11, D81).
///
/// A reference that parses prints as text that parses to the same reference, and never has a tag together with a
/// digest.
///
/// # Panics
///
/// When parsing panics, or a parsed reference is not a fixed point.
pub fn reference(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(parsed) = Reference::parse_docker_ref(text) {
        assert!(
            parsed.tag().is_none() || parsed.digest().is_none(),
            "a docker reference keeps one of tag and digest: {text}"
        );
        assert_eq!(
            Reference::parse_docker_ref(&parsed.to_string()).as_ref(),
            Ok(&parsed),
            "{text}"
        );
    }
}

/// A platform specifier as containerd parses it (D15, D81).
///
/// A platform that parses normalizes to itself, and matches itself.
///
/// # Panics
///
/// When parsing or matching panics, or a parsed platform breaks one of those.
pub fn platform(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let host = Host::current();
    let Ok(parsed) = oci_platform::parse(text, &host) else {
        return;
    };
    let normal = oci_platform::normalize(&parsed, &host);
    assert_eq!(oci_platform::normalize(&normal, &host), normal, "{text}");
    // A variant that counts to a million makes `Only` list a million platforms, as it does in Go.
    let huge = parsed
        .variant()
        .as_deref()
        .is_some_and(|variant| variant.trim_start_matches('v').len() > 3);
    if !huge && let Ok(strict) = Matcher::only_strict(&parsed, &host) {
        assert!(strict.matches(&parsed), "{text}");
    }
}

/// What CRI-O's inspect API answers to `GET /config`, as the agent reads it (D64).
///
/// A response that parses has a body, and the settings read from it are those of the body alone.
///
/// # Panics
///
/// When parsing panics, or the settings of a response differ from those of its body.
pub fn crio_inspect(data: &[u8]) {
    let Ok(body) = speculaire_runtime::crio::body(data) else {
        assert!(speculaire_runtime::crio::Nri::from_response(data).is_err());
        return;
    };
    assert_eq!(
        speculaire_runtime::crio::Nri::from_response(data).ok(),
        speculaire_runtime::crio::Nri::parse(body).ok()
    );
}

/// A containerd `hosts.toml` as `configure` edits it (D32, D82).
///
/// Editing never panics. A file that gets the mirror's entry gets it once: editing the result changes nothing, taking
/// the entry out leaves a file that still parses, and containerd reads the mirror first.
///
/// # Panics
///
/// When editing panics, or a result breaks one of those.
pub fn hosts_edit(data: &[u8]) {
    use speculaire_configure::containerd::{Entry, add, remove};
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let dir = std::path::Path::new("/var/lib/speculaire/mirror");
    let entry = Entry {
        url: "https://127.0.0.1:7480".to_owned(),
        ca: dir.join("ca.crt"),
        client: dir.join("client.pem"),
    };
    let _ = remove(text, dir);
    let Ok(added) = add(text, &entry, dir) else {
        return;
    };
    assert_eq!(
        add(&added, &entry, dir).ok().as_deref(),
        Some(added.as_str())
    );
    assert!(remove(&added, dir).is_ok());
    let base = std::path::Path::new("/certs.d/x");
    if hosts::parse_hosts_file(base, text).is_ok() {
        let hosts = hosts::parse_hosts_file(base, &added)
            .unwrap_or_else(|e| panic!("an edited hosts.toml parses: {e:?}\n{text:?}\n{added:?}"));
        assert_eq!(hosts[0].host, "127.0.0.1:7480");
    }
}

/// A request of the runtime to the mirror: its path, then a line with its `Range` header (D85).
///
/// Routing never panics. A range lies inside a body of any size: it starts at or before its end, and its end is the
/// body's last byte at most; the whole of an empty body has no range.
///
/// # Panics
///
/// When routing or reading a range panics, or a range does not lie in the body.
pub fn mirror_request(data: &[u8]) {
    use speculaire_mirror::request::{Method, Ranged, Span, range, route};
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (path, header) = text.split_once('\n').unwrap_or((text, ""));
    for method in [Method::GET, Method::HEAD] {
        let _ = route(&method, path);
    }
    for size in [0, 1, 2, 1000, u64::MAX] {
        if let Ranged::Part(span) = range(Some(header), size) {
            assert!(
                span.first <= span.last && span.last < size,
                "{header:?} of {size}"
            );
            assert_eq!(span.bytes(), span.last - span.first + 1);
        }
    }
    assert_eq!(Span::whole(0), None);
}

/// The version a runtime reports about itself over the CRI (D86).
///
/// Reading never panics. A text that is a release prints as `major.minor.patch`, which parses back to the same release,
/// and the numbers are those of the text's first three dotted fields.
///
/// # Panics
///
/// When parsing panics, or a release does not survive printing.
pub fn runtime_version(data: &[u8]) {
    use speculaire_runtime::version::Release;
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(release) = Release::parse(text) {
        assert_eq!(Release::parse(&release.to_string()), Some(release));
        let numbers = text.strip_prefix('v').unwrap_or(text);
        assert!(
            numbers.starts_with(|c: char| c.is_ascii_digit()),
            "{text:?}"
        );
    }
}
