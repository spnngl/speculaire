//! Config files written from the config's own keys, for `config_values`.
//!
//! Raw bytes rarely spell a value the value parsers accept, such as a pinned trusted root or a reflector URL, so what
//! the `config` target finds stops at the parse's first refusal. Here each key has the literals that reach its
//! parser, those it accepts and those it refuses, and a draw picks a few keys with a literal or a string of raw bytes
//! for each. It lives in `fuzz/`, so `speculaire-agent` takes no `arbitrary` dependency.

use libfuzzer_sys::arbitrary::{Result, Unstructured};

/// Durations, as `humantime` reads them; the zero and the overflow are the refusals.
const SPANS: &[&str] = &[
    r#""10s""#,
    r#""300ms""#,
    r#""1h30m""#,
    r#""1ms""#,
    r#""0s""#,
    r#""-1s""#,
    r#""10""#,
    r#""1x""#,
    r#""18446744073709551615s""#,
    "10",
];

/// Sizes, as `ByteSize` reads them.
const SIZES: &[&str] = &[
    r#""64MiB""#,
    r#""20GiB""#,
    r#""1B""#,
    r#""0B""#,
    r#""1TiB""#,
    r#""18446744073709551615B""#,
    r#""17179869184GiB""#,
    r#""1.5GiB""#,
    r#""64mib""#,
    r#""64""#,
    r#""""#,
];

/// Absolute paths, and what is not one.
const PATHS: &[&str] = &[
    r#""/etc/speculaire/policy.yaml""#,
    r#""/""#,
    r#""/a/../b""#,
    r#""/ünï""#,
    r#""relative/path""#,
    r#""""#,
    "1",
];

/// Socket addresses.
const ADDRESSES: &[&str] = &[
    r#""[::]:7482""#,
    r#""0.0.0.0:7482""#,
    r#""127.0.0.1:0""#,
    r#""[::1]:7482""#,
    r#""10.0.0.1:65535""#,
    r#""10.0.0.1:65536""#,
    r#""10.0.0.1""#,
    r#""localhost:7482""#,
    r#""""#,
];

/// Loopback addresses: the ones in `ADDRESSES` that are not loopback are the refusals.
const LOOPBACKS: &[&str] = &[
    r#""127.0.0.1:7480""#,
    r#""[::1]:7480""#,
    r#""127.255.255.255:1""#,
    r#""0.0.0.0:7480""#,
    r#""[::]:7480""#,
    r#""10.0.0.1:7480""#,
    r#""localhost:7480""#,
    r#""127.0.0.1""#,
];

/// Lists of strings.
const STRINGS: &[&str] = &[
    "[]",
    r#"["kube-system"]"#,
    r#"["registry.k8s.io/*", "docker.io/library/*"]"#,
    r#"["a", "a"]"#,
    r#"["["]"#,
    r#"[""]"#,
    "[1]",
    r#""kube-system""#,
];

/// Every key with the literals worth drawing for it: valid ones first, then those the key refuses.
pub(crate) const KEYS: &[(&str, &[&str])] = &[
    (
        "role",
        &[r#""agent""#, r#""reflector""#, r#""relay""#, r#""""#, "1"],
    ),
    ("config.poll_interval", SPANS),
    ("identity.certificate", PATHS),
    ("identity.ca", PATHS),
    (
        "gate.mode",
        &[r#""audit""#, r#""enforce""#, r#""block""#, r#""Audit""#],
    ),
    ("gate.wait", SPANS),
    ("gate.unmatched", &[r#""deny""#, r#""allow""#, r#""skip""#]),
    ("gate.exempt.namespaces", STRINGS),
    ("gate.exempt.images", STRINGS),
    ("nri.socket", PATHS),
    ("verify.policy", PATHS),
    (
        "verify.trusted_root",
        &[
            r#""""#,
            r#""/etc/speculaire/trusted_root.json""#,
            r#""trusted_root.json""#,
            "true",
        ],
    ),
    ("verify.stale_max", SPANS),
    ("sbom.max_size", SIZES),
    ("mirror.address", LOOPBACKS),
    ("mirror.directory", PATHS),
    (
        "mirror.registries",
        &[
            r#"["docker.io", "registry.k8s.io"]"#,
            "[]",
            r#"["localhost:5000", "[::1]:5000"]"#,
            r#"["https://docker.io"]"#,
            r#"["docker.io/library"]"#,
            r#"["*.example.com"]"#,
            r#"[""]"#,
            r#""docker.io""#,
            "[1]",
        ],
    ),
    (
        "peer.address",
        &[
            r#""auto""#,
            r#""10.0.0.1:7481""#,
            r#""[fe80::1]:7481""#,
            r#""10.0.0.1""#,
            r#""AUTO""#,
            r#""""#,
        ],
    ),
    (
        "peer.max_uploads",
        &[
            r#""auto""#,
            "8",
            "1",
            "4294967295",
            "4294967296",
            "0",
            "-1",
            r#""8""#,
            "1.5",
            r#""many""#,
        ],
    ),
    ("peer.stall_timeout", SPANS),
    ("peer.deny_ttl", SPANS),
    ("blob_cache.max_size", SIZES),
    ("metrics.address", ADDRESSES),
    (
        "reflector.url",
        &[
            r#""""#,
            r#""https://reflector.example:7483""#,
            r#""https://10.0.0.1""#,
            r#""https://[::1]:7483""#,
            r#""http://reflector.example""#,
            r#""https://reflector.example/path""#,
            r#""https://user@reflector.example""#,
            r#""reflector.example""#,
            r#""https://""#,
        ],
    ),
    (
        "reflector.members",
        &[
            "[]",
            r#"[{ node = "cp-1", address = "10.0.0.1:7483" }]"#,
            r#"[{ node = "cp-1", address = "10.0.0.1:7483" }, { node = "cp-2", address = "[::1]:7483" }]"#,
            r#"[{ node = "a.b-c.d0", address = "10.0.0.1:7483" }]"#,
            r#"[{ node = "CP_1", address = "10.0.0.1:7483" }]"#,
            r#"[{ node = "cp-1" }]"#,
            r#"[{ node = "cp-1", address = "10.0.0.1:7483", extra = 1 }]"#,
            r#"[{ node = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", address = "10.0.0.1:7483" }]"#,
        ],
    ),
    ("reflector.listen", ADDRESSES),
    (
        "prewarm.images",
        &[
            "[]",
            r#"["registry.k8s.io/pause:3.10"]"#,
            r#"["registry.k8s.io/pause@sha256:00"]"#,
            r#"[""]"#,
            "[1]",
        ],
    ),
    (
        "prewarm.seeds",
        &[
            "2",
            "1",
            "10",
            "4294967295",
            "4294967296",
            "0",
            "-1",
            r#""2""#,
        ],
    ),
    (
        "log.filter",
        &[
            r#""warn""#,
            r#""info,speculaire=debug""#,
            r#""off""#,
            r#""speculaire_agent::serve=trace""#,
            r#""info,[""#,
            r#""==""#,
            r#""""#,
        ],
    ),
    ("audit.enabled", &["false", "true", r#""true""#, "1"]),
    ("shutdown.drain_timeout", SPANS),
];

/// A string of raw bytes as a TOML basic string: any text, whatever its characters.
fn quoted(raw: &str) -> String {
    let body: String = raw
        .chars()
        .map(|c| match c {
            '"' => "\\\"".to_owned(),
            '\\' => "\\\\".to_owned(),
            c if c.is_control() => format!("\\u{:04X}", u32::from(c)),
            c => c.to_string(),
        })
        .collect();
    format!("\"{body}\"")
}

/// A config file of about four keys, each with a literal of its own list or a string of raw bytes.
///
/// A key shows up at most once, as a dotted key of the root table: TOML refuses repeats.
///
/// # Errors
///
/// When `data` cannot give the bytes of a string.
pub(crate) fn document(data: &[u8]) -> Result<String> {
    let mut u = Unstructured::new(data);
    let mut text = String::new();
    for (key, literals) in KEYS {
        if !u.ratio(1, 8)? {
            continue;
        }
        // One past the list: a string of raw bytes.
        let value = match literals.get(u.int_in_range(0..=literals.len())?) {
            Some(literal) => (*literal).to_owned(),
            None => quoted(u.arbitrary()?),
        };
        text.extend([*key, " = ", &value, "\n"]);
    }
    Ok(text)
}
