//! The registry config parsers against containerd's own code (D29, D70): the same cases go to `speculaire-oracle` and
//! to the Rust port, and the answers must be the same.
//!
//! The cases of CRI-O's config are in `oracle/crio.rs`.
//!
//! The cases are containerd's test cases (`hosts_test.go`, `config_test.go` at v2.4.2), the config of the e2e node
//! images, and the seeds of the fuzz targets. Without `SPECULAIRE_ORACLE` the tests skip, as in `just check`; `just
//! oracle` sets it, and then a missing binary fails them.

#![expect(
    clippy::panic,
    clippy::too_many_lines,
    reason = "a test file: its helpers report by panicking, and its case lists are long"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use secrecy::ExposeSecret;
use serde::Serialize;
use serde_json::{Value, json};
use speculaire_oracle_harness::Oracle;
use speculaire_registry_config::Headers;
use speculaire_registry_config::containerd::config::{self, Auth, RawRegistry};
use speculaire_registry_config::containerd::hosts::{self, HostConfig, RegistryHost};

/// A self-signed certificate and its key: files that Go's TLS code loads.
const CA: &str = include_str!("data/test-ca.pem");
const KEY: &str = include_str!("data/test-key.pem");

#[path = "oracle/crio.rs"]
mod crio;

fn oracle() -> Option<Oracle> {
    match Oracle::from_env() {
        Ok(Some(oracle)) => Some(oracle),
        Ok(None) => {
            eprintln!(
                "skipped: {} is not set (`just oracle` sets it)",
                speculaire_oracle_harness::ENV
            );
            None
        }
        Err(e) => panic!("{e}"),
    }
}

/// Error messages differ between Go and Rust: only whether there is one is compared.
fn normalise(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map.iter_mut() {
                if key == "error" {
                    *inner = Value::Bool(true);
                } else {
                    normalise(inner);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(normalise),
        _ => {}
    }
}

/// Where two answers first differ: the path, and both values.
fn first_difference(ours: &Value, theirs: &Value, path: &str) -> String {
    match (ours, theirs) {
        (Value::Object(a), Value::Object(b)) => {
            for key in a.keys().chain(b.keys()) {
                let (x, y) = (
                    a.get(key).unwrap_or(&Value::Null),
                    b.get(key).unwrap_or(&Value::Null),
                );
                if x != y {
                    return first_difference(x, y, &format!("{path}.{key}"));
                }
            }
            format!("{path}: objects differ")
        }
        (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
            for (n, (x, y)) in a.iter().zip(b).enumerate() {
                if x != y {
                    return first_difference(x, y, &format!("{path}[{n}]"));
                }
            }
            format!("{path}: arrays differ")
        }
        _ => format!("{path}: rust {ours}, oracle {theirs}"),
    }
}

fn expect_same(subcommand: &str, labelled: &[(String, Value, Value)]) {
    let mut failures = Vec::new();
    let mut compared = 0;
    for (label, ours, theirs) in labelled {
        if theirs.get("unstable").is_some() {
            continue;
        }
        compared += 1;
        let (mut ours, mut theirs) = (ours.clone(), theirs.clone());
        normalise(&mut ours);
        normalise(&mut theirs);
        if ours != theirs {
            failures.push(format!(
                "{label}\n  {}",
                first_difference(&ours, &theirs, "")
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} {subcommand} cases differ from the oracle:\n{}",
        failures.len(),
        compared,
        failures
            .iter()
            .take(12)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    eprintln!(
        "oracle: {compared} of {} {subcommand} cases agree with the oracle, the rest has no stable answer",
        labelled.len()
    );
}

fn headers(h: &Headers) -> Value {
    h.iter()
        .map(|(name, values)| {
            let values: Vec<&str> = values.iter().map(ExposeSecret::expose_secret).collect();
            (name.clone(), json!(values))
        })
        .collect::<serde_json::Map<_, _>>()
        .into()
}

fn parsed<E>(result: Result<Vec<HostConfig>, E>) -> Value {
    match result {
        Err(_) => json!({"ok": [], "error": true}),
        Ok(hosts) => {
            let ok: Vec<Value> = hosts
                .iter()
                .map(|h| {
                    json!({
                        "scheme": h.scheme,
                        "host": h.host,
                        "path": h.path,
                        "capabilities": h.capabilities.names(),
                        "ca": h.ca().iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>(),
                        "client": h.client().iter().map(|c| json!([
                            c.cert.to_string_lossy(),
                            c.key.as_ref().map_or_else(String::new, |k| k.to_string_lossy().into_owned()),
                        ])).collect::<Vec<_>>(),
                        "skip_verify": h.skip_verify,
                        "dial_timeout_ns": h.dial_timeout.map(|d| d.as_nanos()),
                        "header": headers(&h.header),
                    })
                })
                .collect();
            json!({ "ok": ok })
        }
    }
}

fn resolved<E>(result: Result<Vec<RegistryHost>, E>) -> Value {
    match result {
        Err(_) => json!({"ok": [], "error": true}),
        Ok(hosts) => {
            let ok: Vec<Value> = hosts
                .iter()
                .map(|h| {
                    json!({
                        "scheme": h.scheme,
                        "host": h.host,
                        "path": h.path,
                        "capabilities": h.capabilities.names(),
                        "header": headers(&h.header),
                        "fallback": h.http_fallback,
                        "skip_verify": h.tls.skip_verify.unwrap_or(false),
                    })
                })
                .collect();
            json!({ "ok": ok })
        }
    }
}

// ---- hosts ----

#[derive(Serialize, Clone)]
struct HostsCase {
    root: PathBuf,
    files: BTreeMap<String, String>,
    host: String,
    default_scheme: String,
}

fn hosts_case(root: &Path, host: &str, default_scheme: &str, files: &[(&str, &str)]) -> HostsCase {
    HostsCase {
        root: root.to_owned(),
        files: files
            .iter()
            .map(|(name, content)| ((*name).to_owned(), (*content).to_owned()))
            .collect(),
        host: host.to_owned(),
        default_scheme: default_scheme.to_owned(),
    }
}

/// What the Rust port says about a case; the oracle has laid its files out under `root` by now.
fn our_hosts(case: &HostsCase) -> Value {
    let roots = [case.root.clone()];
    let dir = hosts::host_dir(&roots, &case.host).expect("host_dir");
    let mut answer = json!({
        "dir": dir.as_ref().map_or_else(String::new, |d| d.to_string_lossy().into_owned()),
        "parsed": null,
        "loaded": null,
    });
    if let Some(dir) = &dir {
        // `parsed` is the file's own parse: containerd reports it only when there is a file to parse.
        if let Some(text) = std::fs::read(dir.join("hosts.toml"))
            .ok()
            .filter(|t| !t.is_empty())
        {
            let text = String::from_utf8_lossy(&text).into_owned();
            answer["parsed"] = parsed(hosts::parse_hosts_file(dir, &text));
        }
        answer["loaded"] = parsed(hosts::load_host_dir(dir));
    }
    answer["resolved"] = resolved(hosts::resolve(
        &roots,
        &case.host,
        Some(&case.default_scheme)
            .filter(|s| !s.is_empty())
            .map(String::as_str),
    ));
    answer
}

fn hosts_cases(root: &Path) -> Vec<(String, HostsCase)> {
    let mut cases: Vec<(String, HostsCase)> = Vec::new();
    let mut add = |label: &str, host: &str, scheme: &str, files: &[(&str, &str)]| {
        // One directory per case: files of one must not be seen by another.
        let root = root.join(format!("case-{}", cases.len()));
        cases.push((label.to_owned(), hosts_case(&root, host, scheme, files)));
    };

    // The defaults of `ConfigureHosts` for a host with no config.
    for host in [
        "docker.io",
        "ghcr.io",
        "registry.example.com:5000",
        "localhost",
        "localhost:80",
        "localhost:443",
        "localhost:5000",
        "127.0.0.1:5000",
        "127.0.0.1",
        "[::1]:5000",
        "::1",
        "[::1]",
        "10.0.0.1:5000",
        "LOCALHOST:5000",
        "[::ffff:127.0.0.1]:8080",
    ] {
        for scheme in ["", "http", "https"] {
            add(&format!("default {host} {scheme}"), host, scheme, &[]);
        }
    }

    // `TestParseHostFile`, with the paths made relative where the files must exist for Go to load them.
    let parse_host_file = r#"
server = "https://test-default.registry"
ca = "/etc/path/default"
[header]
  x-custom-1 = "custom header"

[host."https://mirror.registry"]
  capabilities = ["pull"]
  ca = "/etc/certs/mirror.pem"
  skip_verify = false
  [host."https://mirror.registry".header]
    x-custom-2 = ["value1", "value2"]

[host."https://mirror-bak.registry/us"]
  capabilities = ["pull"]
  skip_verify = true

[host."http://mirror.registry"]
  capabilities = ["pull"]

[host."https://test-1.registry"]
  capabilities = ["pull", "resolve", "push", "referrers"]
  ca = ["/etc/certs/test-1-ca.pem", "/etc/certs/special.pem"]
  client = [["/etc/certs/client.cert", "/etc/certs/client.key"],["/etc/certs/client.pem", ""]]

[host."https://test-2.registry"]
  client = "/etc/certs/client.pem"

[host."https://test-3.registry"]
  client = ["/etc/certs/client-1.pem", "/etc/certs/client-2.pem"]

[host."https://no-referrers.registry"]
  capabilities = ["pull", "resolve", "push"]
  client = ["/etc/certs/client-1.pem", "/etc/certs/client-2.pem"]

[host."https://noncompliantmirror.registry/v2/namespaceprefix"]
  capabilities = ["pull"]
  override_path = true

[host."https://noprefixnoncompliant.registry"]
  override_path = true

[host."https://onlyheader.registry".header]
  x-custom-1 = "justaheader"

[host."https://dial-timeout.registry"]
  dial_timeout = "3s"
"#;
    add(
        "TestParseHostFile",
        "docker.io",
        "",
        &[("docker.io/hosts.toml", parse_host_file)],
    );
    // The same, with the TLS files in place, so that Go can resolve it too.
    let with_files = parse_host_file
        .replace("/etc/certs/", "")
        .replace("/etc/path/default", "ca.crt")
        .replace("\"mirror.pem\"", "\"ca.crt\"")
        .replace(
            "\"test-1-ca.pem\", \"special.pem\"",
            "\"ca.crt\", \"ca2.crt\"",
        )
        .replace("\"client.pem\", \"\"", "\"pair.pem\", \"\"");
    let pair = format!("{CA}{KEY}");
    add(
        "TestParseHostFile with files",
        "docker.io",
        "",
        &[
            ("docker.io/hosts.toml", &with_files),
            ("docker.io/ca.crt", CA),
            ("docker.io/ca2.crt", CA),
            ("docker.io/client.cert", CA),
            ("docker.io/client.key", KEY),
            ("docker.io/pair.pem", &pair),
            ("docker.io/client.pem", &pair),
            ("docker.io/client-1.pem", &pair),
            ("docker.io/client-2.pem", &pair),
        ],
    );

    // `TestLoadCertFiles`: the certificate files of Docker's layout.
    add(
        "certs crt only",
        "testing.io",
        "",
        &[("testing.io/ca.crt", CA)],
    );
    add(
        "certs crt and pair",
        "testing.io",
        "",
        &[
            ("testing.io/ca.crt", CA),
            ("testing.io/client.cert", CA),
            ("testing.io/client.key", KEY),
        ],
    );
    add(
        "certs pair only",
        "testing.io",
        "",
        &[
            ("testing.io/client.cert", &pair),
            ("testing.io/client.key", KEY),
        ],
    );
    add(
        "certs cert without key",
        "testing.io",
        "",
        &[("testing.io/client.cert", &pair)],
    );
    add(
        "certs directory only",
        "testing.io",
        "",
        &[("testing.io/other.txt", "x")],
    );
    add(
        "hosts.toml empty falls back to certs",
        "testing.io",
        "",
        &[("testing.io/hosts.toml", ""), ("testing.io/ca.crt", CA)],
    );
    add(
        "hosts.toml broken falls back to certs",
        "testing.io",
        "",
        &[
            ("testing.io/hosts.toml", "server = ["),
            ("testing.io/ca.crt", CA),
        ],
    );
    add(
        "hosts.toml with the wrong type falls back to certs",
        "testing.io",
        "",
        &[
            ("testing.io/hosts.toml", "capabilities = \"pull\"\n"),
            ("testing.io/ca.crt", CA),
        ],
    );

    // Where the directory of a host is.
    add(
        "port directory",
        "localhost:5000",
        "",
        &[("localhost_5000_/hosts.toml", "server = \"https://a.b\"\n")],
    );
    add(
        "port directory wins",
        "localhost:5000",
        "",
        &[
            ("localhost_5000_/hosts.toml", "server = \"https://a.b\"\n"),
            ("localhost:5000/hosts.toml", "server = \"https://c.d\"\n"),
        ],
    );
    add(
        "colon directory",
        "localhost:5000",
        "",
        &[("localhost:5000/hosts.toml", "server = \"https://c.d\"\n")],
    );
    add(
        "_default",
        "ghcr.io",
        "",
        &[("_default/hosts.toml", "[host.\"https://m.io\"]\n")],
    );
    add(
        "_default is the last choice",
        "ghcr.io",
        "",
        &[
            ("_default/hosts.toml", "server = \"https://d.io\"\n"),
            ("ghcr.io/hosts.toml", "server = \"https://g.io\"\n"),
        ],
    );

    // Servers, paths, schemes.
    for (n, server) in [
        "mirror.io:5000",
        "mirror.io:5000/prefix",
        "http://m.io",
        "https://m.io/",
        "https://m.io/a/b/",
        "https://m.io/a/../b",
        "https://m.io/v2",
        "https://m.io/v2/",
        "https://m.io/x/v2/y",
        "httpbin.org/x",
        "http",
        "https:foo",
        "HTTPS://M.IO",
        "https://user:pw@m.io/p",
        "https://m.io:99999/p",
        "https://m.io:abc",
        "https://[::1]:5000/x",
        "https://[::1",
        "https://m.io/a%2Fb",
        "https://m.io/%zz",
        "https://m.io/a b",
        "https://m io",
        "https://m.io?x=y",
        "https://m.io/p?x=y#frag",
        "https://m.io/p#%zz",
        "https://m.io//double//slash",
        "https://%41.io",
        "https://m.io/\u{e9}",
        "https://\u{e9}.io",
        "https:///path",
        "",
        "http://",
        "https://m.io/..",
        "https://m.io/./.",
        "ftp://m.io",
        "//m.io",
        "https://m.io\u{7f}",
        "https://[fe80::1%25eth0]:5000/",
        "https://[fe80::1%25%65th0]/",
    ]
    .iter()
    .enumerate()
    {
        let toml = format!("server = {}\n", Value::String((*server).to_owned()));
        add(
            &format!("server {n}: {server:?}"),
            "docker.io",
            "",
            &[("docker.io/hosts.toml", &toml)],
        );
        let toml = format!(
            "[host.{}]\ncapabilities = [\"pull\"]\n",
            Value::String((*server).to_owned())
        );
        add(
            &format!("host {n}: {server:?}"),
            "docker.io",
            "",
            &[("docker.io/hosts.toml", &toml)],
        );
        let toml = format!(
            "server = {}\noverride_path = true\n",
            Value::String((*server).to_owned())
        );
        add(
            &format!("override_path {n}: {server:?}"),
            "docker.io",
            "",
            &[("docker.io/hosts.toml", &toml)],
        );
    }

    // The order of the hosts, and what is not listed.
    add(
        "order: tables",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "[host.\"https://b.io\"]\n[host.\"https://a.io\"]\n[host.\"https://c.io\"]\n",
        )],
    );
    add(
        "order: a host again after another",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "[host.\"https://a.io\"]\ncapabilities=[\"pull\"]\n[host.\"https://b.io\"]\n[host.\"https://a.io\".header]\nx=\"1\"\n",
        )],
    );
    add(
        "order: header table first",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "[host.\"https://a.io\".header]\nx=\"1\"\n[host.\"https://a.io\"]\ncapabilities=[\"pull\"]\n",
        )],
    );
    add(
        "order: dotted keys are not listed",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "host.\"https://a.io\".capabilities = [\"pull\"]\n[host.\"https://b.io\"]\n",
        )],
    );
    add(
        "order: inline table is not listed",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "host = { \"https://a.io\" = { capabilities = [\"pull\"] } }\n",
        )],
    );
    add(
        "order: array of tables is not listed",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "[[host.\"https://a.io\"]]\ncapabilities=[\"pull\"]\n",
        )],
    );
    add(
        "order: empty name is skipped",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "[host.\"\"]\ncapabilities=[\"pull\"]\n[host.\"https://a.io\"]\n",
        )],
    );
    add(
        "order: sub-table of host table",
        "docker.io",
        "",
        &[("docker.io/hosts.toml", "[host]\n[host.\"https://a.io\"]\n")],
    );
    add(
        "order: bare host names",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "[host.mirror]\n[host.mirror.header]\nx=\"1\"\n[host.other]\n",
        )],
    );
    add(
        "order: host header string",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "[host.\"a.io\".header]\nx=[\"1\",\"2\"]\n",
        )],
    );
    add(
        "order: root table later",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "[host.\"a.io\"]\n[header]\nx=\"1\"\n",
        )],
    );
    add(
        "order: server after hosts",
        "docker.io",
        "",
        &[("docker.io/hosts.toml", "[host.\"a.io\"]\n")],
    );
    add(
        "order: no server, only root keys",
        "ghcr.io",
        "",
        &[(
            "ghcr.io/hosts.toml",
            "capabilities = [\"pull\", \"resolve\"]\nskip_verify = true\n",
        )],
    );
    add(
        "order: no server, localhost",
        "localhost:5000",
        "",
        &[("localhost_5000_/hosts.toml", "capabilities = [\"pull\"]\n")],
    );
    add(
        "order: no server, docker.io",
        "docker.io",
        "",
        &[("docker.io/hosts.toml", "[host.\"a.io\"]\n")],
    );
    add(
        "order: not a table",
        "docker.io",
        "",
        &[("docker.io/hosts.toml", "host = 1\n")],
    );
    add(
        "order: host is a string",
        "docker.io",
        "",
        &[("docker.io/hosts.toml", "[host]\n\"a.io\" = \"x\"\n")],
    );

    // Capabilities.
    for caps in [
        "[]",
        "[\"pull\"]",
        "[\"PULL\", \"Resolve\"]",
        "[\"push\"]",
        "[\"referrers\"]",
        "[\"pull\", \"pull\"]",
        "[\"bogus\"]",
        "[\"pull\", \"bogus\"]",
        "\"pull\"",
        "[1]",
        "[\"\"]",
        "[\"\u{130}\"]",
    ] {
        let toml = format!("server = \"https://a.io\"\ncapabilities = {caps}\n");
        add(
            &format!("capabilities {caps}"),
            "docker.io",
            "",
            &[("docker.io/hosts.toml", &toml)],
        );
    }

    // ca, client, skip_verify, header, dial_timeout: types and values.
    for (key, value) in [
        ("ca", "\"a.pem\""),
        ("ca", "[\"a.pem\", \"/abs/b.pem\"]"),
        ("ca", "[]"),
        ("ca", "1"),
        ("ca", "[1]"),
        ("ca", "[[\"a\"]]"),
        ("ca", "\"\""),
        ("ca", "\"../up.pem\""),
        ("ca", "\"./a/../b.pem\""),
        ("client", "\"c.pem\""),
        ("client", "[\"c.pem\", \"d.pem\"]"),
        ("client", "[[\"c.cert\", \"c.key\"]]"),
        ("client", "[[\"c.cert\", \"\"]]"),
        ("client", "[[\"c.cert\"]]"),
        ("client", "[[\"a\", \"b\", \"c\"]]"),
        ("client", "[]"),
        ("client", "[1]"),
        ("client", "[[1, 2]]"),
        ("client", "1"),
        ("client", "[\"a\", [\"b\", \"c\"]]"),
        ("client", "[[]]"),
        ("skip_verify", "true"),
        ("skip_verify", "false"),
        ("skip_verify", "\"true\""),
        ("skip_verify", "1"),
        ("override_path", "true"),
        ("override_path", "\"yes\""),
        ("dial_timeout", "\"3s\""),
        ("dial_timeout", "\"1h30m\""),
        ("dial_timeout", "\"1.5s\""),
        ("dial_timeout", "\"300ms\""),
        ("dial_timeout", "\"0\""),
        ("dial_timeout", "\"0s\""),
        ("dial_timeout", "\"\""),
        ("dial_timeout", "\"3\""),
        ("dial_timeout", "\"s\""),
        ("dial_timeout", "\"1us\""),
        ("dial_timeout", "\"1\u{b5}s\""),
        ("dial_timeout", "\"1\u{3bc}s\""),
        ("dial_timeout", "\"+5s\""),
        ("dial_timeout", "\".5s\""),
        ("dial_timeout", "\"5.s\""),
        ("dial_timeout", "\"1d\""),
        ("dial_timeout", "\"1h1h\""),
        ("dial_timeout", "\"9223372036s\""),
        ("dial_timeout", "\"9223372037s\""),
        ("dial_timeout", "\"2562047h47m16.854775807s\""),
        ("dial_timeout", "\"2562047h47m16.854775808s\""),
        ("dial_timeout", "\"0.000000001s\""),
        ("dial_timeout", "\"1.0000000009s\""),
        ("dial_timeout", "3"),
        ("dial_timeout", "\"1m1\""),
        ("dial_timeout", "\"..s\""),
        ("header", "{ a = \"b\" }"),
        ("header", "{ a = [\"b\", \"c\"] }"),
        ("header", "{ a = 1 }"),
        ("header", "{ a = [1] }"),
        ("header", "{ a = { b = \"c\" } }"),
        ("header", "{}"),
        ("header", "\"x\""),
        ("header", "{ \"X-Mixed-Case\" = \"v\", lower = \"v\" }"),
        ("header", "{ a = [] }"),
        ("server", "1"),
        ("server", "[\"a\"]"),
    ] {
        let toml = format!("server = \"https://a.io\"\n[host.\"https://m.io\"]\n{key} = {value}\n");
        add(
            &format!("host {key} = {value}"),
            "docker.io",
            "",
            &[("docker.io/hosts.toml", &toml)],
        );
        let toml = format!("server = \"https://a.io\"\n{key} = {value}\n");
        add(
            &format!("root {key} = {value}"),
            "docker.io",
            "",
            &[("docker.io/hosts.toml", &toml)],
        );
    }

    // TLS settings and the fallback to plain HTTP.
    for (n, body) in [
        "skip_verify = true",
        "skip_verify = false",
        "ca = \"ca.crt\"",
        "ca = []",
        "client = \"pair.pem\"",
        "client = [[\"client.cert\", \"client.key\"]]",
        "capabilities = [\"pull\"]",
    ]
    .iter()
    .enumerate()
    {
        for server in [
            "http://m.io",
            "http://m.io:80",
            "http://m.io:5000",
            "http://localhost:8080",
            "https://m.io",
            "http://[::1]:5000",
            "http://m.io:",
        ] {
            let toml = format!("[host.\"{server}\"]\n{body}\n");
            add(
                &format!("tls {n}: {body} on {server}"),
                "docker.io",
                "",
                &[
                    ("docker.io/hosts.toml", &toml),
                    ("docker.io/ca.crt", CA),
                    ("docker.io/pair.pem", &pair),
                    ("docker.io/client.cert", CA),
                    ("docker.io/client.key", KEY),
                ],
            );
        }
    }
    add(
        "root tls on a local registry",
        "localhost:5000",
        "",
        &[("localhost_5000_/hosts.toml", "skip_verify = false\n")],
    );
    add(
        "root http on a local registry",
        "localhost:5000",
        "http",
        &[("localhost_5000_/hosts.toml", "ca = []\n")],
    );
    // Headers of a host and of the root.
    add(
        "headers",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "[header]\nauthorization = \"Bearer root\"\n[host.\"a.io\".header]\nx = [\"1\", \"2\"]\n",
        )],
    );

    // Keys of another case, and unknown keys.
    add(
        "unknown keys",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "server = \"https://a.io\"\nunknown = 1\n[host.\"b.io\"]\nunknown = [1]\n[unknown_table]\nx = 1\n",
        )],
    );
    add(
        "case of keys",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "Server = \"https://a.io\"\nCapabilities = [\"pull\"]\n[Host.\"b.io\"]\nCA = \"x.pem\"\nSkip_Verify = true\n",
        )],
    );
    add(
        "two spellings of host",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "[host.\"a.io\"]\ncapabilities = [\"pull\"]\n[HOST.\"b.io\"]\n[host.\"c.io\"]\n[Host.\"a.io\"]\nskip_verify = true\n",
        )],
    );
    add(
        "two spellings of a field",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "Server = \"https://a.io\"\nserver = \"https://b.io\"\nSERVER = \"https://c.io\"\n[host.\"d.io\"]\nskip_verify = true\nSkip_Verify = false\n",
        )],
    );
    add(
        "duplicate key",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "server = \"https://a.io\"\nserver = \"https://b.io\"\n",
        )],
    );
    add(
        "duplicate table",
        "docker.io",
        "",
        &[("docker.io/hosts.toml", "[host.\"a.io\"]\n[host.\"a.io\"]\n")],
    );
    add(
        "not toml",
        "docker.io",
        "",
        &[("docker.io/hosts.toml", "this is not toml")],
    );
    add(
        "bom",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "\u{feff}server = \"https://a.io\"\n",
        )],
    );
    add(
        "crlf",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "server = \"https://a.io\"\r\n[host.\"b.io\"]\r\ncapabilities = [\"pull\"]\r\n",
        )],
    );
    add(
        "comments and literal strings",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "# c\nserver = 'https://a.io' # c\n[host.'b.io']\n[host.\"c\\u002eio\"]\n",
        )],
    );
    add(
        "quoted dotted key",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "[host.\"a.b\".\"c.d\"]\n[\"host\".'x']\n[ host . y ]\n",
        )],
    );
    add(
        "multi-line string holds a header",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "x = \"\"\"\n[host.fake]\n\"\"\"\n[host.real]\n",
        )],
    );
    add(
        "relative ca joins the directory",
        "docker.io",
        "",
        &[(
            "docker.io/hosts.toml",
            "ca = \"sub/../x.pem\"\nserver = \"a.io\"\n",
        )],
    );
    cases
}

#[test]
fn hosts_agree_with_containerd() {
    let Some(oracle) = oracle() else { return };
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut cases = hosts_cases(dir.path());
    // The seeds of the fuzz target: each is the `hosts.toml` of `docker.io`.
    for (n, text) in seeds_and_mutations("hosts_toml", 400)
        .into_iter()
        .enumerate()
    {
        let root = dir.path().join(format!("seed-{n}"));
        cases.push((
            format!("seed {n}"),
            hosts_case(&root, "docker.io", "", &[("docker.io/hosts.toml", &text)]),
        ));
    }
    let asked: Vec<&HostsCase> = cases.iter().map(|(_, case)| case).collect();
    let theirs: Vec<Value> = oracle.ask("hosts", &asked).expect("the oracle answers");
    let labelled: Vec<(String, Value, Value)> = cases
        .iter()
        .zip(theirs)
        .map(|((label, case), mut theirs)| {
            let mut ours = our_hosts(case);
            // Where Go cannot read a file it names, it resolves nothing: that cannot be compared.
            if theirs["resolved"]["error"].is_string() {
                theirs["resolved"] = Value::Null;
                ours["resolved"] = Value::Null;
            }
            (label.clone(), ours, theirs)
        })
        .collect();
    expect_same("hosts", &labelled);
}

// ---- config ----

#[derive(Serialize)]
struct ConfigCase {
    root: PathBuf,
    files: BTreeMap<String, String>,
    entry: String,
}

fn auth(a: &Auth) -> Value {
    json!({
        "username": a.username,
        "password": a.password.expose_secret(),
        "auth": a.auth.expose_secret(),
        "identitytoken": a.identity_token.expose_secret(),
    })
}

fn our_config(root: &Path, entry: &str) -> Value {
    let path = root.join(entry);
    let (Ok(raw), Ok(plugins)) = (config::load_raw(&path), config::load_plugins(&path)) else {
        return json!({"error": true});
    };
    let RawRegistry {
        config_path,
        mirrors,
        configs,
        auths,
        headers: h,
    } = raw;
    json!({
        "registry": {
            "config_path": config_path,
            "mirrors": mirrors,
            "configs": configs.iter().map(|(k, v)| (k.clone(), v.as_ref().map_or(Value::Null, auth))).collect::<serde_json::Map<_, _>>(),
            "auths": auths.iter().map(|(k, v)| (k.clone(), auth(v))).collect::<serde_json::Map<_, _>>(),
            "headers": headers(&h),
        },
        "plugins": {
            "discard_unpacked_layers": plugins.discard_unpacked_layers,
            "nri": {
                "disable": plugins.nri.disable,
                "disable_connections": plugins.nri.disable_connections,
                "plugin_disabled": plugins.nri.plugin_disabled,
                "required_plugins": plugins.nri.required_plugins,
            },
        },
    })
}

fn config_cases(root: &Path) -> Vec<(String, ConfigCase)> {
    let mut cases: Vec<(String, ConfigCase)> = Vec::new();
    let mut add = |label: &str, files: &[(&str, &str)]| {
        let root = root.join(format!("case-{}", cases.len()));
        let substituted = files
            .iter()
            .map(|(name, content)| {
                (
                    (*name).to_owned(),
                    content.replace("@ROOT@", &root.to_string_lossy()),
                )
            })
            .collect();
        cases.push((
            label.to_owned(),
            ConfigCase {
                root,
                files: substituted,
                entry: "config.toml".to_owned(),
            },
        ));
    };

    // The e2e node images' config (containerd 2.3 and 2.4 run on the same kindest/node config).
    for (name, text) in [
        (
            "node k1.35",
            include_str!("data/containerd/node-k1.35.toml"),
        ),
        (
            "node k1.36",
            include_str!("data/containerd/node-k1.36.toml"),
        ),
        (
            "node k1.37",
            include_str!("data/containerd/node-k1.37.toml"),
        ),
    ] {
        add(name, &[("config.toml", text)]);
    }

    let registry = r#"
  config_path = "/etc/containerd/certs.d:/etc/docker/certs.d"
  [plugins.PLUGIN.registry.headers]
    X-Meta = ["a", "b"]
    Single = ["only"]
  [plugins.PLUGIN.registry.configs."reg.io".auth]
    username = "u"
    password = "p"
    auth = "dTpw"
    identitytoken = "t"
  [plugins.PLUGIN.registry.configs."other.io".auth]
    username = "o"
  [plugins.PLUGIN.registry.configs."none.io"]
  [plugins.PLUGIN.registry.auths."https://auth.io"]
    username = "au"
    password = "ap"
"#;
    for (version, plugin) in [
        ("0", "io.containerd.grpc.v1.cri"),
        ("1", "cri"),
        ("2", "io.containerd.grpc.v1.cri"),
        ("3", "io.containerd.cri.v1.images"),
        ("3", "io.containerd.grpc.v1.cri"),
        ("4", "io.containerd.cri.v1.images"),
        ("4", "io.containerd.grpc.v1.cri"),
    ] {
        let body = registry.replace("PLUGIN", &format!("\"{plugin}\""));
        let text = format!("version = {version}\n[plugins.\"{plugin}\"]\n{body}");
        add(
            &format!("registry in {plugin} of version {version}"),
            &[("config.toml", &text)],
        );
    }
    add(
        "no version, v1 names",
        &[(
            "config.toml",
            "[plugins.cri.registry]\nconfig_path = \"/x\"\n[plugins.foo-service]\n[plugins.windows]\n",
        )],
    );
    add(
        "version 5",
        &[(
            "config.toml",
            "version = 5\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/x\"\n",
        )],
    );
    add(
        "version 9 then imports 4",
        &[
            ("config.toml", "version = 9\nimports = [\"b.toml\"]\n"),
            ("b.toml", "version = 4\n"),
        ],
    );
    add(
        "version 4 then imports 9",
        &[
            ("config.toml", "version = 4\nimports = [\"b.toml\"]\n"),
            ("b.toml", "version = 9\n"),
        ],
    );
    add(
        "version is a string",
        &[("config.toml", "version = \"2\"\n")],
    );
    add(
        "legacy and images in a version 3 file",
        &[(
            "config.toml",
            "version = 3\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\nconfig_path = \"/legacy\"\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/images\"\n",
        )],
    );
    add(
        "legacy registry replaces the images one whole",
        &[(
            "config.toml",
            "version = 3\n[plugins.\"io.containerd.grpc.v1.cri\".registry.headers]\na = [\"1\"]\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/images\"\n",
        )],
    );
    add(
        "legacy without registry keeps the images one",
        &[(
            "config.toml",
            "version = 3\n[plugins.\"io.containerd.grpc.v1.cri\"]\nsandbox_image = \"x\"\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/images\"\n",
        )],
    );
    add("empty config", &[("config.toml", "")]);
    add(
        "no registry",
        &[(
            "config.toml",
            "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\"]\nsandbox_image = \"x\"\n",
        )],
    );
    add(
        "mirrors",
        &[(
            "config.toml",
            "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry.mirrors.\"docker.io\"]\nendpoint = [\"https://m.io\", \"http://n.io\"]\n[plugins.\"io.containerd.grpc.v1.cri\".registry.mirrors.\"x.io\"]\n",
        )],
    );
    add(
        "mirrors and config_path",
        &[(
            "config.toml",
            "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\nconfig_path = \"/x\"\n[plugins.\"io.containerd.grpc.v1.cri\".registry.mirrors.\"docker.io\"]\nendpoint = [\"https://m.io\"]\n",
        )],
    );
    add(
        "unknown keys",
        &[(
            "config.toml",
            "unknown = 1\n[plugins.\"io.containerd.cri.v1.images\".registry]\nunknown = 2\nconfig_path = \"/x\"\n[plugins.\"io.containerd.cri.v1.images\".registry.configs.\"a.io\"]\ntls = { ca_file = \"x\" }\n[plugins.\"io.containerd.cri.v1.images\".registry.configs.\"a.io\".auth]\nunknown = 3\nusername = \"u\"\n",
        )],
    );
    add(
        "case of keys",
        &[(
            "config.toml",
            "Version = 4\n[plugins.\"io.containerd.cri.v1.images\".Registry]\nConfig_Path = \"/x\"\n",
        )],
    );
    add(
        "two spellings of registry",
        &[(
            "config.toml",
            "version = 3\n[plugins.\"io.containerd.cri.v1.images\".registry.mirrors.\"a.io\"]\nendpoint = [\"https://m.io\"]\n[plugins.\"io.containerd.cri.v1.images\".Registry.mirrors.\"b.io\"]\nendpoint = [\"https://n.io\"]\n[plugins.\"io.containerd.cri.v1.images\".Registry.Mirrors.\"a.io\"]\nEndpoint = [\"https://o.io\"]\n",
        )],
    );
    add(
        "registry is not a table",
        &[(
            "config.toml",
            "[plugins.\"io.containerd.cri.v1.images\"]\nregistry = 1\n",
        )],
    );
    add(
        "config_path is not a string",
        &[(
            "config.toml",
            "[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = 1\n",
        )],
    );
    add(
        "headers value is a string",
        &[(
            "config.toml",
            "[plugins.\"io.containerd.cri.v1.images\".registry.headers]\nx = \"y\"\n",
        )],
    );
    add(
        "password is a number",
        &[(
            "config.toml",
            "[plugins.\"io.containerd.cri.v1.images\".registry.configs.\"a.io\".auth]\npassword = 1\n",
        )],
    );
    add(
        "endpoint is a string",
        &[(
            "config.toml",
            "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry.mirrors.\"a.io\"]\nendpoint = \"x\"\n",
        )],
    );
    add(
        "images plugin is not a table",
        &[(
            "config.toml",
            "[plugins]\n\"io.containerd.cri.v1.images\" = 1\n",
        )],
    );
    add("not toml", &[("config.toml", "version = ")]);
    add(
        "duplicate key",
        &[("config.toml", "version = 4\nversion = 4\n")],
    );
    add(
        "plugins is not a table",
        &[("config.toml", "plugins = 1\n")],
    );
    add(
        "imports is not a list",
        &[("config.toml", "imports = \"x\"\n")],
    );
    add(
        "required plugin without a dot",
        &[("config.toml", "required_plugins = [\"cri\"]\n")],
    );
    add(
        "disabled plugin without a dot",
        &[("config.toml", "version = 4\ndisabled_plugins = [\"cri\"]\n")],
    );
    add(
        "v1 renames required plugins",
        &[("config.toml", "version = 1\nrequired_plugins = [\"cri\"]\n")],
    );
    add(
        "plugin lists in imports",
        &[
            (
                "config.toml",
                "imports = [\"b.toml\"]\nrequired_plugins = [\"io.a.b\"]\n",
            ),
            ("b.toml", "required_plugins = [\"nodot\"]\n"),
        ],
    );

    // Plugin settings: discard_unpacked_layers where each version keeps it, and NRI.
    let cri = "\"io.containerd.grpc.v1.cri\"";
    let nri = "\"io.containerd.nri.v1.nri\"";
    for (label, text) in [
        (
            "discard in the images plugin",
            "version = 3\n[plugins.\"io.containerd.cri.v1.images\"]\ndiscard_unpacked_layers = true\n".to_owned(),
        ),
        (
            "discard in the images plugin, other case",
            "version = 4\n[plugins.\"io.containerd.cri.v1.images\"]\nDiscard_Unpacked_Layers = true\n".to_owned(),
        ),
        (
            "discard in the CRI plugin with runtimes",
            format!("version = 2\n[plugins.{cri}.containerd]\ndiscard_unpacked_layers = true\n[plugins.{cri}.containerd.runtimes.runc]\nruntime_type = \"x\"\n"),
        ),
        (
            "discard in the CRI plugin without runtimes",
            format!("version = 2\n[plugins.{cri}.containerd]\ndiscard_unpacked_layers = true\n"),
        ),
        (
            "discard in the CRI plugin of version 1",
            "version = 1\n[plugins.cri.containerd]\ndiscard_unpacked_layers = true\n[plugins.cri.containerd.runtimes.runc]\nx = 1\n".to_owned(),
        ),
        (
            "discard in the CRI plugin of version 3",
            format!("version = 3\n[plugins.{cri}.containerd]\ndiscard_unpacked_layers = true\n[plugins.{cri}.containerd.runtimes.runc]\nx = 1\n"),
        ),
        (
            "discard in the CRI plugin of version 4",
            format!("version = 4\n[plugins.{cri}.containerd]\ndiscard_unpacked_layers = true\n[plugins.{cri}.containerd.runtimes.runc]\nx = 1\n"),
        ),
        (
            "discard in both",
            format!("version = 2\n[plugins.{cri}.containerd]\ndiscard_unpacked_layers = true\n[plugins.{cri}.containerd.runtimes.runc]\nx = 1\n[plugins.\"io.containerd.cri.v1.images\"]\ndiscard_unpacked_layers = false\n"),
        ),
        (
            "discard is not a boolean",
            "version = 3\n[plugins.\"io.containerd.cri.v1.images\"]\ndiscard_unpacked_layers = \"yes\"\n".to_owned(),
        ),
        (
            "containerd is not a table",
            format!("version = 2\n[plugins.{cri}]\ncontainerd = 1\n"),
        ),
        (
            "runtimes is not a table",
            format!("version = 2\n[plugins.{cri}.containerd]\nruntimes = 1\n"),
        ),
        (
            "a runtime is not a table",
            format!("version = 2\n[plugins.{cri}.containerd.runtimes]\nrunc = 1\n"),
        ),
        (
            "pinned_images is not a table",
            format!("version = 2\n[plugins.{cri}]\nsandbox_image = \"x\"\n[plugins.\"io.containerd.cri.v1.images\"]\npinned_images = 1\n"),
        ),
        (
            "runtime_platform is not a table with runtimes",
            format!("version = 2\n[plugins.{cri}.containerd.runtimes.runc]\nx = 1\n[plugins.\"io.containerd.cri.v1.images\"]\nruntime_platform = 1\n"),
        ),
        (
            "runtime_platform is not a table without runtimes",
            format!("version = 2\n[plugins.{cri}]\nsandbox_image = \"x\"\n[plugins.\"io.containerd.cri.v1.images\"]\nruntime_platform = 1\n"),
        ),
        ("nri default", "version = 3\n".to_owned()),
        (
            "nri disabled",
            format!("version = 3\n[plugins.{nri}]\ndisable = true\n"),
        ),
        (
            "nri closed, other case",
            format!("version = 3\n[plugins.{nri}]\nDisable_Connections = true\n"),
        ),
        (
            "nri keys of the wrong type",
            format!("version = 3\n[plugins.{nri}]\ndisable = \"yes\"\n"),
        ),
        (
            "nri disabled by the list",
            "version = 3\ndisabled_plugins = [\"io.containerd.nri.v1.nri\"]\n".to_owned(),
        ),
        (
            "nri disabled by the list of version 1",
            "version = 1\ndisabled_plugins = [\"io.containerd.nri.v1.nri\"]\n".to_owned(),
        ),
        (
            "nri not disabled by another plugin",
            "version = 3\ndisabled_plugins = [\"io.containerd.grpc.v1.cri\"]\n".to_owned(),
        ),
        (
            "nri validator",
            format!("version = 3\n[plugins.{nri}.default_validator]\nrequired_plugins = [\"a\", \"b\"]\n"),
        ),
        (
            "nri validator is not a table",
            format!("version = 3\n[plugins.{nri}]\ndefault_validator = 1\n"),
        ),
    ] {
        add(label, &[("config.toml", &text)]);
    }

    add(
        "keys of two cases across imports",
        &[
            (
                "config.toml",
                "version = 3\nimports = [\"b.toml\"]\n[plugins.\"io.containerd.nri.v1.nri\".default_validator]\nrequired_plugins = [\"x\"]\n",
            ),
            (
                "b.toml",
                "[plugins.\"io.containerd.nri.v1.nri\".Default_Validator]\nRequired_Plugins = [\"a\", \"b\"]\n",
            ),
        ],
    );

    // Imports: order, globs, merging.
    add(
        "import relative",
        &[
            ("config.toml", "imports = [\"b.toml\"]\n"),
            (
                "b.toml",
                "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/b\"\n",
            ),
        ],
    );
    add(
        "import absolute",
        &[
            ("config.toml", "imports = [\"@ROOT@/b.toml\"]\n"),
            (
                "b.toml",
                "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/b\"\n",
            ),
        ],
    );
    add(
        "import missing",
        &[("config.toml", "imports = [\"nope.toml\"]\n")],
    );
    add(
        "import glob",
        &[
            ("config.toml", "imports = [\"conf.d/*.toml\"]\n"),
            (
                "conf.d/10.toml",
                "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/10\"\n[plugins.\"io.containerd.cri.v1.images\".registry.headers]\na = [\"10\"]\n",
            ),
            (
                "conf.d/20.toml",
                "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/20\"\n[plugins.\"io.containerd.cri.v1.images\".registry.headers]\nb = [\"20\"]\n",
            ),
            ("conf.d/skip.txt", "not toml"),
        ],
    );
    add(
        "import glob absolute",
        &[
            (
                "config.toml",
                "imports = [\"@ROOT@/conf.d/?0.toml\", \"@ROOT@/conf.d/[a-c]*.toml\"]\n",
            ),
            (
                "conf.d/10.toml",
                "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/10\"\n",
            ),
            (
                "conf.d/20.toml",
                "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/20\"\n",
            ),
            (
                "conf.d/b.toml",
                "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/b\"\n",
            ),
        ],
    );
    add(
        "import glob matches nothing",
        &[("config.toml", "imports = [\"nothing/*.toml\"]\n")],
    );
    add(
        "import glob in a missing directory",
        &[("config.toml", "imports = [\"@ROOT@/missing/*/x.toml\"]\n")],
    );
    add(
        "import glob two levels",
        &[
            ("config.toml", "imports = [\"d*/*.toml\"]\n"),
            (
                "d1/a.toml",
                "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/d1\"\n",
            ),
            (
                "d2/a.toml",
                "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/d2\"\n",
            ),
        ],
    );
    add(
        "import glob bad pattern",
        &[("config.toml", "imports = [\"conf.d/[*.toml\"]\n")],
    );
    add(
        "import glob bad range",
        &[("config.toml", "imports = [\"conf.d/[]a*\"]\n")],
    );
    add(
        "import glob bad escape",
        &[("config.toml", "imports = [\"conf.d/*\\\\\"]\n")],
    );
    add(
        "import glob escape",
        &[("config.toml", "imports = [\"conf.d/\\\\*.toml\"]\n")],
    );
    add(
        "import with dots",
        &[
            (
                "config.toml",
                "imports = [\"sub/../b.toml\", \"./c.toml\"]\n",
            ),
            ("b.toml", "version = 4\n"),
            ("c.toml", "version = 4\n"),
        ],
    );
    add(
        "import from a subdirectory",
        &[
            ("config.toml", "imports = [\"sub/a.toml\"]\n"),
            ("sub/a.toml", "imports = [\"b.toml\", \"../top.toml\"]\n"),
            (
                "sub/b.toml",
                "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/sub-b\"\n",
            ),
            ("top.toml", "version = 4\n"),
        ],
    );
    add(
        "import cycle",
        &[
            ("config.toml", "imports = [\"b.toml\"]\n"),
            (
                "b.toml",
                "imports = [\"config.toml\"]\nversion = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/b\"\n",
            ),
        ],
    );
    add(
        "import self",
        &[("config.toml", "imports = [\"config.toml\"]\nversion = 4\n")],
    );
    add(
        "imports are breadth first",
        &[
            (
                "config.toml",
                "version = 4\nimports = [\"a.toml\", \"b.toml\"]\n",
            ),
            (
                "a.toml",
                "version = 4\nimports = [\"c.toml\"]\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/a\"\n",
            ),
            (
                "b.toml",
                "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/b\"\n",
            ),
            (
                "c.toml",
                "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/c\"\n",
            ),
        ],
    );
    add(
        "import wins over the main file",
        &[
            (
                "config.toml",
                "version = 4\nimports = [\"b.toml\"]\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/main\"\n",
            ),
            (
                "b.toml",
                "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/b\"\n",
            ),
        ],
    );
    add(
        "import merges maps and replaces arrays",
        &[
            (
                "config.toml",
                "version = 4\nimports = [\"b.toml\"]\n[plugins.\"io.containerd.cri.v1.images\".registry.headers]\nx = [\"main1\", \"main2\"]\nonly-main = [\"m\"]\n[plugins.\"io.containerd.cri.v1.images\".registry.configs.\"a.io\".auth]\nusername = \"main\"\npassword = \"main-pw\"\n[plugins.\"io.containerd.cri.v1.images\".registry.configs.\"b.io\".auth]\nusername = \"b\"\n",
            ),
            (
                "b.toml",
                "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry.headers]\nx = [\"b\"]\nonly-b = [\"b\"]\n[plugins.\"io.containerd.cri.v1.images\".registry.configs.\"a.io\".auth]\nusername = \"import\"\n",
            ),
        ],
    );
    add(
        "import replaces a table by a value",
        &[
            (
                "config.toml",
                "version = 4\nimports = [\"b.toml\"]\n[plugins.\"io.containerd.cri.v1.images\"]\nregistry = { config_path = \"/main\" }\n",
            ),
            (
                "b.toml",
                "version = 4\n[plugins]\n\"io.containerd.cri.v1.images\" = 1\n",
            ),
        ],
    );
    add(
        "import replaces a value by a table",
        &[
            (
                "config.toml",
                "version = 4\nimports = [\"b.toml\"]\n[plugins]\n\"io.containerd.cri.v1.images\" = 1\n",
            ),
            (
                "b.toml",
                "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/b\"\n",
            ),
        ],
    );
    add(
        "import with an empty value over a set one",
        &[
            (
                "config.toml",
                "version = 4\nimports = [\"b.toml\"]\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/main\"\n[plugins.\"io.containerd.cri.v1.images\".registry.headers]\nx = [\"1\"]\n",
            ),
            (
                "b.toml",
                "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"\"\n[plugins.\"io.containerd.cri.v1.images\".registry.headers]\nx = []\n",
            ),
        ],
    );
    add(
        "import of an older version",
        &[
            (
                "config.toml",
                "version = 4\nimports = [\"b.toml\"]\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/main\"\n",
            ),
            (
                "b.toml",
                "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\nconfig_path = \"/old\"\n",
            ),
        ],
    );
    add(
        "import of an older version first",
        &[
            (
                "config.toml",
                "version = 2\nimports = [\"b.toml\"]\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\nconfig_path = \"/old\"\n",
            ),
            (
                "b.toml",
                "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/new\"\n",
            ),
        ],
    );
    add(
        "both versions across files",
        &[
            (
                "config.toml",
                "version = 2\nimports = [\"b.toml\"]\n[plugins.\"io.containerd.grpc.v1.cri\".registry.headers]\na = [\"1\"]\n",
            ),
            (
                "b.toml",
                "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry.headers]\nb = [\"2\"]\n",
            ),
        ],
    );
    cases
}

#[test]
fn config_agrees_with_containerd() {
    let Some(oracle) = oracle() else { return };
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut cases = config_cases(dir.path());
    for (n, text) in seeds_and_mutations("containerd_config", 400)
        .into_iter()
        .enumerate()
    {
        let root = dir.path().join(format!("seed-{n}"));
        cases.push((
            format!("seed {n}: {text:?}"),
            ConfigCase {
                root,
                files: BTreeMap::from([("config.toml".to_owned(), text)]),
                entry: "config.toml".to_owned(),
            },
        ));
    }
    let asked: Vec<&ConfigCase> = cases.iter().map(|(_, case)| case).collect();
    let theirs: Vec<Value> = oracle.ask("config", &asked).expect("the oracle answers");
    let labelled: Vec<(String, Value, Value)> = cases
        .iter()
        .zip(theirs)
        .map(|((label, case), theirs)| (label.clone(), our_config(&case.root, &case.entry), theirs))
        .collect();
    expect_same("config", &labelled);
}

/// The seeds, and for each of them mutations that a fuzzer would try: bytes deleted, replaced by one of the seed's own,
/// or inserted. A fixed generator keeps the cases the same on every run.
fn seeds_and_mutations(target: &str, per_seed: usize) -> Vec<String> {
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = move |bound: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        usize::try_from(state % u64::try_from(bound).expect("a small bound"))
            .expect("a small index")
    };
    let mut texts = Vec::new();
    for seed in seeds(target) {
        texts.push(String::from_utf8_lossy(&seed).into_owned());
        for _ in 0..per_seed {
            let mut bytes = seed.clone();
            for _ in 0..=next(3) {
                if bytes.is_empty() {
                    break;
                }
                let at = next(bytes.len());
                match next(3) {
                    0 => {
                        bytes.remove(at);
                    }
                    1 => bytes[at] = seed[next(seed.len())],
                    _ => bytes.insert(at, seed[next(seed.len())]),
                }
            }
            if let Ok(text) = String::from_utf8(bytes) {
                texts.push(text);
            }
        }
    }
    texts
}

/// The seeds of a fuzz target, in file name order.
fn seeds(target: &str) -> Vec<Vec<u8>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/seeds")
        .join(target);
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.expect("a readable seed directory").path())
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|p| std::fs::read(p).expect("a readable seed"))
        .collect()
}
