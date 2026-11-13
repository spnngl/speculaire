//! Image references and platforms against containerd's own code (D29, D70): the same cases go to `speculaire-oracle`
//! and to the Rust port, and the answers must be the same.
//!
//! The cases are the test data of `distribution/reference` v0.6.0 and `containerd/platforms` v1.0.0-rc.5 (the seeds
//! of the fuzz targets, and a mutation of each), the image names of the e2e suites, and platforms listed by hand.
//! Without `SPECULAIRE_ORACLE` the tests skip, as in `just check`; `just oracle` sets it.

#![expect(clippy::panic, reason = "a test file: its helpers report by panicking")]

use std::path::{Path, PathBuf};

use oci_spec::image::{Arch, Os, Platform, PlatformBuilder};
use serde::Serialize;
use serde_json::{Value, json};
use speculaire_oci::platform::{self, Host, Matcher};
use speculaire_oci::reference::Reference;
use speculaire_oracle_harness::Oracle;

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
                if key == "error" || key == "parse_error" {
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

fn expect_same(subcommand: &str, labelled: &[(String, Value, Value)]) {
    let mut failures = Vec::new();
    for (label, ours, theirs) in labelled {
        let (mut ours, mut theirs) = (ours.clone(), theirs.clone());
        normalise(&mut ours);
        normalise(&mut theirs);
        if ours != theirs {
            failures.push(format!("{label}\n  rust:   {ours}\n  oracle: {theirs}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} {subcommand} cases differ from the oracle:\n{}",
        failures.len(),
        labelled.len(),
        failures
            .iter()
            .take(12)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    eprintln!(
        "oracle: {} {subcommand} cases agree with the oracle",
        labelled.len()
    );
}

// ---- reference ----

#[derive(Serialize)]
struct ReferenceCase {
    input: String,
}

fn named(result: &Result<Reference, speculaire_oci::reference::ReferenceError>) -> Value {
    match result {
        Err(_) => json!({"ok": null, "error": true}),
        Ok(reference) => json!({"ok": {
            "reference": reference.to_string(),
            "name": reference.name(),
            "domain": reference.domain(),
            "path": reference.path(),
            "tag": reference.tag().unwrap_or_default(),
            "digest": reference.digest().map(ToString::to_string).unwrap_or_default(),
        }}),
    }
}

fn our_reference(input: &str) -> Value {
    json!({
        "docker": named(&Reference::parse_docker_ref(input)),
        "normalized": named(&Reference::parse_normalized_named(input)),
    })
}

fn reference_inputs() -> Vec<String> {
    let digest = format!("sha256:{}", "ab".repeat(32));
    let mut inputs: Vec<String> = [
        "nginx",
        "nginx:1.27",
        "library/nginx",
        "docker.io/nginx",
        "docker.io/library/nginx:1.27",
        "index.docker.io/nginx",
        "index.docker.io/org/app:v1",
        "registry-1.docker.io/org/app",
        "org/app",
        "localhost/app",
        "localhost:5000/app:v1",
        "registry.example/app",
        "registry.example:5000/a/b/c:tag",
        "[::1]:5000/app",
        "[fe80::1]/app:v1",
        "Registry.Example/app",
        "UPPER/app",
        "org/App",
        "my_registry.example/app",
        "a.b/c.d/e_f/g__h/i---j",
        "a//b",
        "a/-b",
        "nginx:",
        "nginx:_",
        "nginx:-x",
        "nginx@sha256",
        "nginx:1.27:2",
        "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec",
        "docker.io/library/alpine:3.23@sha256:469c9ea410b9215eaee7976ba6c0639039b444be8e5d638f7abbada189971eb2",
        "docker.io/kindest/node",
        "",
        "/",
        ":",
        "@",
        "a:b/c",
    ]
    .map(str::to_owned)
    .into();
    inputs.push("a".repeat(64));
    inputs.push(format!("registry.example/{}", "a".repeat(255)));
    inputs.push(format!("registry.example/{}", "a".repeat(256)));
    inputs.push(format!("nginx:{}", "a".repeat(128)));
    inputs.push(format!("nginx:{}", "a".repeat(129)));
    for alg_digest in [
        digest.clone(),
        format!("sha384:{}", "cd".repeat(48)),
        format!("sha512:{}", "ef".repeat(64)),
        format!("sha1:{}", "ab".repeat(20)),
        format!("blake3:{}", "ab".repeat(32)),
        format!("sha256:{}", "AB".repeat(32)),
        format!("sha256:{}", "ab".repeat(31)),
        format!("sha256-x+y.z:{}", "ab".repeat(32)),
        format!("Sha256:{}", "ab".repeat(32)),
    ] {
        inputs.push(format!("nginx@{alg_digest}"));
        inputs.push(format!("nginx:1.27@{alg_digest}"));
        inputs.push(format!("localhost:5000/a/b:t@{alg_digest}"));
    }
    inputs
}

#[test]
fn references_agree_with_containerd() {
    let Some(oracle) = oracle() else { return };
    let mut inputs = reference_inputs();
    inputs.extend(seeds_and_mutations("reference", 40));
    let cases: Vec<ReferenceCase> = inputs
        .iter()
        .map(|input| ReferenceCase {
            input: input.clone(),
        })
        .collect();
    let theirs: Vec<Value> = oracle.ask("reference", &cases).expect("the oracle answers");
    let labelled: Vec<(String, Value, Value)> = inputs
        .iter()
        .zip(theirs)
        .map(|(input, theirs)| (format!("{input:?}"), our_reference(input), theirs))
        .collect();
    expect_same("reference", &labelled);
}

// ---- platform ----

#[derive(Serialize, Clone)]
struct Plat {
    os: String,
    architecture: String,
    variant: String,
    os_version: String,
    os_features: Vec<String>,
}

impl Plat {
    fn new(os: &str, architecture: &str, variant: &str) -> Self {
        Self {
            os: os.to_owned(),
            architecture: architecture.to_owned(),
            variant: variant.to_owned(),
            os_version: String::new(),
            os_features: Vec::new(),
        }
    }

    fn platform(&self) -> Platform {
        let mut builder = PlatformBuilder::default()
            .os(Os::from(self.os.as_str()))
            .architecture(Arch::from(self.architecture.as_str()));
        if !self.variant.is_empty() {
            builder = builder.variant(self.variant.clone());
        }
        if !self.os_version.is_empty() {
            builder = builder.os_version(self.os_version.clone());
        }
        if !self.os_features.is_empty() {
            builder = builder.os_features(self.os_features.clone());
        }
        builder.build().expect("a platform")
    }
}

#[derive(Serialize)]
struct PlatformCase {
    host: bool,
    specifier: Option<String>,
    platform: Option<Plat>,
    candidates: Vec<Plat>,
}

fn plat_json(platform: &Platform) -> Value {
    json!({
        "os": platform.os().to_string(),
        "architecture": platform.architecture().to_string(),
        "variant": platform.variant().clone().unwrap_or_default(),
        "os_version": platform.os_version().clone().unwrap_or_default(),
        "os_features": platform.os_features().clone().unwrap_or_default(),
    })
}

fn matching(matcher: &Matcher, candidates: &[Platform]) -> Value {
    json!({
        "matches": candidates.iter().map(|c| matcher.matches(c)).collect::<Vec<_>>(),
        "less": candidates.iter().map(|a| candidates.iter().map(|b| matcher.less(a, b)).collect::<Vec<_>>()).collect::<Vec<_>>(),
    })
}

fn our_platform(case: &PlatformCase, host: &Host) -> Value {
    let mut answer = serde_json::Map::new();
    if let Some(specifier) = &case.specifier {
        match platform::parse(specifier, host) {
            Err(_) => {
                answer.insert("parse_error".to_owned(), json!(true));
            }
            Ok(parsed) => {
                answer.insert("parsed".to_owned(), plat_json(&parsed));
                answer.insert("format".to_owned(), json!(platform::format(&parsed)));
                answer.insert(
                    "format_all".to_owned(),
                    json!(platform::format_all(&parsed)),
                );
            }
        }
    }
    if let Some(node) = &case.platform {
        let node = node.platform();
        answer.insert(
            "normalized".to_owned(),
            plat_json(&platform::normalize(&node, host)),
        );
        answer.insert("format".to_owned(), json!(platform::format(&node)));
        answer.insert("format_all".to_owned(), json!(platform::format_all(&node)));
        let candidates: Vec<Platform> = case.candidates.iter().map(Plat::platform).collect();
        if let (Ok(only), Ok(strict)) = (
            Matcher::only(&node, host),
            Matcher::only_strict(&node, host),
        ) {
            answer.insert("only".to_owned(), matching(&only, &candidates));
            answer.insert("only_strict".to_owned(), matching(&strict, &candidates));
        }
    }
    // The oracle leaves out what is empty.
    for key in ["format", "format_all"] {
        if answer.get(key).is_some_and(|text| text == "") {
            answer.remove(key);
        }
    }
    Value::Object(answer)
}

fn specifiers() -> Vec<String> {
    let mut specifiers: Vec<String> = [
        "linux/amd64",
        "linux/x86_64",
        "linux/x86-64",
        "linux/amd64/v1",
        "linux/amd64/v3",
        "linux/arm64",
        "linux/aarch64",
        "linux/arm64/v8",
        "linux/arm64/8",
        "linux/arm64/v8.0",
        "linux/arm64/v8.2",
        "linux/arm64/v9",
        "linux/arm64/9.0",
        "linux/arm64/v9.4",
        "linux/arm64/",
        "linux/arm",
        "linux/arm/v7",
        "linux/arm/7",
        "linux/arm/v6",
        "linux/arm/5",
        "linux/armhf",
        "linux/armel",
        "linux/i386",
        "linux/386",
        "linux/ppc64le",
        "linux/s390x",
        "linux/riscv64",
        "linux/wasm",
        "darwin/arm64",
        "macos/arm64",
        "MacOS/ARM64",
        "freebsd/amd64",
        "windows/amd64",
        "windows(10.0.17763)/amd64",
        "windows(10.0.17763+win32k)/amd64",
        "windows(10.0+a+b)/amd64",
        "windows(a%2Bb)/amd64",
        "windows(a%2)/amd64",
        "windows(a%zz)/amd64",
        "windows(+a)/amd64",
        "windows(a+)/amd64",
        "windows(a++b)/amd64",
        "windows(%20)/amd64",
        "windows()/amd64",
        "windows(",
        "linux(1)",
        "linux",
        "windows",
        "darwin",
        "amd64",
        "arm64",
        "arm",
        "aarch64",
        "armhf",
        "armel",
        "x86_64",
        "i386",
        "arm64(1.0)",
        "plan9",
        "unknown",
        "nothing",
        "",
        "*",
        "linux/*",
        "*/amd64",
        "linux/amd64/v8/extra",
        "linux/amd64/v8/extra/more",
        "/amd64",
        "linux/",
        "linux//amd64",
        "li nux/amd64",
        "linux/am d64",
        "linux/../amd64",
        "linux/./amd64",
        "../amd64",
        "linux/amd64/..",
        "linux/..",
        "linux/arm64/../v9",
        "linux/a.b/c-d_e",
    ]
    .map(str::to_owned)
    .into();
    specifiers.extend(seeds_and_mutations("platform", 20));
    specifiers
}

fn platforms_for_matching() -> Vec<Plat> {
    let mut platforms = Vec::new();
    for os in ["linux", "windows", "Linux"] {
        for (arch, variants) in [
            ("amd64", &["", "v1", "v2", "v3", "v4", "vv3"][..]),
            ("386", &[""][..]),
            (
                "arm64",
                &[
                    "", "v8", "v8.1", "v8.9", "v9", "v9.2", "v9.7", "v8.10", "v10",
                ][..],
            ),
            ("arm", &["", "v5", "v6", "v7", "v8", "vv7"][..]),
            ("x86_64", &[""][..]),
            ("aarch64", &["8"][..]),
            ("ppc64le", &[""][..]),
        ] {
            for variant in variants {
                platforms.push(Plat::new(os, arch, variant));
            }
        }
    }
    for features in [
        vec!["a"],
        vec!["a", "c"],
        vec!["c", "a"],
        vec!["b"],
        vec!["a", "a"],
        vec!["a", "b", "c"],
    ] {
        let mut platform = Plat::new("linux", "amd64", "");
        platform.os_features = features.into_iter().map(str::to_owned).collect();
        platforms.push(platform);
    }
    platforms
}

#[test]
fn platforms_agree_with_containerd() {
    let Some(oracle) = oracle() else { return };
    // The oracle's own platform decides what a specifier that names one half means.
    let probe = PlatformCase {
        host: true,
        specifier: None,
        platform: None,
        candidates: Vec::new(),
    };
    let answers: Vec<Value> = oracle
        .ask("platform", &[&probe])
        .expect("the oracle answers");
    let host = Host {
        os: answers[0]["host"]["os"].as_str().expect("an OS").to_owned(),
        arch: answers[0]["host"]["architecture"]
            .as_str()
            .expect("an architecture")
            .to_owned(),
        variant: String::new(),
    };
    let candidates = platforms_for_matching();
    let mut cases: Vec<(String, PlatformCase)> = Vec::new();
    for specifier in specifiers() {
        cases.push((
            format!("parse {specifier:?}"),
            PlatformCase {
                host: false,
                specifier: Some(specifier),
                platform: None,
                candidates: Vec::new(),
            },
        ));
    }
    // Every platform is a node, in turn, against every candidate; a Windows node has no matcher here.
    for node in &candidates {
        let numeric_variant = node
            .variant
            .strip_prefix('v')
            .unwrap_or(&node.variant)
            .parse::<i64>()
            .is_ok_and(|n| n > 1000);
        if node.os.eq_ignore_ascii_case("windows") || numeric_variant {
            continue;
        }
        cases.push((
            format!("match {}/{}/{}", node.os, node.architecture, node.variant),
            PlatformCase {
                host: false,
                specifier: None,
                platform: Some(node.clone()),
                candidates: candidates.clone(),
            },
        ));
    }
    let mut featured = Plat::new("linux", "amd64", "");
    featured.os_features = vec!["c".to_owned(), "a".to_owned(), "a".to_owned()];
    featured.os_version = "1.0+x".to_owned();
    cases.push((
        "features".to_owned(),
        PlatformCase {
            host: false,
            specifier: None,
            platform: Some(featured),
            candidates,
        },
    ));
    let asked: Vec<&PlatformCase> = cases.iter().map(|(_, case)| case).collect();
    let theirs: Vec<Value> = oracle.ask("platform", &asked).expect("the oracle answers");
    let labelled: Vec<(String, Value, Value)> = cases
        .iter()
        .zip(theirs)
        .map(|((label, case), theirs)| (label.clone(), our_platform(case, &host), theirs))
        .collect();
    expect_same("platform", &labelled);
}

/// The seeds of a fuzz target, and for each of them mutations that a fuzzer would try: bytes deleted, replaced by one
/// of the seed's own, or inserted. A fixed generator keeps the cases the same on every run.
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
