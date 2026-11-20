//! `speculaire verify` as a process (D156): the recorded fixtures of step 01 (D141), served by a registry on loopback,
//! verified against their pinned trusted root under a policy of each test's own.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::collections::HashMap;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::Arc;

use serde_json::Value;
use speculaire_artifacts::testing::{FIXTURES, Layout};

/// The repository the registry serves each fixture in.
const REPOSITORY: &str = "fixtures";

/// The workflow that signed the keyless fixtures, and its issuer.
const SAN: &str =
    "https://github.com/spnngl/speculaire/.github/workflows/fixtures.yml@refs/heads/main";
const ISSUER: &str = "https://token.actions.githubusercontent.com";

/// What the registry answers a path with: the content type, if any, and the body.
type Replies = HashMap<String, (Option<String>, Vec<u8>)>;

/// Serves `layout` on loopback as zot does, the referrers API answering what each fallback tag lists, until the test
/// process ends.
fn registry(layout: &Layout) -> SocketAddr {
    let mut replies = Replies::new();
    for (digest, bytes) in layout.blobs() {
        let media_type = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|json| json["mediaType"].as_str().map(str::to_owned))
            .filter(|media_type| media_type.contains("manifest") || media_type.contains("index"));
        if let Some(media_type) = media_type {
            replies.insert(
                format!("/v2/{REPOSITORY}/manifests/{digest}"),
                (Some(media_type), bytes.clone()),
            );
        }
        replies.insert(format!("/v2/{REPOSITORY}/blobs/{digest}"), (None, bytes));
    }
    for (tag, digest) in layout.tags() {
        let bytes = layout.blob(digest);
        let path = match tag.strip_prefix("sha256-") {
            Some(target) if !target.contains('.') => {
                format!("/v2/{REPOSITORY}/referrers/sha256:{target}")
            }
            _ => format!("/v2/{REPOSITORY}/manifests/{tag}"),
        };
        replies.insert(path, (None, bytes));
    }
    let replies = Arc::new(replies);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().map_while(Result::ok) {
            let replies = Arc::clone(&replies);
            std::thread::spawn(move || answer(stream, &replies));
        }
    });
    address
}

/// Answers each request on `stream` from `replies`, `404` when none is for its path.
fn answer(stream: TcpStream, replies: &Replies) {
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let mut words = line.split_whitespace();
        let (method, target) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
        let path = target.split('?').next().unwrap_or("");
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 || header == "\r\n" {
                break;
            }
        }
        let (status, content_type, body) = replies
            .get(path)
            .map_or(("404 Not Found", None, &[][..]), |(content_type, body)| {
                ("200 OK", content_type.as_deref(), body.as_slice())
            });
        let content_type = content_type
            .map(|content_type| format!("Content-Type: {content_type}\r\n"))
            .unwrap_or_default();
        let head = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\n{content_type}\r\n",
            body.len()
        );
        let body = if method == "HEAD" { &[][..] } else { body };
        if writer.write_all(head.as_bytes()).is_err() || writer.write_all(body).is_err() {
            return;
        }
    }
}

/// A node: containerd's config, whose `hosts.toml` sends the registry at `address` over plain HTTP, the agent's
/// config, and the policy file holding `policy`.
struct Node {
    dir: tempfile::TempDir,
}

impl Node {
    fn new(address: SocketAddr, policy: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        let hosts = path.join("certs.d").join(address.to_string());
        std::fs::create_dir_all(&hosts).unwrap();
        std::fs::write(
            hosts.join("hosts.toml"),
            format!("server = \"http://{address}\"\n"),
        )
        .unwrap();
        std::fs::write(
            path.join("containerd.toml"),
            format!(
                "version = 3\n[plugins.'io.containerd.cri.v1.images'.registry]\nconfig_path = \"{}\"\n",
                path.join("certs.d").display()
            ),
        )
        .unwrap();
        std::fs::write(path.join("policy.yaml"), policy).unwrap();
        let dir_text = path.display();
        std::fs::write(
            path.join("config.toml"),
            format!(
                "[runtime]\ncontainerd_socket = \"{dir_text}/containerd.sock\"\ncontainerd_config = \
                 \"{dir_text}/containerd.toml\"\ncrio_socket = \"{dir_text}/crio.sock\"\n[verify]\npolicy = \
                 \"{dir_text}/policy.yaml\"\ntrusted_root = \"{FIXTURES}/trusted_root.json\"\n"
            ),
        )
        .unwrap();
        Self { dir }
    }

    /// `speculaire verify` of `image` on this node, with `args` before it.
    fn verify(&self, args: &[&str], image: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_speculaire"))
            .arg("verify")
            .arg("--config")
            .arg(self.dir.path().join("config.toml"))
            .args(["--runtime", "containerd"])
            .args(args)
            .arg(image)
            .output()
            .unwrap()
    }
}

/// A policy named `name` over every image, which the fixtures' workflow signs, with `extra` appended to its spec and
/// `authority` to its one authority.
fn policy(name: &str, extra: &str, authority: &str) -> String {
    format!(
        "apiVersion: policy.sigstore.dev/v1beta1\nkind: ClusterImagePolicy\nmetadata:\n  name: {name}\nspec:\n  \
         images:\n  - glob: \"**\"\n{extra}  authorities:\n  - keyless:\n      identities:\n      - issuer: {ISSUER}\n        \
         subject: {SAN}\n{authority}"
    )
}

/// `speculaire verify` of `case`, served by a registry of its own, under `policy`: its exit code and its stdout.
fn verify(case: &str, policy: &str, args: &[&str]) -> (Option<i32>, String) {
    let layout = Layout::open(case);
    let address = registry(&layout);
    let node = Node::new(address, policy);
    let image = format!("{address}/{REPOSITORY}@{}", layout.root());
    let out = node.verify(args, &image);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("{case}:\n{stdout}{stderr}");
    (out.status.code(), stdout)
}

#[test]
fn a_keyless_image_is_allowed_naming_the_authority_that_passes_with_its_san() {
    let (code, stdout) = verify("keyless", &policy("signed", "", ""), &[]);

    assert_eq!(code, Some(0), "{stdout}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.first(), Some(&"allow"), "{stdout}");
    assert!(lines.contains(&"policy signed: pass"), "{stdout}");
    let authority = format!("  authority 1: pass: {SAN} (issuer {ISSUER})");
    assert!(lines.contains(&authority.as_str()), "{stdout}");
}

#[test]
fn json_holds_the_same_content_as_one_object() {
    let (code, stdout) = verify("keyless", &policy("signed", "", ""), &["--json"]);

    assert_eq!(code, Some(0), "{stdout}");
    let json: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["verdict"], "allow");
    let authority = &json["policies"][0]["authorities"][0];
    assert_eq!(json["policies"][0]["name"], "signed");
    assert_eq!(authority["result"], "pass");
    assert_eq!(
        authority["reason"].as_str(),
        Some(format!("{SAN} (issuer {ISSUER})").as_str())
    );
}

#[test]
fn an_image_attested_only_by_an_att_tag_is_rejected_with_the_missing_attestation() {
    let attestation = "    attestations:\n    - name: provenance\n      predicateType: https://slsa.dev/provenance/v1\n";
    let (code, stdout) = verify("att-only", &policy("attested", "", attestation), &[]);

    assert_eq!(code, Some(1), "{stdout}");
    let reason = "attestation https://slsa.dev/provenance/v1 missing (.att tags are not supported)";
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.first().copied(),
        Some(format!("rejected: {reason}").as_str())
    );
    let line =
        format!("    attestation provenance (https://slsa.dev/provenance/v1): fail: {reason}");
    assert!(lines.contains(&line.as_str()), "{stdout}");
}

#[test]
fn an_sbom_without_packages_is_rejected_on_its_sbom_line() {
    let (code, stdout) = verify("spdx-empty", &policy("sbom", "  sbom: required\n", ""), &[]);

    assert_eq!(code, Some(1), "{stdout}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.first(),
        Some(&"rejected: SBOM without packages"),
        "{stdout}"
    );
    assert!(
        lines.contains(&"  sbom: fail: SBOM without packages"),
        "{stdout}"
    );
}

#[test]
fn a_config_error_or_a_reference_without_digest_exits_2() {
    let out = Command::new(env!("CARGO_BIN_EXE_speculaire"))
        .args(["verify", "--config", "/nonexistent/config.toml"])
        .args(["--runtime", "containerd"])
        .arg(format!("registry.test/app@sha256:{}", "0".repeat(64)))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("/nonexistent/config.toml"));

    let layout = Layout::open("keyless");
    let node = Node::new(registry(&layout), &policy("signed", "", ""));
    let out = node.verify(&[], "registry.test/app:latest");
    assert_eq!(out.status.code(), Some(2));
}
