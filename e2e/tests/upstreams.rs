//! The upstreams of the harness (D94, D112): each serves the test images where the suites look for them, the proxy
//! throttles what it is told to, and a node can lose an upstream.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use e2e::registry::{PASSWORD, Proxy, USER};
use e2e::upstream::{Kind, SIGNED, UNSIGNED, Upstream};
use e2e::{Cluster, Output};

/// The tests share the nodes' runtimes and network: one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The predicate types of the referrers of [`SIGNED`]: its signature, its SLSA provenance and its SPDX document.
const PREDICATES: [&str; 3] = [
    "https://sigstore.dev/cosign/sign/v1",
    "https://slsa.dev/provenance/v1",
    "https://spdx.dev/Document",
];

/// The repository of [`SIGNED`].
const REPOSITORY: &str = "e2e/signed";

fn sh(cluster: &Cluster, node: &str, script: &str) -> Output {
    cluster.exec_output(node, &["sh", "-c", script]).unwrap()
}

fn nodes(cluster: &Cluster) -> Vec<String> {
    cluster
        .nodes()
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .collect()
}

/// `GET <path>` of `upstream` from `node`, logged in on the private one: the status and the body.
fn get(
    cluster: &Cluster,
    node: &str,
    upstream: &Upstream,
    kind: Kind,
    path: &str,
) -> (u16, String) {
    let host = upstream.address();
    let accept = "-H 'Accept: application/vnd.oci.image.index.v1+json' \
                  -H 'Accept: application/vnd.oci.image.manifest.v1+json'";
    let script = match kind {
        Kind::Plain | Kind::Referrers => {
            format!("curl -s {accept} -w '\\n%{{http_code}}' http://{host}{path}")
        }
        Kind::Public => format!("curl -s {accept} -w '\\n%{{http_code}}' https://{host}{path}"),
        // The token server's address is in the registry's challenge.
        Kind::Private => format!(
            "realm=$(curl -sk -o /dev/null -D - https://{host}/v2/ | tr -d '\\r' \
               | sed -n 's/.*realm=\"\\([^\"]*\\)\".*/\\1/p') \
             && token=$(curl -sfk -u {USER}:{PASSWORD} \"$realm?service=e2e-registry&scope=repository:{REPOSITORY}:pull\" \
               | sed 's/.*\"token\":\"\\([^\"]*\\)\".*/\\1/') \
             && curl -sk {accept} -H \"Authorization: Bearer $token\" -w '\\n%{{http_code}}' https://{host}{path}"
        ),
    };
    let output = sh(cluster, node, &script);
    assert!(output.success, "{output:?}");
    let (body, status) = output
        .stdout
        .trim_end()
        .rsplit_once('\n')
        .unwrap_or(("", &output.stdout));
    (status.trim().parse().unwrap(), body.to_owned())
}

/// The digests of the manifests an index lists, each with the predicate type of its Sigstore bundle, if it names one.
fn listed(index: &str) -> BTreeSet<(String, String)> {
    let index: serde_json::Value = serde_json::from_str(index).unwrap();
    index["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|manifest| {
            let predicate = manifest
                .pointer("/annotations/dev.sigstore.bundle.predicateType")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            (
                manifest["digest"].as_str().unwrap().to_owned(),
                predicate.to_owned(),
            )
        })
        .collect()
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_node_pulls_the_test_images_from_each_upstream_with_its_own_config() {
    let _serial = serial();
    let cluster = Cluster::from_env();
    let node = nodes(&cluster).pop().unwrap();
    for kind in Kind::ALL {
        let host = cluster.upstream(kind).address().to_owned();
        for image in [SIGNED, UNSIGNED] {
            let reference = format!("{host}/{image}");
            let pull = sh(&cluster, &node, &format!("crictl pull {reference}"));
            assert!(pull.success, "{kind:?}: {pull:?}");
            sh(&cluster, &node, &format!("crictl rmi {reference}"));
        }
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_signed_image_has_three_referrers_on_zot_and_a_fallback_tag_on_each_registry() {
    let _serial = serial();
    let cluster = Cluster::from_env();
    let node = nodes(&cluster).pop().unwrap();
    let zot = cluster.upstream(Kind::Referrers);
    let digest = zot.digest(SIGNED).unwrap();
    let (status, index) = get(
        &cluster,
        &node,
        &zot,
        Kind::Referrers,
        &format!("/v2/{REPOSITORY}/referrers/{digest}"),
    );
    assert_eq!(status, 200, "{index}");
    let referrers = listed(&index);
    let predicates: BTreeSet<&str> = referrers
        .iter()
        .map(|(_, predicate)| predicate.as_str())
        .collect();
    assert_eq!(predicates, BTreeSet::from(PREDICATES), "{index}");
    let digests: BTreeSet<&String> = referrers.iter().map(|(digest, _)| digest).collect();

    let fallback = format!("sha256-{}", digest.hex());
    for kind in Kind::ALL {
        let upstream = cluster.upstream(kind);
        assert_eq!(upstream.digest(SIGNED).unwrap(), digest, "{kind:?}");
        let tags = upstream
            .regctl(&format!(
                "regctl tag ls {}/{REPOSITORY}",
                upstream.address()
            ))
            .unwrap();
        for suffix in [".sig", ".att"] {
            let tag = format!("{fallback}{suffix}");
            assert!(
                tags.lines().any(|t| t == tag),
                "{kind:?} has no {tag}: {tags}"
            );
            let (status, _) = get(
                &cluster,
                &node,
                &upstream,
                kind,
                &format!("/v2/{REPOSITORY}/manifests/{tag}"),
            );
            assert_eq!(status, 200, "{kind:?}: {tag}");
        }
        if kind == Kind::Referrers {
            continue;
        }
        let (status, body) = get(
            &cluster,
            &node,
            &upstream,
            kind,
            &format!("/v2/{REPOSITORY}/referrers/{digest}"),
        );
        assert_eq!(status, 404, "{kind:?}: {body}");
        let (status, index) = get(
            &cluster,
            &node,
            &upstream,
            kind,
            &format!("/v2/{REPOSITORY}/manifests/{fallback}"),
        );
        assert_eq!(status, 200, "{kind:?}: {index}");
        let listed: BTreeSet<String> = listed(&index)
            .into_iter()
            .map(|(digest, _)| digest)
            .collect();
        assert_eq!(
            listed.iter().collect::<BTreeSet<_>>(),
            digests,
            "{kind:?}: {index}"
        );
    }
    // The unsigned image has no fallback tag.
    let plain = cluster.upstream(Kind::Plain);
    let unsigned = plain.digest(UNSIGNED).unwrap();
    let (status, _) = get(
        &cluster,
        &node,
        &plain,
        Kind::Plain,
        &format!("/v2/e2e/unsigned/manifests/sha256-{}", unsigned.hex()),
    );
    assert_eq!(status, 404);
    // Each request names its client.
    let requests = plain.requests().unwrap();
    assert!(
        requests
            .iter()
            .any(|r| r.status == 404 && r.user_agent.starts_with("curl/")),
        "{requests:?}"
    );
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_proxy_answers_429_with_retry_after_to_what_it_throttles_and_logs_it() {
    let _serial = serial();
    let cluster = Cluster::from_env();
    let node = nodes(&cluster).pop().unwrap();
    let plain = cluster.upstream(Kind::Plain);
    let proxy = Proxy::start("throttle.e2e.test", plain.address(), None, None).unwrap();
    let address = proxy.address();
    let head = format!(
        "curl -sI -A e2e-throttled -H 'Accept: application/vnd.oci.image.manifest.v1+json' http://{address}/v2/{REPOSITORY}/manifests/1 | tr -d '\\r'"
    );
    proxy
        .throttle("/manifests/", Duration::from_secs(7), Some(1))
        .unwrap();
    let throttled = sh(&cluster, &node, &head).stdout;
    assert!(throttled.starts_with("HTTP/1.1 429"), "{throttled}");
    assert!(
        throttled
            .lines()
            .any(|l| l.eq_ignore_ascii_case("retry-after: 7")),
        "{throttled}"
    );
    // One time only, then the request goes through; and none goes through while it is on for every request.
    let passed = sh(&cluster, &node, &head).stdout;
    assert!(passed.starts_with("HTTP/1.1 200"), "{passed}");
    proxy
        .throttle("/manifests/", Duration::from_secs(1), None)
        .unwrap();
    for _ in 0..2 {
        assert!(
            sh(&cluster, &node, &head)
                .stdout
                .starts_with("HTTP/1.1 429")
        );
    }
    proxy.unthrottle().unwrap();
    assert!(
        sh(&cluster, &node, &head)
            .stdout
            .starts_with("HTTP/1.1 200")
    );

    let requests = proxy.requests().unwrap();
    let statuses: Vec<u16> = requests.iter().map(|r| r.status).collect();
    assert_eq!(statuses, [429, 200, 429, 429, 200], "{requests:?}");
    assert!(
        requests
            .iter()
            .all(|r| r.method == "HEAD" && r.user_agent == "e2e-throttled"),
        "{requests:?}"
    );
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_rejected_upstream_fails_at_once_from_its_node_only() {
    let _serial = serial();
    let cluster = Cluster::from_env();
    let nodes = nodes(&cluster);
    let (a, b) = (&nodes[0], &nodes[nodes.len() - 1]);
    let plain = cluster.upstream(Kind::Plain);
    let curl = format!("curl -sf -m 10 -o /dev/null http://{}/v2/", plain.address());
    {
        let _rejected = cluster.reject(b, plain.address()).unwrap();
        let start = Instant::now();
        let from_b = sh(&cluster, b, &curl);
        assert!(!from_b.success, "{from_b:?}");
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "{:?}",
            start.elapsed()
        );
        assert!(sh(&cluster, a, &curl).success);
    }
    assert!(sh(&cluster, b, &curl).success, "the rules are gone");
}
