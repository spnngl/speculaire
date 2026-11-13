//! The peer API serves what a node holds to the agents of other nodes, over mutual TLS with kubelet certificates
//! (D14, D16, D100).
//!
//! The second worker pulls; the first reads from its peer API with curl and kubelet's certificate, as another agent
//! would.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use e2e::reflector::KUBELET;
use e2e::upstream::{Digest, Image};
use e2e::{Cluster, Output};

/// The peer API's port when `peer.address` is `"auto"` (D36).
const PEER_PORT: u16 = 7481;

/// The node `suffix` names: `-worker` or `-worker2`.
fn node(cluster: &Cluster, suffix: &str) -> String {
    cluster
        .nodes()
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .find(|name| name.ends_with(suffix))
        .expect("a node of each name")
}

/// A new image of the upstream with a layer of 1 MiB, pulled on `holder`.
fn pulled(cluster: &Cluster, holder: &str) -> Image {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let image = cluster
        .upstream()
        .push(&format!("peer/{nanos}"), 1 << 20)
        .unwrap();
    cluster
        .exec(holder, &["crictl", "pull", &image.reference])
        .unwrap();
    image
}

/// A `GET` of `digest` from `from` on the peer API at `address`, with curl's `options`: the status and the length and
/// SHA-256 of the body, as `"<status> <length> <sha256>"`, or the failure.
fn get(
    cluster: &Cluster,
    from: &str,
    address: SocketAddr,
    digest: &Digest,
    options: &str,
) -> Output {
    // The peer API presents a kubelet client certificate, which has no name to check: `-k` (D16).
    let script = format!(
        r#"set -e; body=$(mktemp); trap 'rm -f "$body"' EXIT
code=$(curl -sSg -k --max-time 10 {options} -o "$body" -w '%{{http_code}}' https://{address}/v2/e2e/peer/blobs/{digest})
echo "$code $(wc -c < "$body" | tr -d ' ') $(sha256sum < "$body" | cut -d' ' -f1)""#
    );
    cluster.exec_output(from, &["sh", "-c", &script]).unwrap()
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn another_node_reads_a_blob_with_its_kubelet_certificate_and_a_client_without_one_is_refused() {
    let cluster = Cluster::from_env();
    let (holder, reader) = (node(&cluster, "-worker2"), node(&cluster, "-worker"));
    let image = pulled(&cluster, &holder);
    let address = SocketAddr::new(cluster.family_address(&holder).unwrap(), PEER_PORT);
    let layer = &image.blobs[1];
    let cert = format!("--cert {KUBELET}");

    let whole = get(&cluster, &reader, address, layer, &cert);
    assert!(whole.success, "{}", whole.stderr);
    let fields: Vec<&str> = whole.stdout.split_whitespace().collect();
    assert_eq!(
        (fields[0], fields[2]),
        ("200", layer.hex()),
        "{layer} from {address}"
    );
    let part = get(
        &cluster,
        &reader,
        address,
        layer,
        &format!("{cert} -H 'Range: bytes=0-99'"),
    );
    assert!(part.success, "{}", part.stderr);
    assert!(part.stdout.starts_with("206 100 "), "{}", part.stdout);

    // No certificate, then a client certificate of the cluster CA that is not a node's: kube-apiserver's.
    let anonymous = get(&cluster, &reader, address, layer, "");
    assert!(!anonymous.success, "{}", anonymous.stdout);
    let [control_plane, _] = cluster.reflectors();
    let apiserver = get(
        &cluster,
        &control_plane,
        address,
        layer,
        "--cert /etc/kubernetes/pki/apiserver-kubelet-client.crt --key /etc/kubernetes/pki/apiserver-kubelet-client.key",
    );
    assert!(!apiserver.success, "{}", apiserver.stdout);

    cluster
        .exec(&holder, &["crictl", "rmi", &image.reference])
        .unwrap();
}
