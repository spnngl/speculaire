//! The reflectors of the control plane and the first worker (D2, D16, D97): reached through the balancer, closed to
//! any certificate but a node's, and following kubelet's certificate rotation.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use e2e::Cluster;
use e2e::balancer::PORT;
use e2e::reflector::{Answer, KUBELET};

fn sh(cluster: &Cluster, node: &str, script: &str) -> String {
    cluster.exec(node, &["sh", "-c", script]).unwrap()
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn every_node_gets_the_members_through_the_balancer_and_another_certificate_is_refused() {
    let cluster = Cluster::from_env();
    let reflectors = cluster.reflectors();
    let balancer = SocketAddr::new(cluster.balancer().address().unwrap(), PORT);
    for node in cluster.nodes().unwrap() {
        let answer = cluster
            .members(&node.name, balancer, KUBELET, None)
            .unwrap();
        assert!(reflectors.contains(&answer.node), "{answer:?}");
        for reflector in &reflectors {
            assert!(answer.members.contains(reflector.as_str()), "{answer:?}");
        }
    }
    // The apiserver's kubelet client certificate chains to the cluster CA and has `clientAuth`, but no
    // `O=system:nodes`. TLS 1.3 ends the client's handshake before the server checks it: the refusal is an alert on
    // the first read.
    let [first, _] = &reflectors;
    let refused = cluster
        .members(
            first,
            balancer,
            "/etc/kubernetes/pki/apiserver-kubelet-client.crt",
            Some("/etc/kubernetes/pki/apiserver-kubelet-client.key"),
        )
        .unwrap_err();
    assert!(refused.to_string().contains("alert"), "{refused}");
}

/// kubelet's certificate of `node` replaced by a fresh pair of the cluster CA, as kubelet rotates it: a new dated
/// file, then the link renamed over. The previous pair is back when this drops.
struct Rotated<'a> {
    cluster: &'a Cluster,
    node: String,
    previous: String,
    /// The new certificate's serial number, as `openssl x509 -serial` prints it.
    serial: String,
}

impl<'a> Rotated<'a> {
    /// Needs the cluster CA's key: on the control plane only.
    fn new(cluster: &'a Cluster, node: &str) -> Self {
        let out = sh(
            cluster,
            node,
            &format!(
                r#"set -e; cd /var/lib/kubelet/pki; previous=$(readlink kubelet-client-current.pem)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$work/key" \
  -subj "/O=system:nodes/CN=system:node:{node}" -out "$work/csr" 2>/dev/null
printf 'keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' >"$work/ext"
openssl x509 -req -in "$work/csr" -CA /etc/kubernetes/pki/ca.crt -CAkey /etc/kubernetes/pki/ca.key \
  -set_serial "0x$(openssl rand -hex 16)" -days 1 -extfile "$work/ext" -out "$work/crt" 2>/dev/null
cat "$work/crt" "$work/key" >kubelet-client-e2e-rotated.pem
ln -sfn "$PWD/kubelet-client-e2e-rotated.pem" "$work/link"; mv -T "$work/link" kubelet-client-current.pem
echo "$previous"; openssl x509 -in kubelet-client-current.pem -noout -serial"#
            ),
        );
        let mut lines = out.lines();
        let previous = lines.next().unwrap().to_owned();
        let serial = lines
            .next()
            .and_then(|line| line.strip_prefix("serial="))
            .unwrap()
            .to_owned();
        Self {
            cluster,
            node: node.to_owned(),
            previous,
            serial,
        }
    }
}

impl Drop for Rotated<'_> {
    fn drop(&mut self) {
        let _ = self.cluster.exec(
            &self.node,
            &[
                "sh",
                "-c",
                &format!(
                    "cd /var/lib/kubelet/pki && ln -sfn {} link.e2e && mv -T link.e2e kubelet-client-current.pem && rm -f kubelet-client-e2e-rotated.pem",
                    self.previous
                ),
            ],
        );
    }
}

/// Whether two serial numbers, as curl and openssl print them, are the same.
fn same_serial(a: &str, b: &str) -> bool {
    let digits = |s: &str| {
        s.to_ascii_lowercase()
            .replace(':', "")
            .trim_start_matches('0')
            .to_owned()
    };
    digits(a) == digits(b)
}

/// Calls `Members` on `address` from `node` until the reflector presents `serial`; every call must succeed.
fn wait_serial(cluster: &Cluster, node: &str, address: SocketAddr, serial: &str) -> Answer {
    // The agent reads the file again at its next poll, 10 s in the e2e config.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let answer = cluster.members(node, address, KUBELET, None).unwrap();
        if same_serial(&answer.serial, serial) {
            return answer;
        }
        assert!(Instant::now() < deadline, "{answer:?}, not serial {serial}");
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_reflector_presents_its_rotated_kubelet_certificate_without_a_restart() {
    let cluster = Cluster::from_env();
    let [reflector, _] = cluster.reflectors();
    let node = cluster
        .nodes()
        .unwrap()
        .into_iter()
        .find(|n| n.name == reflector)
        .unwrap();
    let address = SocketAddr::new(node.address.parse().unwrap(), PORT);
    let pid = || {
        sh(
            &cluster,
            &reflector,
            "systemctl show -p MainPID --value speculaire",
        )
    };
    let before = pid();
    let first = cluster.members(&reflector, address, KUBELET, None).unwrap();
    {
        let rotated = Rotated::new(&cluster, &reflector);
        assert!(!same_serial(&first.serial, &rotated.serial));
        let answer = wait_serial(&cluster, &reflector, address, &rotated.serial);
        assert_eq!(answer.node, reflector);
    }
    wait_serial(&cluster, &reflector, address, &first.serial);
    assert_eq!(pid(), before, "the agent restarted");
}
