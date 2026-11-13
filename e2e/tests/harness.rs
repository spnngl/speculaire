//! The peer harness itself (D94): the balancer, the upstream and the node helpers do what the peer suites rely on.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use e2e::balancer::PORT;
use e2e::node::Metrics;
use e2e::{Cluster, IpFamily};

/// The tests share the node no reflector runs on: one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn sh(cluster: &Cluster, node: &str, script: &str) -> String {
    cluster.exec(node, &["sh", "-c", script]).unwrap()
}

/// The node no reflector runs on.
fn client(cluster: &Cluster) -> String {
    let reflectors = cluster.reflectors();
    cluster
        .nodes()
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .find(|name| !reflectors.contains(name))
        .expect("a node with no reflector")
}

/// A listener on the reflectors' port of `node` that answers each connection with the node's name, until it drops.
/// It stands in for the reflector, which listens there from step 02 of M3 on.
struct Responder<'a> {
    cluster: &'a Cluster,
    node: String,
}

impl<'a> Responder<'a> {
    fn start(cluster: &'a Cluster, node: &str) -> Self {
        // Perl, which every Debian has: with `systemd-socket-activate --inetd hostname`, connections on the CI runners
        // closed before the name arrived. `--expand-environment=no` keeps systemd off Perl's `$`.
        let server = format!(
            r#"$s = IO::Socket::IP->new(LocalHost => "::", LocalPort => {PORT}, V6Only => 0, Listen => 64, ReuseAddr => 1) or die $@; chomp($n = `hostname`); while ($c = $s->accept) {{ $c->send("$n\n"); $c->shutdown(1); close $c }}"#
        );
        sh(
            cluster,
            node,
            &format!(
                "systemctl stop e2e-responder 2>/dev/null; systemd-run --unit=e2e-responder --collect --expand-environment=no perl -MIO::Socket::IP -e '{server}'"
            ),
        );
        Self {
            cluster,
            node: node.to_owned(),
        }
    }
}

impl Drop for Responder<'_> {
    fn drop(&mut self) {
        let _ = self
            .cluster
            .exec(&self.node, &["systemctl", "stop", "e2e-responder"]);
    }
}

/// The nodes that answered 6 connections from `client` through the balancer.
fn answers(cluster: &Cluster, client: &str) -> BTreeSet<String> {
    let balancer = cluster.balancer().address().unwrap();
    sh(
        cluster,
        client,
        &format!(
            "for i in 1 2 3 4 5 6; do timeout 5 bash -c 'exec 3<>/dev/tcp/{balancer}/{PORT}; head -1 <&3' || true; done"
        ),
    )
    .lines()
    .map(str::to_owned)
    .collect()
}

/// Waits until the connections through the balancer reach `expected` only: it checks its backends every second.
fn wait_answers(cluster: &Cluster, client: &str, expected: &[&str]) {
    let expected: BTreeSet<String> = expected.iter().map(|&n| n.to_owned()).collect();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let answers = answers(cluster, client);
        if answers == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{answers:?}, not {expected:?}\n{}",
            diagnostics(cluster, client)
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// The responders' units, a connection from `client` to each reflector and to the balancer, and Envoy's log.
fn diagnostics(cluster: &Cluster, client: &str) -> String {
    let connect = |address: &str| {
        sh(
            cluster,
            client,
            &format!(
                "timeout 5 bash -c 'exec 3<>/dev/tcp/{address}/{PORT}; head -1 <&3' 2>&1; echo \"{address}: exit $?\""
            ),
        )
    };
    let nodes = cluster.nodes().unwrap();
    let mut out: Vec<String> = Vec::new();
    for reflector in cluster.reflectors() {
        out.push(sh(
            cluster,
            &reflector,
            &format!("systemctl status e2e-responder 2>&1; ss -ltn | grep {PORT}; true"),
        ));
        let node = nodes.iter().find(|n| n.name == reflector).unwrap();
        out.push(connect(&node.address));
    }
    out.push(connect(&cluster.balancer().address().unwrap().to_string()));
    out.push(cluster.balancer().logs().unwrap_or_else(|e| e.to_string()));
    out.join("\n")
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_balancer_reaches_each_reflector_and_skips_a_stopped_one() {
    let _serial = serial();
    let cluster = Cluster::from_env();
    let client = client(&cluster);
    let [first, second] = cluster.reflectors();
    let _responders = [
        Responder::start(&cluster, &first),
        Responder::start(&cluster, &second),
    ];
    wait_answers(&cluster, &client, &[&first, &second]);
    let balancer = cluster.balancer();
    {
        let _stopped = balancer.stop(&first).unwrap();
        wait_answers(&cluster, &client, &[&second]);
    }
    wait_answers(&cluster, &client, &[&first, &second]);
    let _stopped = balancer.stop(&second).unwrap();
    wait_answers(&cluster, &client, &[&first]);
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn every_agent_dials_the_balancer_and_knows_the_reflectors_on_the_family_addresses() {
    let cluster = Cluster::from_env();
    let balancer = cluster.balancer().address().unwrap();
    let nodes = cluster.nodes().unwrap();
    assert_eq!(nodes.len(), 3);
    let dual = cluster.ip_family() == IpFamily::Dual;
    assert_eq!(balancer.is_ipv6(), dual, "{balancer}");
    let url = match balancer {
        IpAddr::V4(a) => format!("\nurl = \"https://{a}:{PORT}\"\n"),
        IpAddr::V6(a) => format!("\nurl = \"https://[{a}]:{PORT}\"\n"),
    };
    let reflectors = cluster.reflectors();
    let members: Vec<String> = reflectors
        .iter()
        .map(|reflector| {
            let node = nodes.iter().find(|n| &n.name == reflector).unwrap();
            let address = match &node.ipv6 {
                Some(ipv6) if dual => format!("[{ipv6}]"),
                _ => node.address.clone(),
            };
            format!("{{ node = \"{reflector}\", address = \"{address}:{PORT}\" }}")
        })
        .collect();
    let members = format!("\nmembers = [{}]\n", members.join(", "));
    for node in &nodes {
        assert_eq!(node.ipv6.is_some(), dual, "{}", node.name);
        let config = sh(&cluster, &node.name, "cat /etc/speculaire/config.toml");
        assert!(config.contains(&url), "{}: no {url}", node.name);
        assert!(config.contains(&members), "{}: no {members}", node.name);
        assert_eq!(
            config.contains("\nrole = \"reflector\"\n"),
            reflectors.contains(&node.name),
            "{}",
            node.name
        );
    }
}

/// The blob requests of the runtime to the node's mirror.
fn blob_requests(metrics: &Metrics) -> f64 {
    ["served", "fall_through"]
        .iter()
        .filter_map(|result| {
            metrics.get(&format!(
                r#"speculaire_mirror_requests_total{{kind="blob",result="{result}"}}"#
            ))
        })
        .sum()
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_pull_gets_each_blob_of_a_new_image_from_the_upstream_once() {
    let _serial = serial();
    let cluster = Cluster::from_env();
    let client = client(&cluster);
    let upstream = cluster.upstream();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let image = upstream.push(&format!("harness/{nanos}"), 1 << 20).unwrap();
    assert_eq!(image.blobs.len(), 2, "a config and a layer");
    let before = blob_requests(&cluster.metrics(&client).unwrap());
    sh(
        &cluster,
        &client,
        &format!("crictl pull {}", image.reference),
    );
    let gets = upstream.blob_gets(&image).unwrap();
    assert!(gets.values().all(|&n| n == 1), "{gets:?}");
    assert!(blob_requests(&cluster.metrics(&client).unwrap()) > before);
    // The layer, as the node would serve it to a peer, no longer matches its digest.
    let layer = &image.blobs[1];
    let sum = format!("sha256sum {} | cut -d' ' -f1", cluster.blob_path(layer));
    assert_eq!(sh(&cluster, &client, &sum).trim(), layer.hex());
    cluster.corrupt_blob(&client, layer).unwrap();
    assert_ne!(sh(&cluster, &client, &sum).trim(), layer.hex());
    sh(
        &cluster,
        &client,
        &format!("crictl rmi {}", image.reference),
    );
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn netem_delays_what_leaves_a_node() {
    let _serial = serial();
    let cluster = Cluster::from_env();
    let client = client(&cluster);
    let [reflector, _] = cluster.reflectors();
    let target = cluster
        .nodes()
        .unwrap()
        .into_iter()
        .find(|n| n.name == reflector)
        .unwrap()
        .address;
    // The TCP handshake with the kubelet, in seconds.
    let connect = || -> f64 {
        sh(
            &cluster,
            &client,
            &format!("curl -sk -o /dev/null -w '%{{time_connect}}' https://{target}:10250/"),
        )
        .trim()
        .parse()
        .unwrap()
    };
    {
        let _netem = cluster.netem(&client, "delay 300ms").unwrap();
        let slow = connect();
        assert!(slow >= 0.3, "{slow} s");
    }
    let fast = connect();
    assert!(fast < 0.3, "{fast} s");
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn an_agent_stops_starts_and_comes_back_after_a_kill() {
    let _serial = serial();
    let cluster = Cluster::from_env();
    let client = client(&cluster);
    let ready = || {
        cluster
            .exec_output(
                &client,
                &[
                    "curl",
                    "-sf",
                    "-o",
                    "/dev/null",
                    "http://127.0.0.1:7482/readyz",
                ],
            )
            .unwrap()
            .success
    };
    cluster.stop_agent(&client).unwrap();
    assert!(!ready());
    cluster.start_agent(&client).unwrap();
    assert!(ready());
    let pid = || {
        sh(
            &cluster,
            &client,
            "systemctl show -p MainPID --value speculaire",
        )
    };
    let killed = pid();
    cluster.kill_agent(&client).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while [killed.as_str(), "0\n"].contains(&pid().as_str()) {
        assert!(
            Instant::now() < deadline,
            "systemd did not restart the agent"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    cluster.wait_ready(&client).unwrap();
    cluster.reset_agent(&client).unwrap();
}
