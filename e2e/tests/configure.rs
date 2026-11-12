//! `speculaire configure`, `unconfigure` and `check-config` on the nodes (D32, D55, D56, D64, D66).
//!
//! `just e2e-up` ran `configure` on every node before it started the agent. These tests change a worker's runtime
//! config and put it back, so they run one at a time.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use e2e::{Cluster, Runtime};

static SERIAL: Mutex<()> = Mutex::new(());

/// Held by each test: they change the same nodes.
fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

const MIRROR_DIR: &str = "/var/lib/speculaire/mirror";
const CONTAINERD_SOCKET: &str = "/run/containerd/containerd.sock";
const CRIO_SOCKET: &str = "/var/run/crio/crio.sock";
/// An image no other suite pulls, so that a pull really pulls.
const IMAGE: &str = "docker.io/library/busybox:1.36.1";

fn sh(cluster: &Cluster, node: &str, script: &str) -> String {
    cluster.exec(node, &["sh", "-c", script]).unwrap()
}

fn workers(cluster: &Cluster) -> Vec<String> {
    cluster
        .nodes()
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .filter(|name| !name.contains("control-plane"))
        .collect()
}

/// The directories `configure` writes in, for the node's runtime.
fn directories(cluster: &Cluster) -> String {
    match cluster.runtime() {
        Runtime::Containerd => format!("/etc/containerd/certs.d {MIRROR_DIR}"),
        Runtime::Crio => {
            format!("/etc/containers/registries.conf.d /etc/containers/certs.d {MIRROR_DIR}")
        }
    }
}

/// Every file `configure` writes, with its mode and SHA-256.
fn state(cluster: &Cluster, node: &str) -> String {
    sh(
        cluster,
        node,
        &format!(
            "find {} -type f | sort | while read -r f; do echo \"$(stat -c '%a %n' \"$f\") $(sha256sum < \"$f\")\"; done",
            directories(cluster)
        ),
    )
}

fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(90);
    while !ready() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// The three commands against a node, with what each wrote to stderr; each must have failed.
fn refusals(cluster: &Cluster, node: &str) -> Vec<String> {
    ["configure", "unconfigure", "check-config"]
        .into_iter()
        .map(|command| {
            let out = cluster.exec_output(node, &["speculaire", command]).unwrap();
            assert!(!out.success, "{node}: {command} went on: {out:?}");
            out.stderr
        })
        .collect()
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn configure_ran_before_the_agent_and_a_second_run_changes_nothing() {
    let _serial = serial();
    let cluster = Cluster::from_env();
    for node in cluster.nodes().unwrap() {
        let node = node.name;
        let before = state(&cluster, &node);
        let wanted: &[&str] = match cluster.runtime() {
            Runtime::Containerd => &["/etc/containerd/certs.d/_default/hosts.toml"],
            Runtime::Crio => &[
                "/etc/containers/registries.conf.d/99-speculaire.conf",
                "/etc/containers/certs.d/127.0.0.1:7480/ca.crt",
                "/etc/containers/certs.d/127.0.0.1:7480/client.cert",
                "/etc/containers/certs.d/127.0.0.1:7480/client.key",
            ],
        };
        for file in wanted.iter().chain(&[
            "/var/lib/speculaire/mirror/ca.crt",
            "/var/lib/speculaire/mirror/server.crt",
        ]) {
            assert!(before.contains(file), "{node}: no {file} in\n{before}");
        }
        // A key ends at 0600, whoever else could read the directory (D55).
        for key in ["server.key", "client.pem"] {
            let mode = sh(&cluster, &node, &format!("stat -c %a {MIRROR_DIR}/{key}"));
            assert_eq!(mode.trim(), "600", "{node}: {key}");
        }
        let out = cluster.exec(&node, &["speculaire", "configure"]).unwrap();
        assert_eq!(out, "", "{node}: a second run reported changes");
        assert_eq!(state(&cluster, &node), before, "{node}");
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn crio_applied_the_new_registry_configuration() {
    let cluster = Cluster::from_env();
    if cluster.runtime() != Runtime::Crio {
        return;
    }
    for node in cluster.nodes().unwrap() {
        let logged = sh(
            &cluster,
            &node.name,
            "journalctl -u crio --no-pager | grep -c 'Applied new registry configuration' || true",
        );
        assert!(
            logged.trim() != "0",
            "{}: CRI-O never reloaded its registries",
            node.name
        );
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn check_config_passes_and_names_the_file_that_lacks_the_entry() {
    let _serial = serial();
    let cluster = Cluster::from_env();
    let node = workers(&cluster).remove(0);
    let check = || {
        cluster
            .exec_output(&node, &["speculaire", "check-config"])
            .unwrap()
    };
    let ok = check();
    assert!(ok.success, "{ok:?}");

    let (file, damage, repair) = match cluster.runtime() {
        Runtime::Containerd => (
            "/etc/containerd/certs.d/_default/hosts.toml",
            "rm /etc/containerd/certs.d/_default/hosts.toml".to_owned(),
            "true".to_owned(),
        ),
        Runtime::Crio => (
            "/etc/containers/registries.conf.d/99-speculaire.conf",
            // A file that loads after the drop-in replaces its entry for docker.io (D66).
            "printf '[[registry]]\\nprefix = \"docker.io\"\\nlocation = \"docker.io\"\\n' > /etc/containers/registries.conf.d/999-admin.conf"
                .to_owned(),
            "rm -f /etc/containers/registries.conf.d/999-admin.conf".to_owned(),
        ),
    };
    sh(&cluster, &node, &damage);
    let bad = check();
    sh(&cluster, &node, &repair);
    assert!(!bad.success, "{bad:?}");
    assert!(bad.stderr.contains(file), "{}", bad.stderr);
    if cluster.runtime() == Runtime::Containerd {
        assert!(
            cluster
                .exec(&node, &["speculaire", "configure"])
                .unwrap()
                .contains(file)
        );
    }
    assert!(check().success);

    if cluster.runtime() == Runtime::Crio {
        // Without the drop-in at all.
        sh(&cluster, &node, &format!("rm {file}"));
        let bad = check();
        cluster.exec(&node, &["speculaire", "configure"]).unwrap();
        assert!(!bad.success && bad.stderr.contains(file), "{bad:?}");
        assert!(check().success);
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn unconfigure_refuses_while_the_plugin_is_required() {
    let _serial = serial();
    let cluster = Cluster::from_env();
    let node = workers(&cluster).remove(1);
    let before = state(&cluster, &node);

    // The runtime requires the plugin: unconfigure stops, and changes nothing.
    let (require, unrequire, key) = match cluster.runtime() {
        Runtime::Containerd => (
            "cp /etc/containerd/config.toml /tmp/config.toml.orig && printf '\\n[plugins.\"io.containerd.nri.v1.nri\".default_validator]\\n  enable = true\\n  required_plugins = [\"speculaire\"]\\n' >> /etc/containerd/config.toml",
            "cp /tmp/config.toml.orig /etc/containerd/config.toml",
            "required_plugins",
        ),
        Runtime::Crio => (
            "printf '[crio.nri.default_validator]\\nnri_enable_default_validator = true\\nnri_validator_required_plugins = [\"speculaire\"]\\n' > /etc/crio/crio.conf.d/90-required.conf && systemctl restart crio",
            "rm /etc/crio/crio.conf.d/90-required.conf && systemctl restart crio",
            "nri_validator_required_plugins",
        ),
    };
    let ready = |cluster: &Cluster| {
        wait_until("the runtime", || match cluster.runtime() {
            Runtime::Containerd => cluster
                .exec_output(&node, &["crictl", "version"])
                .is_ok_and(|o| o.success),
            Runtime::Crio => cluster
                .exec_output(
                    &node,
                    &[
                        "sh",
                        "-c",
                        "crictl version && crio status config | grep -q nri",
                    ],
                )
                .is_ok_and(|o| o.success),
        });
    };
    sh(&cluster, &node, require);
    ready(&cluster);
    let refused = cluster
        .exec_output(&node, &["speculaire", "unconfigure"])
        .unwrap();
    let during = state(&cluster, &node);
    sh(&cluster, &node, unrequire);
    ready(&cluster);
    assert!(
        !refused.success && refused.stderr.contains(key),
        "{refused:?}"
    );
    assert_eq!(during, before, "a refused unconfigure removed something");
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn unconfigure_removes_only_its_own_and_pulls_still_work() {
    let _serial = serial();
    let cluster = Cluster::from_env();
    let node = workers(&cluster).remove(1);
    let before = state(&cluster, &node);

    // An admin's own file, edited after `configure`, survives; the certificates and our entries go; pulls work.
    let (admin_file, admin_seed, edit) = match cluster.runtime() {
        Runtime::Containerd => (
            "/etc/containerd/certs.d/docker.io/hosts.toml",
            "mkdir -p /etc/containerd/certs.d/docker.io && printf 'server = \"https://registry-1.docker.io\"\\n' > /etc/containerd/certs.d/docker.io/hosts.toml",
            "printf '# edited by the admin after configure\\n' >> /etc/containerd/certs.d/docker.io/hosts.toml",
        ),
        Runtime::Crio => (
            "/etc/containers/registries.conf.d/50-admin.conf",
            "printf '# the admin\\n' > /etc/containers/registries.conf.d/50-admin.conf",
            "printf '# edited by the admin after configure\\n' >> /etc/containers/registries.conf.d/50-admin.conf",
        ),
    };
    sh(&cluster, &node, admin_seed);
    cluster.exec(&node, &["speculaire", "configure"]).unwrap();
    let configured = sh(&cluster, &node, &format!("cat {admin_file}"));
    if cluster.runtime() == Runtime::Containerd {
        assert!(configured.contains("speculaire configure"), "{configured}");
    }
    sh(&cluster, &node, edit);
    let out = cluster.exec(&node, &["speculaire", "unconfigure"]).unwrap();
    let kept = sh(&cluster, &node, &format!("cat {admin_file}"));
    let left = sh(
        &cluster,
        &node,
        &format!("find {} -type f 2>/dev/null | sort", directories(&cluster)),
    );
    let mirror_dir = sh(&cluster, &node, &format!("ls {MIRROR_DIR} 2>&1 || true"));
    let pull = cluster
        .exec_output(&node, &["crictl", "pull", IMAGE])
        .unwrap();
    sh(
        &cluster,
        &node,
        &format!(
            "crictl rmi {IMAGE}; rm -f {admin_file}; rmdir /etc/containerd/certs.d/docker.io 2>/dev/null; true"
        ),
    );
    cluster.exec(&node, &["speculaire", "configure"]).unwrap();
    assert!(out.contains("removed"), "{out}");
    assert!(
        kept.contains("edited by the admin after configure") && !kept.contains("speculaire"),
        "{kept}"
    );
    assert!(!left.contains("speculaire"), "unconfigure left {left}");
    assert!(!mirror_dir.contains("ca.crt"), "{mirror_dir}");
    assert!(pull.success, "a pull failed after unconfigure: {pull:?}");

    // `configure` puts it all back.
    assert_eq!(
        state(&cluster, &node).lines().count(),
        before.lines().count()
    );
    assert!(
        cluster
            .exec_output(&node, &["speculaire", "check-config"])
            .unwrap()
            .success
    );
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn with_neither_runtime_socket_or_both_all_three_commands_refuse_naming_both() {
    let _serial = serial();
    let cluster = Cluster::from_env();
    let node = workers(&cluster).remove(0);
    let (socket, other) = match cluster.runtime() {
        Runtime::Containerd => (CONTAINERD_SOCKET, CRIO_SOCKET),
        Runtime::Crio => (CRIO_SOCKET, CONTAINERD_SOCKET),
    };

    // Neither: the runtime's socket is moved aside for the moment the commands take.
    let aside = format!("{socket}.aside");
    sh(&cluster, &node, &format!("mv {socket} {aside}"));
    let neither = std::panic::catch_unwind(|| refusals(&cluster, &node));
    sh(&cluster, &node, &format!("mv {aside} {socket}"));
    // Both: a socket where the other runtime's would be.
    sh(&cluster, &node, &format!("mkdir -p $(dirname {other})"));
    cluster
        .exec_output(
            &node,
            &[
                "sh",
                "-c",
                &format!("systemd-socket-activate -l {other} sleep 30 > /dev/null 2>&1 &"),
            ],
        )
        .unwrap();
    wait_until("the other socket", || {
        cluster
            .exec_output(&node, &["test", "-S", other])
            .is_ok_and(|o| o.success)
    });
    let both = std::panic::catch_unwind(|| refusals(&cluster, &node));
    sh(
        &cluster,
        &node,
        &format!("pkill systemd-socket-a; rm -f {other}; true"),
    );

    for stderr in neither.unwrap().into_iter().chain(both.unwrap()) {
        assert!(
            stderr.contains(CONTAINERD_SOCKET) && stderr.contains(CRIO_SOCKET),
            "{stderr}"
        );
    }
    assert!(
        cluster
            .exec_output(&node, &["speculaire", "check-config"])
            .unwrap()
            .success
    );
}
