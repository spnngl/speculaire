//! `configure`, `unconfigure` and `check` of CRI-O on a temporary tree standing for a node's root.

use std::path::PathBuf;

use super::own_cert_dirs;
use crate::crio::CriO;
use crate::detect::Runtime;
use crate::fixture::{Tree, put};
use crate::paths::Paths;
use crate::wiring::Error;

const REGISTRIES_CONF: &str = "unqualified-search-registries = [\"docker.io\"]\n\n[[registry]]\nprefix = \"docker.io\"\nlocation = \"registry-1.docker.io\"\n[[registry.mirror]]\nlocation = \"mirror.corp:5000/dockerhub\"\n";

fn crio_node() -> Tree {
    let node = Tree::new(Runtime::CriO);
    node.crio(REGISTRIES_CONF);
    node
}

#[test]
fn crio_gets_a_drop_in_certificates_and_a_reload() {
    let node = crio_node();
    let report = node.configure().unwrap();
    let tree = node.tree();
    let dropin = &tree[&node.crio_dropin()];
    insta::assert_snapshot!(
        "crio-node-dropin",
        String::from_utf8(dropin.0.clone()).unwrap()
    );
    let certs = node.crio_certs().join("127.0.0.1:7480");
    for (name, mode) in [
        ("ca.crt", 0o644),
        ("client.cert", 0o644),
        ("client.key", 0o600),
    ] {
        assert_eq!(tree[&certs.join(name)].1, mode, "{name}");
    }
    // The client files are the parts of the combined PEM containerd would read.
    let pem = String::from_utf8(
        tree[&node.dir.path().join("var/lib/speculaire/mirror/client.pem")]
            .0
            .clone(),
    )
    .unwrap();
    let parts = format!(
        "{}{}",
        String::from_utf8(tree[&certs.join("client.cert")].0.clone()).unwrap(),
        String::from_utf8(tree[&certs.join("client.key")].0.clone()).unwrap()
    );
    assert_eq!(pem, parts);
    assert_eq!(node.reloads(), 1);
    assert_eq!(report.notes, [""; 0]);
    assert_eq!(node.check(), Vec::<String>::new());

    let once = node.tree();
    let report = node.configure().unwrap();
    assert_eq!(report.changes, []);
    assert_eq!(node.tree(), once);
    assert_eq!(
        node.reloads(),
        2,
        "a reload that failed before must be able to run again"
    );
}

#[test]
fn crio_check_finds_a_later_file_that_replaces_the_entry_and_an_admin_edit() {
    let node = crio_node();
    node.configure().unwrap();
    let late = put(
        &node
            .dir
            .path()
            .join("etc/containers/registries.conf.d/999-admin.conf"),
        "[[registry]]\nprefix = \"docker.io\"\nlocation = \"registry-1.docker.io\"\n",
    );
    let problems = node.check();
    assert!(
        problems.iter().any(|p| p.starts_with(
            "/etc/containers/registries.conf.d/99-speculaire.conf: the effective entry of docker.io does not have the mirror first"
        )),
        "{problems:#?}"
    );
    // `configure` cannot fix that, and says so.
    let report = node.configure().unwrap();
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("effective entry of docker.io does not have the mirror first")),
        "{:#?}",
        report.notes
    );
    // The drop-in now copies the late file's entry: it is stale once that file goes.
    std::fs::remove_file(late).unwrap();
    assert_eq!(node.check().len(), 2);
    node.configure().unwrap();
    assert_eq!(node.check(), Vec::<String>::new());
    // The admin changes their own entry: the drop-in copied the old one.
    put(
        &node.dir.path().join("etc/containers/registries.conf"),
        &REGISTRIES_CONF.replace("mirror.corp:5000/dockerhub", "mirror2.corp:5000/dockerhub"),
    );
    let problems = node.check();
    assert!(
        problems
            .iter()
            .all(|p| p.starts_with("/etc/containers/registries.conf.d/99-speculaire.conf: ")),
        "{problems:#?}"
    );
    assert!(
        problems
            .iter()
            .any(|p| p.contains("differs from what `speculaire configure` writes")),
        "{problems:#?}"
    );
    node.configure().unwrap();
    assert_eq!(node.check(), Vec::<String>::new());
    // Without the drop-in the check says so once.
    std::fs::remove_file(node.crio_dropin()).unwrap();
    let problems = node.check();
    assert_eq!(problems.len(), 1, "{problems:#?}");
    assert!(
        problems[0].contains("99-speculaire.conf: is missing"),
        "{problems:#?}"
    );
}

#[test]
fn crio_unconfigure_reloads_before_the_certificates_go() {
    let node = crio_node();
    node.configure().unwrap();
    node.watch(&node.crio_certs().join("127.0.0.1:7480/ca.crt"));
    node.forget_seen();
    let admin = put(
        &node
            .dir
            .path()
            .join("etc/containers/registries.conf.d/50-admin.conf"),
        "[[registry]]\nlocation = \"x.example\"\n",
    );
    node.unconfigure().unwrap();
    assert_eq!(
        node.seen(),
        [true],
        "CRI-O reloaded while the certificates were still there"
    );
    let left: Vec<_> = node.tree().keys().cloned().collect();
    assert!(!node.crio_dropin().exists());
    assert!(!node.crio_certs().join("127.0.0.1:7480").exists());
    assert!(!node.dir.path().join("var/lib/speculaire/mirror").exists());
    assert!(
        left.contains(&admin)
            && left.contains(&node.dir.path().join("etc/containers/registries.conf"))
    );
    // Again: the reload runs, and nothing changes.
    let report = node.unconfigure().unwrap();
    assert_eq!(report.changes, []);
    assert_eq!(node.reloads(), 3);
}

#[test]
fn crio_a_new_address_leaves_no_certificates_of_the_old_one() {
    let mut node = crio_node();
    node.configure().unwrap();
    node.target.address = "127.0.0.2:7481".parse().unwrap();
    let problems = node.check();
    assert!(problems.len() >= 2, "{problems:#?}");
    node.configure().unwrap();
    assert!(!node.crio_certs().join("127.0.0.1:7480").exists());
    assert!(node.crio_certs().join("127.0.0.2:7481/ca.crt").is_file());
    let dropin = std::fs::read_to_string(node.crio_dropin()).unwrap();
    assert!(
        dropin.contains("127.0.0.2:7481/registry-1.docker.io") && !dropin.contains("7480"),
        "{dropin}"
    );
    assert_eq!(node.check(), Vec::<String>::new());
    node.unconfigure().unwrap();
    assert!(!node.crio_certs().join("127.0.0.2:7481").exists());
}

#[test]
fn crio_a_failed_reload_is_an_error_and_a_rerun_reloads_again() {
    let node = crio_node();
    node.reload_fails(true);
    let err = node.configure().unwrap_err();
    assert!(matches!(err, Error::Reload(_)), "{err}");
    assert!(node.crio_dropin().is_file());
    node.reload_fails(false);
    node.configure().unwrap();
    assert_eq!(node.reloads(), 2);
    node.reload_fails(true);
    let err = node.unconfigure().unwrap_err();
    assert!(matches!(err, Error::Reload(_)), "{err}");
    assert!(
        node.dir
            .path()
            .join("var/lib/speculaire/mirror/ca.crt")
            .is_file(),
        "the certificates stay while CRI-O may use them"
    );
}

#[test]
fn registries_that_are_left_out_are_noted_and_a_broken_registries_conf_is_an_error() {
    let node = crio_node();
    put(
        &node
            .dir
            .path()
            .join("etc/containers/registries.conf.d/10-block.conf"),
        "[[registry]]\nprefix = \"evil.example\"\nlocation = \"evil.example\"\nblocked = true\n",
    );
    let report = node.configure().unwrap();
    assert_eq!(
        report.notes,
        ["registry evil.example: not mirrored: blocked"]
    );
    put(
        &node
            .dir
            .path()
            .join("etc/containers/registries.conf.d/20-bad.conf"),
        "[[registry\n",
    );
    let err = node.configure().unwrap_err();
    assert!(matches!(err, Error::Registries(_)), "{err}");
    assert!(err.to_string().contains("20-bad.conf"), "{err}");
}

#[test]
fn systemctl_reloads_crio_and_its_failure_is_reported() {
    let node = crio_node();
    let crio = CriO::new(
        Paths::under(node.dir.path()),
        "/nonexistent/crio.sock",
        "/nonexistent/systemctl",
    );
    assert!(crio.reload().is_err());
    let crio = CriO::new(
        Paths::under(node.dir.path()),
        node.node.socket(),
        node.systemctl(),
    );
    crio.reload().unwrap();
    assert_eq!(node.reloads(), 1);
    node.reload_fails(true);
    let err = crio.reload().unwrap_err();
    assert!(err.to_string().contains("systemctl reload crio"), "{err}");
}

#[test]
fn own_cert_dirs_are_those_holding_the_ca_and_a_missing_certs_d_has_none() {
    let dir = tempfile::tempdir().unwrap();
    let certs = dir.path().join("certs.d");
    assert_eq!(own_cert_dirs(&certs, "ca").unwrap(), Vec::<PathBuf>::new());
    put(&certs.join("b:7480/ca.crt"), "ca");
    put(&certs.join("a:7480/ca.crt"), "ca");
    put(&certs.join("other/ca.crt"), "another ca");
    put(&certs.join("no-ca/client.key"), "x");
    assert_eq!(
        own_cert_dirs(&certs, "ca").unwrap(),
        [certs.join("a:7480"), certs.join("b:7480")]
    );
    let file = dir.path().join("file");
    put(&file, "");
    assert!(matches!(own_cert_dirs(&file, "ca"), Err(Error::Io { .. })));
}

#[test]
fn a_later_file_that_keeps_the_mirror_first_but_changes_the_entry_is_named_as_different() {
    let node = crio_node();
    node.configure().unwrap();
    put(
        &node
            .dir
            .path()
            .join("etc/containers/registries.conf.d/999-admin.conf"),
        "[[registry]]\nprefix = \"docker.io\"\nlocation = \"registry-1.docker.io\"\ninsecure = true\n[[registry.mirror]]\nlocation = \"127.0.0.1:7480/registry-1.docker.io\"\npull-from-mirror = \"all\"\n[[registry.mirror]]\nlocation = \"mirror.corp:5000/dockerhub\"\n",
    );
    let problems = node.check();
    assert!(
        problems.iter().any(|p| p.contains(
            "the effective entry of docker.io differs from the admin's, with the mirror first"
        )),
        "{problems:#?}"
    );
}
