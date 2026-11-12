//! `configure`, `unconfigure` and `check` of containerd on a temporary tree standing for a node's root.

use std::os::unix::fs::MetadataExt;

use speculaire_pki::mirror::Mirror;

use crate::containerd::Containerd;
use crate::detect::Runtime;
use crate::files::Change;
use crate::fixture::{Tree, now, put};
use crate::paths::Paths;
use crate::wiring::Error;

const DOCKER_IO: &str = "# docker.io, through the corporate proxy\nserver = \"https://registry-1.docker.io\"\n\n[host.\"https://proxy.corp\"]\n  capabilities = [\"pull\", \"resolve\"]\n";

fn node() -> Tree {
    Tree::new(Runtime::Containerd)
}

#[test]
fn configure_makes_the_certificates_and_puts_the_mirror_first_in_every_hosts_toml() {
    let node = node();
    node.containerd();
    put(&node.certs_d().join("docker.io/hosts.toml"), DOCKER_IO);
    let report = node.configure().unwrap();
    let tree = node.tree();
    let mirror = node.dir.path().join("var/lib/speculaire/mirror");
    for (name, mode) in [
        ("ca.crt", 0o644),
        ("server.crt", 0o644),
        ("server.key", 0o600),
        ("client.pem", 0o600),
    ] {
        assert_eq!(tree[&mirror.join(name)].1, mode, "{name}");
    }
    let docker =
        String::from_utf8(tree[&node.certs_d().join("docker.io/hosts.toml")].0.clone()).unwrap();
    insta::assert_snapshot!(
        "node-docker-io",
        docker.replace(node.dir.path().to_str().unwrap(), "<root>")
    );
    let default =
        String::from_utf8(tree[&node.certs_d().join("_default/hosts.toml")].0.clone()).unwrap();
    insta::assert_snapshot!(
        "node-default",
        default.replace(node.dir.path().to_str().unwrap(), "<root>")
    );
    assert_eq!(
        report.changes.len(),
        4 + 2,
        "four certificates, two hosts.toml"
    );
    assert_eq!(
        node.reloads(),
        0,
        "containerd reads hosts.toml on every pull"
    );
    assert_eq!(node.check(), Vec::<String>::new());
}

#[test]
fn a_second_run_changes_nothing_byte_for_byte() {
    let node = node();
    node.containerd();
    put(&node.certs_d().join("docker.io/hosts.toml"), DOCKER_IO);
    node.configure().unwrap();
    let once = node.tree();
    let report = node.configure().unwrap();
    assert_eq!(report.changes, []);
    assert_eq!(node.tree(), once);
    node.unconfigure().unwrap();
    let off = node.tree();
    let report = node.unconfigure().unwrap();
    assert_eq!(report.changes, []);
    assert_eq!(node.tree(), off);
}

#[test]
fn unconfigure_removes_what_configure_added_and_keeps_the_admins_edits() {
    let node = node();
    node.containerd();
    let docker = put(&node.certs_d().join("docker.io/hosts.toml"), DOCKER_IO);
    let before = node.tree();
    node.configure().unwrap();
    // An edit made after `configure`.
    let edited = std::fs::read_to_string(&docker).unwrap().replace(
        "pull\", \"resolve\"]\n",
        "pull\", \"resolve\"]\n  skip_verify = true\n",
    );
    std::fs::write(&docker, &edited).unwrap();
    let report = node.unconfigure().unwrap();
    let after = node.tree();
    assert_eq!(
        String::from_utf8(after[&docker].0.clone()).unwrap(),
        DOCKER_IO.replace(
            "pull\", \"resolve\"]\n",
            "pull\", \"resolve\"]\n  skip_verify = true\n"
        )
    );
    assert!(
        !node.certs_d().join("_default").exists(),
        "the file configure made, and its directory"
    );
    assert!(!node.dir.path().join("var/lib/speculaire/mirror").exists());
    assert!(report.changes.len() >= 6, "{:?}", report.changes);
    // Without the edit, everything is as it was.
    std::fs::write(&docker, DOCKER_IO).unwrap();
    assert_eq!(
        node.tree().keys().collect::<Vec<_>>(),
        before.keys().collect::<Vec<_>>()
    );
}

#[test]
fn a_new_address_moves_the_entries_and_the_certificates_follow() {
    let mut node = node();
    node.containerd();
    put(&node.certs_d().join("docker.io/hosts.toml"), DOCKER_IO);
    node.configure().unwrap();
    let ca_before = node.tree()[&node.dir.path().join("var/lib/speculaire/mirror/ca.crt")]
        .0
        .clone();
    node.target.address = "127.0.0.2:7481".parse().unwrap();
    assert!(
        node.check()
            .iter()
            .any(|p| p.contains("hosts.toml") && p.contains("127.0.0.2:7481")),
        "check names the files that still point at the old address"
    );
    node.configure().unwrap();
    let tree = node.tree();
    let docker =
        String::from_utf8(tree[&node.certs_d().join("docker.io/hosts.toml")].0.clone()).unwrap();
    assert!(
        docker.contains("127.0.0.2:7481") && !docker.contains("127.0.0.1:7480"),
        "{docker}"
    );
    assert_ne!(
        tree[&node.dir.path().join("var/lib/speculaire/mirror/ca.crt")].0,
        ca_before
    );
    assert_eq!(node.check(), Vec::<String>::new());
    node.unconfigure().unwrap();
    let docker = std::fs::read_to_string(node.certs_d().join("docker.io/hosts.toml")).unwrap();
    assert_eq!(docker, DOCKER_IO);
}

#[test]
fn check_names_the_file_that_lacks_the_entry_or_the_certificate() {
    let node = node();
    node.containerd();
    put(&node.certs_d().join("docker.io/hosts.toml"), DOCKER_IO);
    // Before `configure`: the hosts.toml lacks the entry, `_default` is missing, and so are the certificates.
    let problems = node.check();
    assert_eq!(problems.len(), 3, "{problems:#?}");
    assert!(
        problems[0]
            .starts_with("/etc/containerd/certs.d/docker.io/hosts.toml: lacks the mirror entry"),
        "{problems:#?}"
    );
    assert!(
        problems[1].starts_with("/etc/containerd/certs.d/_default/hosts.toml: is missing"),
        "{problems:#?}"
    );
    assert!(
        problems[2].starts_with("/var/lib/speculaire/mirror/ca.crt: is missing"),
        "{problems:#?}"
    );

    node.configure().unwrap();
    assert_eq!(node.check(), Vec::<String>::new());
    std::fs::write(node.certs_d().join("docker.io/hosts.toml"), DOCKER_IO).unwrap();
    let problems = node.check();
    assert_eq!(problems.len(), 1);
    assert!(
        problems[0].contains("docker.io/hosts.toml: lacks the mirror entry"),
        "{problems:#?}"
    );
    node.configure().unwrap();
    std::fs::remove_file(node.dir.path().join("var/lib/speculaire/mirror/server.key")).unwrap();
    let problems = node.check();
    assert!(
        problems[0].starts_with("/var/lib/speculaire/mirror/server.key: is missing"),
        "{problems:#?}"
    );
    // A certificate for another address, and one that the CA did not sign.
    node.configure().unwrap();
    let ca = node.dir.path().join("var/lib/speculaire/mirror/ca.crt");
    let other = Mirror::generate("127.0.0.1".parse().unwrap(), now()).unwrap();
    std::fs::write(&ca, other.ca()).unwrap();
    let problems = node.check();
    assert!(
        problems[0].contains("server.crt: is not signed by the CA"),
        "{problems:#?}"
    );
    // And configure repairs it.
    node.configure().unwrap();
    assert_eq!(node.check(), Vec::<String>::new());
}

#[test]
fn a_key_that_was_readable_by_others_ends_at_0600() {
    let node = node();
    node.containerd();
    node.configure().unwrap();
    let key = node.dir.path().join("var/lib/speculaire/mirror/server.key");
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o666)).unwrap();
    let report = node.configure().unwrap();
    assert_eq!(report.changes, [Change::Updated(key.clone())]);
    assert_eq!(std::fs::metadata(&key).unwrap().mode() & 0o7777, 0o600);
}

#[test]
fn a_config_containerd_would_refuse_or_a_file_that_is_not_toml_changes_nothing() {
    let node = node();
    put(
        &node.containerd_config(),
        "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry.mirrors.\"docker.io\"]\n  endpoint = [\"https://m\"]\n",
    );
    let err = node.configure().unwrap_err();
    assert!(matches!(err, Error::LegacyMirrors(_)), "{err}");
    assert!(err.to_string().contains("config.toml"), "{err}");
    assert!(!node.dir.path().join("var").exists());

    let node = self::node();
    node.containerd();
    put(&node.certs_d().join("docker.io/hosts.toml"), "[host\n");
    let err = node.configure().unwrap_err();
    assert!(matches!(err, Error::Edit { .. }), "{err}");
    assert!(err.to_string().contains("docker.io/hosts.toml"), "{err}");
    assert!(
        !node.dir.path().join("var").exists(),
        "no certificate was made"
    );
    assert!(!node.certs_d().join("_default").exists());
    let problems = node.check_all().unwrap();
    assert!(
        problems
            .iter()
            .any(|p| p.path.ends_with("docker.io/hosts.toml")),
        "{problems:?}"
    );
}

#[test]
fn without_a_config_file_containerd_runs_on_its_defaults() {
    let node = node();
    let docker = put(
        &node
            .dir
            .path()
            .join("etc/docker/certs.d/quay.io/hosts.toml"),
        "server = \"https://quay.io\"\n",
    );
    node.configure().unwrap();
    assert!(
        node.dir
            .path()
            .join("etc/containerd/certs.d/_default/hosts.toml")
            .is_file()
    );
    assert!(
        std::fs::read_to_string(docker)
            .unwrap()
            .contains("[host.\"https://127.0.0.1:7480\"]")
    );
    assert_eq!(node.check(), Vec::<String>::new());
}

#[test]
fn without_a_config_file_unconfigure_works_but_a_config_that_cannot_be_read_is_an_error() {
    let node = node();
    node.configure().unwrap();
    // No `config.toml`: containerd's defaults.
    node.unconfigure().unwrap();
    assert!(!node.dir.path().join("var/lib/speculaire/mirror").exists());
    // A `config.toml` that cannot be read is not the same as none.
    std::fs::create_dir_all(node.containerd_config()).unwrap();
    let err = node.unconfigure().unwrap_err();
    assert!(matches!(err, Error::Containerd { .. }), "{err}");
    let err = node.configure().unwrap_err();
    assert!(matches!(err, Error::Containerd { .. }), "{err}");
}

#[test]
fn a_missing_import_is_an_error_and_not_a_config_that_is_missing() {
    let node = node();
    put(
        &node.containerd_config(),
        "version = 2\nimports = [\"/nonexistent/conf.d/x.toml\"]\n",
    );
    let err = node.configure().unwrap_err();
    assert!(matches!(err, Error::Containerd { .. }), "{err}");
    assert!(err.to_string().contains("config.toml"), "{err}");
}

#[test]
fn directories_that_are_left_alone_are_noted() {
    let node = node();
    node.containerd();
    put(&node.certs_d().join("private.example/ca.crt"), "pem");
    let report = node.configure().unwrap();
    assert_eq!(report.notes.len(), 1, "{:?}", report.notes);
    assert!(
        report.notes[0].contains("private.example: left alone"),
        "{:?}",
        report.notes
    );
}

#[test]
fn the_containerd_config_can_be_somewhere_else() {
    let node = node();
    let elsewhere = node.dir.path().join("other/config.toml");
    let socket = node.node.socket();
    let moved = Containerd::new(
        Paths::under(node.dir.path()),
        socket,
        Some(elsewhere.clone()),
    );
    assert_eq!(moved.config(), elsewhere);
    assert_eq!(
        Containerd::new(Paths::under(node.dir.path()), socket, None).config(),
        node.dir.path().join("etc/containerd/config.toml")
    );
    assert_eq!(
        Containerd::new(Paths::system(), socket, None).config(),
        std::path::PathBuf::from("/etc/containerd/config.toml")
    );
}
