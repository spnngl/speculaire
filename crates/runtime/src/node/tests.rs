//! A node of either runtime, through the traits a [`Node`](super::Node) hands out.

use speculaire_oci::reference::Digest;

use super::Fallback;
use crate::content::Content as _;
use crate::detect::Runtime;
use crate::fixture::{Tree, has};

#[test]
fn a_node_says_which_runtime_it_is_and_what_the_mirror_does_for_what_it_lacks() {
    let containerd = Tree::new(Runtime::Containerd);
    assert_eq!(containerd.node.runtime(), Runtime::Containerd);
    assert_eq!(containerd.node.name(), "containerd");
    assert_eq!(containerd.node.fallback(), Fallback::PerBlob);
    assert!(containerd.node.socket().ends_with("containerd.sock"));
    let crio = Tree::new(Runtime::CriO);
    assert_eq!(crio.node.runtime(), Runtime::CriO);
    assert_eq!(crio.node.name(), "cri-o");
    assert_eq!(crio.node.fallback(), Fallback::Relay);
    assert!(crio.node.socket().ends_with("cri-o.sock"));
}

#[tokio::test]
async fn crio_holds_no_content_the_mirror_can_read() {
    let node = Tree::new(Runtime::CriO);
    let digest = Digest::parse(&format!("sha256:{}", "ab".repeat(32))).unwrap();
    assert!(node.node.content().open(&digest).await.unwrap().is_none());
}

#[test]
fn a_node_configure_has_run_on_has_no_problem_on_either_runtime() {
    for runtime in [Runtime::Containerd, Runtime::CriO] {
        let node = Tree::configured(runtime);
        assert_eq!(node.preflight(), Vec::<String>::new(), "{runtime}");
        assert_eq!(node.check(), Vec::<String>::new(), "{runtime}");
    }
}

#[test]
fn missing_certificates_are_named_and_stop_startup() {
    let node = Tree::configured(Runtime::Containerd);
    std::fs::remove_dir_all(node.dir.path().join("var/lib/speculaire/mirror")).unwrap();
    let problems = node.preflight();
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        has(
            &problems,
            &[
                "/var/lib/speculaire/mirror/ca.crt",
                "run `speculaire configure`"
            ]
        ),
        "{problems:?}"
    );
}

#[test]
fn a_runtime_that_is_too_old_is_refused_with_the_version_it_reports() {
    for (runtime, name, old, ok) in [
        (Runtime::Containerd, "containerd", "v2.2.9", "v2.3.0"),
        (Runtime::Containerd, "containerd", "1.7.29", "2.3.0-rc.1"),
        (Runtime::CriO, "cri-o", "1.34.9", "1.35.0"),
    ] {
        let node = Tree::configured(runtime);
        node.version(name, old);
        let problems = node.preflight();
        assert!(
            has(
                &problems,
                &[
                    &format!("/run/{runtime}.sock"),
                    "is older than",
                    old.trim_start_matches('v')
                ]
            ),
            "{problems:?}"
        );
        node.version(name, ok);
        assert_eq!(node.preflight(), Vec::<String>::new(), "{ok}");
    }
    let node = Tree::configured(Runtime::Containerd);
    node.version("containerd", "v2.2.9");
    assert!(has(
        &node.preflight(),
        &["containerd 2.2.9 is older than 2.3.0"]
    ));
}

#[test]
fn a_runtime_that_answers_wrongly_or_not_at_all_is_a_problem_naming_its_socket() {
    let mut node = Tree::configured(Runtime::Containerd);
    node.version("cri-o", "1.37.2");
    assert!(has(
        &node.preflight(),
        &["answers as \"cri-o\", not containerd"]
    ));
    node.version("containerd", "Unknown");
    assert!(has(&node.preflight(), &["\"Unknown\"", "no release"]));
    node.stop();
    let problems = node.preflight();
    assert!(
        has(
            &problems,
            &[
                "/run/containerd.sock",
                "cannot connect to /run/containerd.sock",
                "`runtime.containerd_socket`"
            ]
        ),
        "{problems:?}"
    );
    let mut node = Tree::configured(Runtime::CriO);
    node.stop();
    assert!(has(
        &node.preflight(),
        &["/run/cri-o.sock", "`runtime.crio_socket`"]
    ));
}
