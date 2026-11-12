//! The calls to a runtime, against a fake one on a socket.

use std::os::unix::net::UnixListener;
use std::time::{Duration, Instant};

use speculaire_fake_runtime::{Answers, Fake};
use speculaire_runtime::containerd::{ImageExports, image_exports};
use speculaire_runtime::cri::{self, Error};
use speculaire_runtime::version::Release;

#[test]
fn the_version_is_what_the_runtime_reports() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let socket = dir.path().join("containerd.sock");
    let _fake = Fake::start(&socket, Answers::containerd("v2.4.2")).expect("a fake runtime");
    let version = cri::version(&socket).expect("an answer");
    assert_eq!(version.name, "containerd");
    assert_eq!(version.version, "v2.4.2");
    assert_eq!(version.release(), Some(Release::new(2, 4, 2)));
    // The same socket answers again, on a new connection.
    assert_eq!(cri::version(&socket).expect("an answer"), version);
}

#[test]
fn a_version_that_is_no_release_has_none() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let socket = dir.path().join("containerd.sock");
    let _fake = Fake::start(&socket, Answers::containerd("Unknown")).expect("a fake runtime");
    assert_eq!(cri::version(&socket).expect("an answer").release(), None);
}

#[test]
fn a_socket_nobody_listens_on_is_an_error_naming_it() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let socket = dir.path().join("none.sock");
    let err = cri::version(&socket).expect_err("no runtime");
    assert!(matches!(err, Error::Connect { .. }), "{err}");
    assert!(err.to_string().contains("none.sock"), "{err}");
    let err = image_exports(&socket).expect_err("no runtime");
    assert!(matches!(err, Error::Connect { .. }), "{err}");
}

#[test]
fn the_image_service_exports_what_it_was_configured_with() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let socket = dir.path().join("containerd.sock");
    let mut answers = Answers::containerd("v2.4.2");
    answers.image_exports = Some((true, String::new()));
    let _fake = Fake::start(&socket, answers).expect("a fake runtime");
    assert_eq!(
        image_exports(&socket).expect("an answer"),
        Some(ImageExports {
            discard_unpacked_layers: true,
            registry_config_path: String::new(),
        })
    );
}

#[test]
fn a_runtime_that_lists_no_image_service_exports_nothing() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let socket = dir.path().join("containerd.sock");
    let mut answers = Answers::containerd("v2.3.7");
    answers.image_exports = None;
    let _fake = Fake::start(&socket, answers).expect("a fake runtime");
    assert_eq!(image_exports(&socket).expect("an answer"), None);
}

#[test]
fn a_runtime_that_does_not_answer_is_an_error_after_five_seconds() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let socket = dir.path().join("silent.sock");
    // Accepts connections and says nothing.
    let listener = UnixListener::bind(&socket).expect("a socket");
    let _holder = std::thread::spawn(move || {
        let held: Vec<_> = listener.incoming().take(2).collect();
        std::thread::sleep(Duration::from_secs(8));
        drop(held);
    });
    let start = Instant::now();
    let err = cri::version(&socket).expect_err("no answer");
    let waited = start.elapsed();
    assert!(matches!(err, Error::Call { .. }), "{err}");
    assert!(err.to_string().contains("no answer within 5 s"), "{err}");
    assert!(
        waited >= Duration::from_secs(5) && waited < Duration::from_secs(7),
        "{waited:?}"
    );
}

#[test]
fn the_list_of_images_is_read_with_its_names() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let socket = dir.path().join("crio.sock");
    let mut answers = Answers::containerd("1.37.2");
    answers.images = vec![
        (
            "0123".to_owned(),
            vec!["docker.io/library/busybox:1.37".to_owned()],
            vec!["docker.io/library/busybox@sha256:aa".to_owned()],
        ),
        ("4567".to_owned(), Vec::new(), Vec::new()),
    ];
    let _fake = Fake::start(&socket, answers).expect("a fake runtime");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let images = runtime
        .block_on(cri::list_images(&socket))
        .expect("an answer");
    assert_eq!(images.len(), 2);
    assert_eq!(images[0].id, "0123");
    assert_eq!(images[0].repo_tags, ["docker.io/library/busybox:1.37"]);
    assert_eq!(
        images[0].repo_digests,
        ["docker.io/library/busybox@sha256:aa"]
    );
    assert_eq!(images[1].repo_tags.len(), 0);
    let err = runtime
        .block_on(cri::list_images(&dir.path().join("none.sock")))
        .expect_err("no runtime");
    assert!(matches!(err, Error::Connect { .. }), "{err}");
}
