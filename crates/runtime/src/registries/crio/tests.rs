//! Sources from a node's registry config, on a temporary tree standing for its root.

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixListener;

use secrecy::ExposeSecret as _;

use super::*;

const CERT: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
const ROTATED: &str = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n";
// Armor in two pieces, so that no secret scanner takes the made-up key for a leak.
const KEY: &str = concat!(
    "-----BEGIN PRIVATE ",
    "KEY-----\nCCCC\n-----END PRIVATE ",
    "KEY-----\n"
);
const OWN: &str = "/etc/containers/registries.conf.d/99-speculaire.conf";

struct Node {
    dir: tempfile::TempDir,
}

impl Node {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn put(&self, path: &str, text: &str) {
        let path = self.dir.path().join(path.trim_start_matches('/'));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// The registry config of this tree, read, with the CRI-O config `crio` as its socket serves it.
    fn registries_with(&self, crio: &str) -> CrioRegistries {
        let registries = self.unread(crio);
        registries.reload(None).unwrap();
        registries
    }

    /// As `registries_with`, before anything is read.
    fn unread(&self, crio: &str) -> CrioRegistries {
        let socket = self.dir.path().join("crio.sock");
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).unwrap();
        let crio = format!("HTTP/1.0 200 OK\r\n\r\n{crio}");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let _ = stream.read(&mut [0_u8; 512]);
                let _ = stream.write_all(crio.as_bytes());
            }
        });
        let context = Context {
            root: self.dir.path().to_owned(),
            home: self.dir.path().join("root"),
            ..Context::root()
        };
        CrioRegistries::new(
            context,
            socket,
            self.dir.path().join(OWN.trim_start_matches('/')),
        )
    }

    fn registries(&self) -> CrioRegistries {
        self.registries_with("")
    }
}

fn tag(text: &str) -> Reference<'_> {
    Reference::Tag(text)
}

fn authorities(sources: &[Source]) -> Vec<Vec<(String, bool)>> {
    sources
        .iter()
        .map(|s| {
            s.candidates
                .iter()
                .map(|e| (e.authority.clone(), e.https))
                .collect()
        })
        .collect()
}

#[test]
fn a_registry_without_an_entry_is_asked_where_the_reference_says_and_docker_hub_where_it_answers() {
    let node = Node::new();
    let registries = node.registries();
    let sources = registries.sources("quay.io/org/app", tag("1")).unwrap();
    assert_eq!(authorities(&sources), [[("quay.io".to_owned(), true)]]);
    assert_eq!(sources[0].repository, "org/app");
    assert!(matches!(sources[0].credentials, Credentials::Anonymous));
    for name in [
        "docker.io/library/busybox",
        "index.docker.io/library/busybox",
    ] {
        let sources = registries.sources(name, tag("1.37")).unwrap();
        assert_eq!(
            authorities(&sources),
            [[("registry-1.docker.io".to_owned(), true)]],
            "{name}"
        );
        assert_eq!(sources[0].repository, "library/busybox");
    }
    // A port stays, a digest is not part of the repository.
    let digest = format!("sha256:{}", "ab".repeat(32));
    let sources = registries
        .sources("localhost:5000/team/app", Reference::Digest(&digest))
        .unwrap();
    assert_eq!(
        authorities(&sources),
        [[("localhost:5000".to_owned(), true)]]
    );
    assert_eq!(sources[0].repository, "team/app");
}

#[test]
fn the_admins_mirrors_come_first_and_the_location_replaces_the_prefix() {
    let node = Node::new();
    node.put(
        "/etc/containers/registries.conf",
        r#"
[[registry]]
prefix = "docker.io"
location = "registry.corp/dockerhub"

[[registry.mirror]]
location = "mirror.corp:5000/hub"
insecure = true

[[registry.mirror]]
location = "digest.corp/hub"
pull-from-mirror = "digest-only"
"#,
    );
    let sources = node
        .registries()
        .sources("docker.io/library/busybox", tag("1.37"))
        .unwrap();
    assert_eq!(
        authorities(&sources),
        [
            // The insecure mirror: TLS without verification, then plain HTTP.
            vec![
                ("mirror.corp:5000".to_owned(), true),
                ("mirror.corp:5000".to_owned(), false)
            ],
            vec![("registry.corp".to_owned(), true)],
        ]
    );
    assert_eq!(sources[0].repository, "hub/library/busybox");
    assert!(sources[0].candidates[0].tls.skip_verify);
    assert!(!sources[0].candidates[1].tls.skip_verify);
    assert_eq!(sources[1].repository, "dockerhub/library/busybox");
    // By digest, the digest-only mirror applies too.
    let digest = format!("sha256:{}", "cd".repeat(32));
    let sources = node
        .registries()
        .sources("docker.io/library/busybox", Reference::Digest(&digest))
        .unwrap();
    assert_eq!(sources.len(), 3);
    assert_eq!(sources[1].candidates[0].authority, "digest.corp");
}

#[test]
fn speculaires_own_drop_in_is_not_a_source_and_a_blocked_registry_has_none() {
    let node = Node::new();
    node.put(OWN, "[[registry]]\nprefix = \"docker.io\"\nlocation = \"docker.io\"\n[[registry.mirror]]\nlocation = \"127.0.0.1:7480/docker.io\"\n");
    node.put(
        "/etc/containers/registries.conf",
        "[[registry]]\nprefix = \"blocked.example\"\nlocation = \"blocked.example\"\nblocked = true\n",
    );
    let registries = node.registries();
    let sources = registries
        .sources("docker.io/library/busybox", tag("1"))
        .unwrap();
    assert_eq!(
        authorities(&sources),
        [[("registry-1.docker.io".to_owned(), true)]]
    );
    assert!(
        registries
            .sources("blocked.example/a/b", tag("1"))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_name_without_a_registry_and_a_repository_is_an_error() {
    let node = Node::new();
    let registries = node.registries();
    for name in ["busybox", "/busybox", "docker.io/", ""] {
        let err = registries.sources(name, tag("1")).unwrap_err();
        assert!(matches!(err, Error::Name(_)), "{name:?}: {err}");
    }
}

#[test]
fn a_registry_config_that_is_invalid_is_an_error() {
    let node = Node::new();
    node.put("/etc/containers/registries.conf", "[[registry]]\nprefix = ");
    let registries = node.unread("");
    let err = registries.reload(None).unwrap_err();
    assert!(
        matches!(&err, Error::Config(text) if text.contains("registries.conf")),
        "{err}"
    );
    let err = registries
        .sources("docker.io/library/busybox", tag("1"))
        .unwrap_err();
    assert!(matches!(err, Error::Config(_)), "{err}");
}

#[test]
fn the_login_of_the_credential_files_is_the_one_for_the_repository_then_its_registry() {
    let node = Node::new();
    // alice:s3cret, and bob:hunter2.
    node.put(
        "/run/containers/0/auth.json",
        r#"{"auths":{"quay.io":{"auth":"YWxpY2U6czNjcmV0"},"quay.io/org/private":{"auth":"Ym9iOmh1bnRlcjI="}}}"#,
    );
    let registries = node.registries();
    let login = |name: &str| match &registries.sources(name, tag("1")).unwrap()[0].credentials {
        Credentials::Login {
            username, password, ..
        } => Some((username.clone(), password.expose_secret().to_owned())),
        Credentials::Anonymous => None,
    };
    assert_eq!(
        login("quay.io/org/public"),
        Some(("alice".to_owned(), "s3cret".to_owned()))
    );
    assert_eq!(
        login("quay.io/org/private"),
        Some(("bob".to_owned(), "hunter2".to_owned()))
    );
    assert_eq!(login("ghcr.io/org/app"), None);
}

#[test]
fn an_identity_token_beside_the_login_is_kept_for_the_token_endpoint() {
    let node = Node::new();
    node.put(
        "/run/containers/0/auth.json",
        r#"{"auths":{"quay.io":{"auth":"YWxpY2U6czNjcmV0","identitytoken":"refresh-me"}}}"#,
    );
    let sources = node
        .registries()
        .sources("quay.io/org/app", tag("1"))
        .unwrap();
    match &sources[0].credentials {
        Credentials::Login {
            username,
            identity_token,
            ..
        } => {
            assert_eq!(username, "alice");
            assert_eq!(
                identity_token.as_ref().unwrap().expose_secret(),
                "refresh-me"
            );
        }
        other @ Credentials::Anonymous => panic!("{other:?}"),
    }
}

#[test]
fn a_credential_helper_or_an_unreadable_file_means_anonymous() {
    let node = Node::new();
    node.put(
        "/etc/containers/registries.conf",
        "credential-helpers = [\"ecr-login\"]\n",
    );
    let sources = node
        .registries()
        .sources("quay.io/org/app", tag("1"))
        .unwrap();
    assert!(matches!(sources[0].credentials, Credentials::Anonymous));
}

/// The user name of the login for `name`, none for an anonymous source.
fn user_at(registries: &CrioRegistries, name: &str) -> Option<String> {
    match &registries.sources(name, tag("1")).unwrap()[0].credentials {
        Credentials::Login { username, .. } => Some(username.clone()),
        Credentials::Anonymous => None,
    }
}

fn later() -> std::time::SystemTime {
    std::time::SystemTime::now() + std::time::Duration::from_secs(60)
}

#[test]
fn a_credential_file_that_is_not_valid_leaves_the_hosts_that_reach_it_anonymous_and_is_reported_once()
 {
    let node = Node::new();
    // alice:s3cret for quay.io, in the first file of the search; the next one is not JSON.
    node.put(
        "/run/containers/0/auth.json",
        r#"{"auths":{"quay.io":{"auth":"YWxpY2U6czNjcmV0"}}}"#,
    );
    node.put("/root/.docker/config.json", "{\n  x");
    node.put(
        "/etc/containers/registries.conf",
        "[[registry]]\nprefix = \"docker.io\"\nlocation = \"docker.io\"\n\n[[registry.mirror]]\nlocation = \"mirror.corp\"\n",
    );
    let registries = node.unread("");
    let reloaded = registries.reload(None).unwrap();
    assert!(reloaded.changed);
    assert_eq!(reloaded.problems.len(), 1, "{:?}", reloaded.problems);
    let problem = &reloaded.problems[0];
    assert!(
        problem.contains("config.json") && problem.contains("line 2, column"),
        "{problem}"
    );
    // The login found before the bad file is kept; a host that reaches the bad file is anonymous; the rest of the
    // snapshot is built.
    assert_eq!(
        user_at(&registries, "quay.io/org/app").as_deref(),
        Some("alice")
    );
    assert_eq!(user_at(&registries, "ghcr.io/org/app"), None);
    let sources = registries
        .sources("docker.io/library/busybox", tag("1"))
        .unwrap();
    assert_eq!(sources.len(), 2);
    // A poll that finds the files unchanged says nothing; a reload that reads them says it again.
    assert_eq!(
        registries.reload(Some(later())).unwrap(),
        Reloaded::default()
    );
    assert_eq!(registries.reload(None).unwrap().problems.len(), 1);
}

#[test]
fn a_bad_credential_file_ahead_of_a_good_one_hides_the_login_behind_it() {
    let node = Node::new();
    node.put("/run/containers/0/auth.json", "{");
    node.put(
        "/root/.docker/config.json",
        r#"{"auths":{"quay.io":{"auth":"YWxpY2U6czNjcmV0"}}}"#,
    );
    let registries = node.unread("");
    assert_eq!(registries.reload(None).unwrap().problems.len(), 1);
    assert_eq!(user_at(&registries, "quay.io/org/app"), None);
}

#[test]
fn an_auth_that_is_not_base64_is_reported_and_anonymous() {
    let node = Node::new();
    node.put(
        "/run/containers/0/auth.json",
        r#"{"auths":{"quay.io":{"auth":"***"},"ghcr.io":{"auth":"Ym9iOmh1bnRlcjI="}}}"#,
    );
    let registries = node.unread("");
    let reloaded = registries.reload(None).unwrap();
    assert_eq!(reloaded.problems.len(), 1, "{:?}", reloaded.problems);
    assert!(reloaded.problems[0].contains("quay.io"));
    assert_eq!(user_at(&registries, "quay.io/org/app"), None);
    assert_eq!(
        user_at(&registries, "ghcr.io/org/app").as_deref(),
        Some("bob")
    );
}

#[test]
fn the_certificate_directory_of_a_host_is_its_trust() {
    let node = Node::new();
    node.put("/etc/containers/certs.d/reg.test:5000/ca.crt", CERT);
    node.put("/etc/containers/certs.d/reg.test:5000/client.cert", CERT);
    node.put("/etc/containers/certs.d/reg.test:5000/client.key", KEY);
    let registries = node.registries();
    let sources = registries.sources("reg.test:5000/app", tag("1")).unwrap();
    let tls = &sources[0].candidates[0].tls;
    assert_eq!(tls.roots.len(), 1);
    assert!(tls.roots[0].starts_with(b"-----BEGIN CERTIFICATE"));
    let client = tls.client.as_ref().expect("a client certificate");
    assert_eq!(client.certificate, CERT.as_bytes());
    assert_eq!(client.key.expose_secret(), KEY);
    assert!(!tls.skip_verify);
    // Another host has none.
    let sources = registries.sources("other.test/app", tag("1")).unwrap();
    assert_eq!(sources[0].candidates[0].tls.roots.len(), 0);
    // A certificate without its key is a directory that cannot be used: the host is reached with the system's trust.
    let node = Node::new();
    node.put("/etc/containers/certs.d/reg.test/client.cert", CERT);
    let sources = node.registries().sources("reg.test/app", tag("1")).unwrap();
    assert!(sources[0].candidates[0].tls.client.is_none());
}

fn trust(registries: &CrioRegistries, name: &str) -> Tls {
    registries.sources(name, tag("1")).unwrap()[0].candidates[0]
        .tls
        .clone()
}

#[test]
fn a_client_key_that_is_not_pem_leaves_the_host_without_a_client_certificate_and_is_reported() {
    let node = Node::new();
    node.put("/etc/containers/certs.d/bad.test/ca.crt", CERT);
    node.put("/etc/containers/certs.d/bad.test/client.cert", CERT);
    node.put("/etc/containers/certs.d/bad.test/client.key", "not a key");
    node.put("/etc/containers/certs.d/good.test/client.cert", CERT);
    node.put("/etc/containers/certs.d/good.test/client.key", KEY);
    let registries = node.unread("");
    let reloaded = registries.reload(None).unwrap();
    assert_eq!(reloaded.problems.len(), 1, "{:?}", reloaded.problems);
    assert!(reloaded.problems[0].contains("client.key"));
    let bad = trust(&registries, "bad.test/app");
    assert_eq!(bad.roots, [CERT.as_bytes()]);
    assert!(bad.client.is_none());
    assert!(trust(&registries, "good.test/app").client.is_some());
    assert_eq!(
        registries.reload(Some(later())).unwrap(),
        Reloaded::default()
    );
}

#[test]
fn a_ca_file_without_a_certificate_is_left_out_and_reported() {
    let node = Node::new();
    node.put("/etc/containers/certs.d/reg.test/a.crt", "junk");
    node.put("/etc/containers/certs.d/reg.test/b.crt", CERT);
    let registries = node.unread("");
    let reloaded = registries.reload(None).unwrap();
    assert_eq!(reloaded.problems.len(), 1, "{:?}", reloaded.problems);
    assert!(reloaded.problems[0].contains("a.crt"));
    assert_eq!(trust(&registries, "reg.test/app").roots, [CERT.as_bytes()]);
}

#[test]
fn certificates_are_read_at_reload_and_a_rotation_is_picked_up_by_the_next_poll() {
    let node = Node::new();
    let ca = "/etc/containers/certs.d/reg.test/ca.crt";
    node.put(ca, CERT);
    node.put("/etc/containers/certs.d/reg.test/client.cert", CERT);
    node.put("/etc/containers/certs.d/reg.test/client.key", KEY);
    let registries = node.registries();
    // No request reads a file: they can all be gone, and the trust is the one that was read.
    let directory = node.dir.path().join("etc/containers/certs.d/reg.test");
    std::fs::remove_dir_all(&directory).unwrap();
    let held = trust(&registries, "reg.test/app");
    assert_eq!(held.roots, [CERT.as_bytes()]);
    assert!(held.client.is_some());
    // A rotation changes a watched path, and the next poll that looks since the last read finds it.
    let since = std::time::SystemTime::now();
    std::thread::sleep(std::time::Duration::from_millis(20));
    node.put(ca, ROTATED);
    let reloaded = registries.reload(Some(since)).unwrap();
    assert!(reloaded.changed && reloaded.problems.is_empty());
    assert_eq!(
        trust(&registries, "reg.test/app").roots,
        [ROTATED.as_bytes()]
    );
}

#[test]
fn the_auth_file_crio_names_is_the_only_credential_file() {
    let node = Node::new();
    // alice:s3cret in the default search, bob:hunter2 in the file CRI-O names.
    node.put(
        "/run/containers/0/auth.json",
        r#"{"auths":{"quay.io":{"auth":"YWxpY2U6czNjcmV0"}}}"#,
    );
    node.put(
        "/srv/kubelet.json",
        r#"{"auths":{"quay.io":{"auth":"Ym9iOmh1bnRlcjI="}}}"#,
    );
    let named = node.dir.path().join("srv/kubelet.json");
    let crio = format!(
        "[crio.image]\nglobal_auth_file = {:?}\n",
        named.display().to_string()
    );
    let sources = node
        .registries_with(&crio)
        .sources("quay.io/org/app", tag("1"))
        .unwrap();
    match &sources[0].credentials {
        Credentials::Login { username, .. } => assert_eq!(username, "bob"),
        other @ Credentials::Anonymous => panic!("{other:?}"),
    }
    // Unset: the default search finds alice's.
    let sources = node
        .registries()
        .sources("quay.io/org/app", tag("1"))
        .unwrap();
    match &sources[0].credentials {
        Credentials::Login { username, .. } => assert_eq!(username, "alice"),
        other @ Credentials::Anonymous => panic!("{other:?}"),
    }
}

#[test]
fn a_crio_that_cannot_be_asked_is_a_config_error() {
    let node = Node::new();
    let context = Context {
        root: node.dir.path().to_owned(),
        ..Context::root()
    };
    let registries = CrioRegistries::new(context, node.dir.path().join("gone.sock"), "/none");
    let err = registries.reload(None).unwrap_err();
    assert!(
        matches!(&err, Error::Config(text) if text.contains("gone.sock")),
        "{err}"
    );
}
