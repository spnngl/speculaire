//! Sources from a containerd config on a temporary tree.

use secrecy::ExposeSecret as _;

use super::*;

struct Node {
    dir: tempfile::TempDir,
}

impl Node {
    /// A `config.toml` whose `config_path` is the tree's `certs.d`, with `extra` below the registry section.
    fn new(extra: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let certs = dir.path().join("certs.d");
        std::fs::create_dir_all(&certs).unwrap();
        let section = "plugins.\"io.containerd.cri.v1.images\".registry";
        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                "version = 3\n[{section}]\nconfig_path = {:?}\n{extra}",
                certs.display().to_string()
            ),
        )
        .unwrap();
        Self { dir }
    }

    fn hosts(&self, host: &str, text: &str) {
        let dir = self.dir.path().join("certs.d").join(host);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("hosts.toml"), text).unwrap();
    }

    /// The registry config of this tree, read.
    fn registries(&self) -> ContainerdRegistries {
        let registries = self.unread();
        registries.reload().unwrap();
        registries
    }

    fn unread(&self) -> ContainerdRegistries {
        ContainerdRegistries::new(self.dir.path().join("config.toml"))
    }
}

fn tag(text: &str) -> Reference<'_> {
    Reference::Tag(text)
}

fn endpoints(sources: &[Source]) -> Vec<Vec<(String, bool)>> {
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
fn a_registry_without_a_host_directory_is_itself_and_docker_hub_is_where_it_answers() {
    let node = Node::new("");
    let registries = node.registries();
    let sources = registries
        .sources("docker.io/library/busybox", tag("1.37"))
        .unwrap();
    assert_eq!(
        endpoints(&sources),
        [[("registry-1.docker.io".to_owned(), true)]]
    );
    assert_eq!(sources[0].repository, "library/busybox");
    assert_eq!(sources[0].candidates[0].root, "/v2");
    assert!(sources[0].candidates[0].namespace.is_none());
    assert!(matches!(sources[0].credentials, Credentials::Anonymous));
    let sources = registries.sources("quay.io/org/app", tag("1")).unwrap();
    assert_eq!(endpoints(&sources), [[("quay.io".to_owned(), true)]]);
    assert_eq!(sources[0].repository, "org/app");
}

#[test]
fn the_hosts_of_a_host_directory_come_in_order_with_the_registry_last_and_mirrors_carry_the_namespace()
 {
    let node = Node::new("");
    node.hosts(
        "docker.io",
        "server = \"https://registry-1.docker.io\"\n\
         [host.\"https://mirror.corp:5000/hub\"]\n\
         capabilities = [\"pull\", \"resolve\"]\n\
         skip_verify = true\n\
         header = { \"X-Team\" = \"infra\" }\n",
    );
    let sources = node
        .registries()
        .sources("docker.io/library/busybox", tag("1.37"))
        .unwrap();
    assert_eq!(
        endpoints(&sources),
        [
            vec![("mirror.corp:5000".to_owned(), true)],
            vec![("registry-1.docker.io".to_owned(), true)],
        ]
    );
    let mirror = &sources[0].candidates[0];
    assert_eq!(mirror.root, "/hub/v2");
    assert_eq!(mirror.namespace.as_deref(), Some("docker.io"));
    assert!(mirror.tls.skip_verify);
    assert_eq!(mirror.headers.len(), 1);
    assert_eq!(mirror.headers[0].0, "X-Team");
    assert_eq!(mirror.headers[0].1.expose_secret(), "infra");
    let upstream = &sources[1].candidates[0];
    assert!(upstream.namespace.is_none());
    assert!(!upstream.tls.skip_verify);
    assert!(upstream.headers.is_empty());
}

#[test]
fn a_host_that_cannot_do_what_is_asked_is_skipped() {
    let node = Node::new("");
    node.hosts(
        "docker.io",
        "[host.\"https://pull-only.corp\"]\ncapabilities = [\"pull\"]\n\
         [host.\"https://resolve-only.corp\"]\ncapabilities = [\"resolve\"]\n",
    );
    let registries = node.registries();
    let by_tag = registries
        .sources("docker.io/library/busybox", tag("1"))
        .unwrap();
    let hosts = |sources: &[Source]| -> Vec<String> {
        sources
            .iter()
            .map(|s| s.candidates[0].authority.clone())
            .collect()
    };
    assert_eq!(
        hosts(&by_tag),
        ["resolve-only.corp", "registry-1.docker.io"]
    );
    let digest = format!("sha256:{}", "ab".repeat(32));
    let by_digest = registries
        .sources("docker.io/library/busybox", Reference::Digest(&digest))
        .unwrap();
    assert_eq!(
        hosts(&by_digest),
        ["pull-only.corp", "registry-1.docker.io"]
    );
}

#[test]
fn an_http_host_with_tls_settings_is_tried_on_https_then_on_http() {
    let node = Node::new("");
    let ca = node.dir.path().join("certs.d/reg.test:5000/ca.crt");
    node.hosts(
        "reg.test:5000",
        "server = \"http://reg.test:5000\"\nca = \"ca.crt\"\n",
    );
    std::fs::write(
        ca,
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let sources = node
        .registries()
        .sources("reg.test:5000/app", tag("1"))
        .unwrap();
    assert_eq!(
        endpoints(&sources),
        [[
            ("reg.test:5000".to_owned(), true),
            ("reg.test:5000".to_owned(), false)
        ]]
    );
    assert_eq!(sources[0].candidates[0].tls.roots.len(), 1);
    assert_eq!(sources[0].candidates[1].tls.roots.len(), 0);
}

#[test]
fn the_login_of_an_endpoint_is_its_configs_entry_by_host() {
    let section = "plugins.\"io.containerd.cri.v1.images\".registry.configs";
    let node = Node::new(&format!(
        "[{section}.\"mirror.corp:5000\".auth]\nusername = \"alice\"\npassword = \"s3cret\"\n\
         [{section}.\"quay.io\".auth]\nidentitytoken = \"refresh-me\"\n"
    ));
    node.hosts(
        "docker.io",
        "[host.\"https://mirror.corp:5000\"]\ncapabilities = [\"pull\", \"resolve\"]\n",
    );
    let registries = node.registries();
    let sources = registries
        .sources("docker.io/library/busybox", tag("1"))
        .unwrap();
    match &sources[0].credentials {
        Credentials::Login {
            username,
            password,
            identity_token,
        } => {
            assert_eq!(username, "alice");
            assert_eq!(password.expose_secret(), "s3cret");
            assert!(identity_token.is_none());
        }
        other @ Credentials::Anonymous => panic!("{other:?}"),
    }
    // The registry itself has no entry: the mirror's login is not sent to it.
    assert!(matches!(sources[1].credentials, Credentials::Anonymous));
    let sources = registries.sources("quay.io/org/app", tag("1")).unwrap();
    match &sources[0].credentials {
        Credentials::Login {
            username,
            identity_token,
            ..
        } => {
            assert_eq!(username, "");
            assert_eq!(
                identity_token.as_ref().unwrap().expose_secret(),
                "refresh-me"
            );
        }
        other @ Credentials::Anonymous => panic!("{other:?}"),
    }
}

#[test]
fn a_login_that_is_no_user_and_password_is_anonymous() {
    let section = "plugins.\"io.containerd.cri.v1.images\".registry.configs";
    let node = Node::new(&format!(
        "[{section}.\"quay.io\".auth]\nauth = \"***\"\n[{section}.\"ghcr.io\".auth]\nusername = \"alice\"\npassword = \"s3cret\"\n"
    ));
    let registries = node.unread();
    let reloaded = registries.reload().unwrap();
    // The snapshot is built: the other login is kept, and the bad one is reported, once.
    assert_eq!(reloaded.problems.len(), 1, "{:?}", reloaded.problems);
    assert!(reloaded.problems[0].contains("quay.io"));
    let sources = registries.sources("quay.io/org/app", tag("1")).unwrap();
    assert!(matches!(sources[0].credentials, Credentials::Anonymous));
    let sources = registries.sources("ghcr.io/org/app", tag("1")).unwrap();
    assert!(
        matches!(&sources[0].credentials, Credentials::Login { username, .. } if username == "alice")
    );
    assert!(!registries.changed());
}

const CERT: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
const ROTATED: &str = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n";
// Armor in two pieces, so that no secret scanner takes the made-up key for a leak.
const KEY: &str = concat!(
    "-----BEGIN PRIVATE ",
    "KEY-----\nCCCC\n-----END PRIVATE ",
    "KEY-----\n"
);

/// A directory outside `config_path` with `files`, and the `hosts.toml` of `reg.test` naming them as `client` pairs
/// and `ca`.
fn outside(
    node: &Node,
    files: &[(&str, &str)],
    hosts: impl Fn(&Path) -> String,
) -> tempfile::TempDir {
    let pki = tempfile::tempdir().unwrap();
    for (name, text) in files {
        std::fs::write(pki.path().join(name), text).unwrap();
    }
    node.hosts("reg.test", &hosts(pki.path()));
    pki
}

fn trust(registries: &ContainerdRegistries) -> Tls {
    registries.sources("reg.test/app", tag("1")).unwrap()[0].candidates[0]
        .tls
        .clone()
}

#[test]
fn certificates_are_read_at_reload_and_a_rotation_outside_the_host_directory_is_picked_up_by_the_next_poll()
 {
    let node = Node::new("");
    let pki = outside(
        &node,
        &[("ca.crt", CERT), ("c.cert", CERT), ("c.key", KEY)],
        |pki| {
            format!(
                "ca = {:?}\nclient = [[{:?}, {:?}]]\n",
                pki.join("ca.crt"),
                pki.join("c.cert"),
                pki.join("c.key")
            )
        },
    );
    let registries = node.registries();
    // No request reads a file: they can all be gone, and the trust is the one that was read.
    std::fs::remove_file(pki.path().join("c.key")).unwrap();
    std::fs::remove_file(pki.path().join("c.cert")).unwrap();
    let held = trust(&registries);
    assert_eq!(held.roots, [CERT.as_bytes()]);
    assert_eq!(held.client.as_ref().unwrap().key.expose_secret(), KEY);
    // A key that is held is never shown.
    assert!(!format!("{held:?}").contains("CCCC"));
    // A rotation of a file that `config_path` does not hold is found by the poll all the same.
    std::fs::write(pki.path().join("ca.crt"), ROTATED).unwrap();
    assert!(registries.changed());
    let reloaded = registries.reload().unwrap();
    assert_eq!(trust(&registries).roots, [ROTATED.as_bytes()]);
    // The client files are gone now: the reload says so once and the host has no client certificate.
    assert_eq!(reloaded.problems.len(), 1, "{:?}", reloaded.problems);
    assert!(reloaded.problems[0].contains("c.cert"));
    assert!(trust(&registries).client.is_none());
    assert!(!registries.changed());
}

#[test]
fn a_client_key_that_is_not_pem_and_a_ca_without_a_certificate_are_left_out_and_reported() {
    let node = Node::new("");
    let _pki = outside(
        &node,
        &[
            ("good.crt", CERT),
            ("junk.crt", "junk"),
            ("c.cert", CERT),
            ("c.key", "not a key"),
        ],
        |pki| {
            format!(
                "ca = [{:?}, {:?}]\nclient = [[{:?}, {:?}]]\n",
                pki.join("good.crt"),
                pki.join("junk.crt"),
                pki.join("c.cert"),
                pki.join("c.key")
            )
        },
    );
    let registries = node.unread();
    let reloaded = registries.reload().unwrap();
    assert_eq!(reloaded.problems.len(), 2, "{:?}", reloaded.problems);
    assert!(reloaded.problems.iter().any(|p| p.contains("junk.crt")));
    assert!(reloaded.problems.iter().any(|p| p.contains("c.key")));
    let trust = trust(&registries);
    assert_eq!(trust.roots, [CERT.as_bytes()]);
    assert!(trust.client.is_none());
}

#[test]
fn the_deprecated_mirrors_table_is_a_config_error() {
    let section = "plugins.\"io.containerd.cri.v1.images\".registry";
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "version = 3\n[{section}.mirrors.\"docker.io\"]\nendpoint = [\"https://m.corp\"]\n"
        ),
    )
    .unwrap();
    let registries = ContainerdRegistries::new(dir.path().join("config.toml"));
    registries.reload().unwrap();
    let err = registries
        .sources("docker.io/library/busybox", tag("1"))
        .unwrap_err();
    assert!(
        matches!(&err, Error::Config(text) if text.contains("mirrors")),
        "{err}"
    );
}

#[test]
fn nothing_is_answered_before_a_read_and_no_config_is_the_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let registries = ContainerdRegistries::new(dir.path().join("config.toml"));
    assert!(matches!(
        registries.sources("quay.io/org/app", tag("1")),
        Err(Error::Config(_))
    ));
    // containerd with no `config.toml` runs on its defaults: no `config_path`, the registry itself.
    registries.reload().unwrap();
    let sources = registries.sources("quay.io/org/app", tag("1")).unwrap();
    assert_eq!(endpoints(&sources), [[("quay.io".to_owned(), true)]]);
    // A file that appears is a change.
    assert!(!registries.changed());
    std::fs::write(dir.path().join("config.toml"), "version = 3\n").unwrap();
    assert!(registries.changed());
}

#[test]
fn an_edit_of_a_hosts_file_shows_on_reload_and_only_then() {
    let node = Node::new("");
    node.hosts(
        "quay.io",
        "[host.\"https://one.corp\"]\n  capabilities = [\"pull\", \"resolve\"]\n",
    );
    let registries = node.registries();
    let hosts = |registries: &ContainerdRegistries| {
        endpoints(&registries.sources("quay.io/org/app", tag("1")).unwrap())
    };
    assert_eq!(
        hosts(&registries),
        [
            [("one.corp".to_owned(), true)],
            [("quay.io".to_owned(), true)]
        ]
    );
    assert!(!registries.changed());
    node.hosts(
        "quay.io",
        "[host.\"https://two.corp\"]\n  capabilities = [\"pull\", \"resolve\"]\n",
    );
    // The answer stays the one that was read, whatever the disk says, until a reload.
    assert_eq!(hosts(&registries)[0], [("one.corp".to_owned(), true)]);
    assert!(registries.changed());
    registries.reload().unwrap();
    assert!(!registries.changed());
    assert_eq!(hosts(&registries)[0], [("two.corp".to_owned(), true)]);
}

#[test]
fn a_file_that_is_not_valid_keeps_the_config_held_and_names_the_file_and_the_place() {
    let node = Node::new("");
    node.hosts("quay.io", "[host.\"https://one.corp\"]\n");
    let registries = node.registries();
    node.hosts("quay.io", "[host.\"https://two.corp\"\n");
    let err = registries.reload().unwrap_err();
    let Error::Config(text) = &err else {
        panic!("{err}")
    };
    assert!(
        text.contains("hosts.toml") && text.contains("line 1, column 25"),
        "{text}"
    );
    let sources = registries.sources("quay.io/org/app", tag("1")).unwrap();
    assert_eq!(endpoints(&sources)[0], [("one.corp".to_owned(), true)]);
    // The failure is no change; the file made right is one, and is read.
    assert!(!registries.changed());
    node.hosts("quay.io", "[host.\"https://three.corp\"]\n");
    assert!(registries.changed());
    registries.reload().unwrap();
    let sources = registries.sources("quay.io/org/app", tag("1")).unwrap();
    assert_eq!(endpoints(&sources)[0], [("three.corp".to_owned(), true)]);
}

#[test]
fn a_config_toml_that_cannot_be_read_is_an_error_and_a_missing_one_is_not() {
    let dir = tempfile::tempdir().unwrap();
    // A directory where the file should be: not `NotFound`, so not the defaults.
    let registries = ContainerdRegistries::new(dir.path());
    assert!(registries.reload().is_err());
    assert!(
        ContainerdRegistries::new(dir.path().join("gone.toml"))
            .reload()
            .is_ok()
    );
}

#[test]
fn a_config_toml_that_is_not_valid_is_an_error_naming_it() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config.toml"), "version = [").unwrap();
    let err = ContainerdRegistries::new(dir.path().join("config.toml"))
        .reload()
        .unwrap_err();
    assert!(
        matches!(&err, Error::Config(text) if text.contains("config.toml")),
        "{err}"
    );
}

#[test]
fn a_name_without_a_registry_and_a_repository_is_an_error() {
    let node = Node::new("");
    for name in ["busybox", "/busybox", "docker.io/", ""] {
        let err = node.registries().sources(name, tag("1")).unwrap_err();
        assert!(matches!(err, Error::Name(_)), "{name:?}: {err}");
    }
}
