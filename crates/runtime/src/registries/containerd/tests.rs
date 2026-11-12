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

    fn registries(&self) -> ContainerdRegistries {
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
    let node = Node::new(&format!("[{section}.\"quay.io\".auth]\nauth = \"***\"\n"));
    let sources = node
        .registries()
        .sources("quay.io/org/app", tag("1"))
        .unwrap();
    assert!(matches!(sources[0].credentials, Credentials::Anonymous));
}

#[test]
fn the_deprecated_mirrors_table_and_a_missing_config_are_config_errors() {
    let section = "plugins.\"io.containerd.cri.v1.images\".registry";
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "version = 3\n[{section}.mirrors.\"docker.io\"]\nendpoint = [\"https://m.corp\"]\n"
        ),
    )
    .unwrap();
    let err = ContainerdRegistries::new(dir.path().join("config.toml"))
        .sources("docker.io/library/busybox", tag("1"))
        .unwrap_err();
    assert!(
        matches!(&err, Error::Config(text) if text.contains("mirrors")),
        "{err}"
    );
    let err = ContainerdRegistries::new(dir.path().join("gone.toml"))
        .sources("docker.io/library/busybox", tag("1"))
        .unwrap_err();
    assert!(matches!(err, Error::Config(_)), "{err}");
}

#[test]
fn a_name_without_a_registry_and_a_repository_is_an_error() {
    let node = Node::new("");
    for name in ["busybox", "/busybox", "docker.io/", ""] {
        let err = node.registries().sources(name, tag("1")).unwrap_err();
        assert!(matches!(err, Error::Name(_)), "{name:?}: {err}");
    }
}
