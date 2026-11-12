//! The containerd registry config on temporary directories: the behaviour that `oracle.rs` compares with containerd,
//! kept here as examples that run without the oracle binary.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use secrecy::ExposeSecret;
use speculaire_registry_config::containerd::config::{self, Hosts, LoadError, RegistryError};
use speculaire_registry_config::containerd::hosts::{self, Capabilities};

const NODE_CONFIGS: [&str; 3] = [
    include_str!("data/containerd/node-k1.35.toml"),
    include_str!("data/containerd/node-k1.36.toml"),
    include_str!("data/containerd/node-k1.37.toml"),
];

fn write(root: &Path, name: &str, text: &str) -> PathBuf {
    let path = root.join(name);
    fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
    fs::write(&path, text).expect("a file");
    path
}

fn registry_of(text: &str) -> Result<config::Registry, LoadError> {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = write(dir.path(), "config.toml", text);
    config::load(&path)
}

#[test]
fn e2e_node_configs_load() {
    for text in NODE_CONFIGS {
        let registry = registry_of(text).expect("a config");
        assert_eq!(
            registry.hosts,
            Hosts::ConfigPath(vec![PathBuf::from("/etc/containerd/certs.d")])
        );
        assert!(registry.configs.is_empty());
        assert!(registry.headers.is_empty());
    }
}

#[test]
fn without_a_registry_section_the_default_config_path_applies() {
    let registry = registry_of("version = 3\n").expect("a config");
    assert_eq!(
        registry.hosts,
        Hosts::ConfigPath(vec![
            PathBuf::from("/etc/containerd/certs.d"),
            PathBuf::from("/etc/docker/certs.d")
        ])
    );
}

#[test]
fn version_two_and_three_name_the_registry_in_their_own_plugin() {
    let v2 = registry_of(
        "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\nconfig_path = \"/two\"\n",
    )
    .expect("a config");
    assert_eq!(v2.hosts, Hosts::ConfigPath(vec![PathBuf::from("/two")]));
    let v3 = registry_of(
        "version = 3\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/three\"\n",
    )
    .expect("a config");
    assert_eq!(v3.hosts, Hosts::ConfigPath(vec![PathBuf::from("/three")]));
    let v1 = registry_of("version = 1\n[plugins.cri.registry]\nconfig_path = \"/one\"\n")
        .expect("a config");
    assert_eq!(v1.hosts, Hosts::ConfigPath(vec![PathBuf::from("/one")]));
}

#[test]
fn keys_are_matched_in_any_case_as_go_toml_does() {
    let registry = registry_of(
        "Version = 3\n[plugins.\"io.containerd.cri.v1.images\".Registry]\nConfig_Path = \"/cased\"\n",
    )
    .expect("a config");
    assert_eq!(
        registry.hosts,
        Hosts::ConfigPath(vec![PathBuf::from("/cased")])
    );
}

#[test]
fn two_spellings_of_a_table_merge_and_the_lower_case_one_is_set_last() {
    let registry = registry_of(
        "version = 3\n[plugins.\"io.containerd.cri.v1.images\".registry.mirrors.\"a.io\"]\nendpoint = [\"https://m.io\"]\n\
         [plugins.\"io.containerd.cri.v1.images\".Registry.mirrors.\"b.io\"]\nendpoint = [\"https://n.io\"]\n\
         [plugins.\"io.containerd.cri.v1.images\".Registry.Mirrors.\"a.io\"]\nEndpoint = [\"https://o.io\"]\n",
    )
    .expect("a config");
    let Hosts::Mirrors(mirrors) = registry.hosts else {
        panic!("mirrors expected");
    };
    assert_eq!(mirrors.len(), 2);
    assert_eq!(mirrors["a.io"], ["https://m.io"]);
    assert_eq!(mirrors["b.io"], ["https://n.io"]);
}

#[test]
fn nri_required_plugins_come_from_the_default_validator_across_imports() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let required = |text: &str| {
        let path = write(dir.path(), "config.toml", text);
        config::load_plugins(&path).map(|plugins| plugins.nri.required_plugins)
    };
    assert_eq!(
        required("version = 3\n").expect("a config"),
        Vec::<String>::new()
    );
    assert_eq!(
        required("[plugins.\"io.containerd.nri.v1.nri\".default_validator]\nenable = true\nrequired_plugins = [\"speculaire\"]\n")
            .expect("a config"),
        ["speculaire"]
    );
    // Keys match in any case, and a later file replaces the array of the same spelling. Spelled otherwise, the two
    // keys stay side by side, and go-toml, which sees them in byte order, ends on the all-lower-case one (the
    // oracle test has the same case).
    write(
        dir.path(),
        "conf.d/late.toml",
        "[plugins.\"io.containerd.nri.v1.nri\".Default_Validator]\nRequired_Plugins = [\"a\", \"b\"]\n",
    );
    assert_eq!(
        required("imports = [\"conf.d/*.toml\"]\n[plugins.\"io.containerd.nri.v1.nri\".default_validator]\nrequired_plugins = [\"speculaire\"]\n")
            .expect("a config"),
        ["speculaire"]
    );
    let err = required("[plugins.\"io.containerd.nri.v1.nri\".default_validator]\nrequired_plugins = \"speculaire\"\n")
        .unwrap_err();
    assert!(matches!(err, LoadError::Nri(_)), "{err}");
    let err = required("[plugins]\n\"io.containerd.nri.v1.nri\" = 1\n").unwrap_err();
    assert!(matches!(err, LoadError::Nri(_)), "{err}");
    assert!(config::load_plugins(&dir.path().join("missing.toml")).is_err());
}

#[test]
fn imports_merge_in_order_and_expand_globs() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    write(
        dir.path(),
        "conf.d/10-a.toml",
        "version = 3\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/a\"\n[plugins.\"io.containerd.cri.v1.images\".registry.headers]\nx = [\"a\"]\n",
    );
    write(
        dir.path(),
        "conf.d/20-b.toml",
        "version = 3\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/b\"\n",
    );
    let main = write(
        dir.path(),
        "config.toml",
        "version = 3\nimports = [\"conf.d/*.toml\"]\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/main\"\n",
    );
    let registry = config::load(&main).expect("a config");
    assert_eq!(registry.hosts, Hosts::ConfigPath(vec![PathBuf::from("/b")]));
    let values: Vec<&str> = registry.headers["x"]
        .iter()
        .map(ExposeSecret::expose_secret)
        .collect();
    assert_eq!(values, ["a"]);
}

#[test]
fn a_version_above_the_known_one_is_refused() {
    let error = registry_of("version = 5\n").expect_err("a refusal");
    assert!(
        matches!(error, LoadError::Version { found: 5 }),
        "{error:?}"
    );
}

#[test]
fn a_missing_file_and_a_bad_file_name_themselves() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let missing = dir.path().join("none.toml");
    let error = config::load(&missing).expect_err("a refusal");
    assert!(error.to_string().contains("none.toml"), "{error}");
    let bad = write(dir.path(), "bad.toml", "version = [\n");
    let error = config::load(&bad).expect_err("a refusal");
    assert!(error.to_string().contains("bad.toml"), "{error}");
}

#[test]
fn mirrors_and_config_path_exclude_each_other() {
    let error = registry_of(
        "version = 3\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/x\"\n[plugins.\"io.containerd.cri.v1.images\".registry.mirrors.\"docker.io\"]\nendpoint = [\"https://m.io\"]\n",
    )
    .expect_err("a refusal");
    assert!(
        matches!(
            error,
            LoadError::Refused(RegistryError::MirrorsWithConfigPath)
        ),
        "{error:?}"
    );
}

#[test]
fn mirrors_alone_are_kept() {
    let registry = registry_of(
        "version = 3\n[plugins.\"io.containerd.cri.v1.images\".registry.mirrors.\"docker.io\"]\nendpoint = [\"https://m.io\"]\n",
    )
    .expect("a config");
    let Hosts::Mirrors(mirrors) = registry.hosts else {
        panic!("mirrors expected");
    };
    assert_eq!(mirrors["docker.io"], ["https://m.io"]);
}

#[test]
fn credentials_come_from_configs_and_auths_keyed_by_host() {
    let registry = registry_of(
        r#"version = 3
[plugins."io.containerd.cri.v1.images".registry.configs."a.io".auth]
username = "u"
password = "p"
[plugins."io.containerd.cri.v1.images".registry.auths."https://b.io"]
identitytoken = "tok"
[plugins."io.containerd.cri.v1.images".registry.headers]
x-one = ["1"]
x-many = ["2", "3"]
"#,
    )
    .expect("a config");
    let a = &registry.configs["a.io"];
    assert_eq!(a.username, "u");
    assert_eq!(a.password.expose_secret(), "p");
    assert_eq!(
        registry.configs["b.io"].identity_token.expose_secret(),
        "tok"
    );
    assert_eq!(registry.headers["x-one"][0].expose_secret(), "1");
    assert_eq!(registry.headers["x-many"].len(), 2);
}

#[test]
fn an_auths_key_that_is_not_a_url_is_refused() {
    let error = registry_of(
        "version = 3\n[plugins.\"io.containerd.cri.v1.images\".registry.auths.\"http://[::1\"]\nusername = \"u\"\n",
    )
    .expect_err("a refusal");
    assert!(
        matches!(error, LoadError::Refused(RegistryError::AuthsUrl { .. })),
        "{error:?}"
    );
}

const HOSTS: &str = r#"
server = "https://registry.example"
capabilities = ["pull", "resolve"]
ca = "root.pem"

[host."https://mirror-a.example:5000/v2/path"]
  capabilities = ["pull"]
  skip_verify = true
  override_path = true
  dial_timeout = "1m30s"
  ca = ["/abs/ca.pem", "rel/ca.pem"]
  client = [["c.pem", "c.key"], "only.pem"]
  [host."https://mirror-a.example:5000/v2/path".header]
    x-one = "1"
    x-many = ["2", "3"]

[host."http://mirror-b.example"]
"#;

#[test]
fn hosts_toml_lists_the_hosts_in_order_then_the_server() {
    let hosts = hosts::parse_hosts_file(Path::new("/base"), HOSTS).expect("a hosts.toml");
    let names: Vec<&str> = hosts.iter().map(|h| h.host.as_str()).collect();
    assert_eq!(
        names,
        [
            "mirror-a.example:5000",
            "mirror-b.example",
            "registry.example"
        ]
    );
    let a = &hosts[0];
    assert_eq!(a.scheme, "https");
    assert_eq!(a.path, "/v2/path");
    assert_eq!(a.capabilities, Capabilities::PULL);
    assert_eq!(a.skip_verify, Some(true));
    assert_eq!(a.dial_timeout, Some(Duration::from_secs(90)));
    assert_eq!(
        a.ca(),
        [
            PathBuf::from("/abs/ca.pem"),
            PathBuf::from("/base/rel/ca.pem")
        ]
    );
    assert_eq!(a.client().len(), 2);
    assert_eq!(a.client()[0].key, Some(PathBuf::from("/base/c.key")));
    assert_eq!(a.header["x-many"].len(), 2);
    let b = &hosts[1];
    assert_eq!(b.scheme, "http");
    assert_eq!(b.path, "/v2");
    assert_eq!(b.capabilities, Capabilities::ALL);
    assert!(!b.has_tls());
    let server = &hosts[2];
    assert_eq!(
        server.capabilities,
        Capabilities::PULL | Capabilities::RESOLVE
    );
    assert_eq!(server.ca(), [PathBuf::from("/base/root.pem")]);
}

#[test]
fn a_hosts_toml_without_server_ends_with_the_defaults_of_the_registry() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    write(
        dir.path(),
        "docker.io/hosts.toml",
        "[host.\"https://m.io\"]\n  capabilities = [\"pull\"]\n",
    );
    let roots = [dir.path().to_path_buf()];
    let docker = hosts::resolve(&roots, "docker.io", None).expect("hosts");
    let names: Vec<&str> = docker.iter().map(|h| h.host.as_str()).collect();
    assert_eq!(names, ["m.io", "registry-1.docker.io"]);
    assert!(docker[0].is_proxy("docker.io"));
    assert!(!docker[1].is_proxy("docker.io"));
}

#[test]
fn registries_without_a_directory_get_the_defaults() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let roots = [dir.path().to_path_buf()];
    let plain = hosts::resolve(&roots, "ghcr.io", None).expect("hosts");
    assert_eq!(plain.len(), 1);
    assert_eq!(
        (
            plain[0].scheme.as_str(),
            plain[0].host.as_str(),
            plain[0].path.as_str()
        ),
        ("https", "ghcr.io", "/v2")
    );
    assert_eq!(plain[0].capabilities, Capabilities::ALL);
    let local = hosts::resolve(&roots, "localhost:5000", None).expect("hosts");
    // HTTP with TLS settings is tried as HTTPS first, then as HTTP.
    assert_eq!(
        (local[0].scheme.as_str(), local[0].http_fallback),
        ("https", true)
    );
    assert_eq!(local[0].tls.skip_verify, Some(true));
    let local_tls = hosts::resolve(&roots, "localhost", None).expect("hosts");
    assert_eq!(local_tls[0].scheme, "https");
    let forced = hosts::resolve(&roots, "ghcr.io", Some("http")).expect("hosts");
    assert_eq!(forced[0].scheme, "http");
}

#[test]
fn a_port_names_its_directory_with_underscores_and_default_is_the_last_resort() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    write(
        dir.path(),
        "reg.io_5000_/hosts.toml",
        "server = \"https://ported.example\"\n",
    );
    write(
        dir.path(),
        "_default/hosts.toml",
        "server = \"https://fallback.example\"\n",
    );
    let roots = [dir.path().to_path_buf()];
    let ported = hosts::resolve(&roots, "reg.io:5000", None).expect("hosts");
    assert_eq!(ported[0].host, "ported.example");
    let other = hosts::resolve(&roots, "other.io", None).expect("hosts");
    assert_eq!(other[0].host, "fallback.example");
}

#[test]
fn the_first_root_with_a_directory_wins() {
    let first = tempfile::tempdir().expect("a temporary directory");
    let second = tempfile::tempdir().expect("a temporary directory");
    write(
        second.path(),
        "reg.io/hosts.toml",
        "server = \"https://second.example\"\n",
    );
    let roots = [first.path().to_path_buf(), second.path().to_path_buf()];
    let found = hosts::host_dir(&roots, "reg.io").expect("a lookup");
    assert_eq!(found, Some(second.path().join("reg.io")));
    assert_eq!(hosts::host_dir(&roots, "none.io").expect("a lookup"), None);
}

#[test]
fn a_directory_without_hosts_toml_is_read_as_certificate_files() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    write(dir.path(), "reg.io/ca.crt", "ca");
    write(dir.path(), "reg.io/client.cert", "cert");
    write(dir.path(), "reg.io/client.key", "key");
    let loaded = hosts::load_host_dir(&dir.path().join("reg.io")).expect("hosts");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].ca(), [dir.path().join("reg.io/ca.crt")]);
    assert_eq!(
        loaded[0].client()[0].cert,
        dir.path().join("reg.io/client.cert")
    );
    assert_eq!(
        loaded[0].client()[0].key,
        Some(dir.path().join("reg.io/client.key"))
    );
}

#[test]
fn an_unreadable_hosts_toml_falls_back_to_the_certificate_files() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    write(dir.path(), "reg.io/hosts.toml", "server = [\n");
    write(dir.path(), "reg.io/ca.crt", "ca");
    let loaded = hosts::load_host_dir(&dir.path().join("reg.io")).expect("hosts");
    assert_eq!(loaded[0].ca(), [dir.path().join("reg.io/ca.crt")]);
}

#[test]
fn a_hosts_toml_that_is_wrong_names_the_key_and_the_position() {
    let error = hosts::parse_hosts_file(
        Path::new("/b"),
        "server = \"https://a.io\"\ncapabilities = [\"fly\"]\n",
    )
    .expect_err("a refusal");
    assert_eq!(error.key(), "capabilities");
    let error = hosts::parse_hosts_file(Path::new("/b"), "x = = 1\n").expect_err("a refusal");
    assert_eq!(error.position().map(|(line, _)| line), Some(1));
}

#[test]
fn http_with_tls_settings_is_https_with_a_plain_http_fallback() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    write(
        dir.path(),
        "reg.io/hosts.toml",
        "[host.\"http://m.io:5000\"]\n  skip_verify = true\n[host.\"http://p.io:80\"]\n  skip_verify = true\n",
    );
    let roots = [dir.path().to_path_buf()];
    let found = hosts::resolve(&roots, "reg.io", None).expect("hosts");
    assert_eq!(
        (found[0].scheme.as_str(), found[0].http_fallback),
        ("https", true)
    );
    assert_eq!(
        (found[1].scheme.as_str(), found[1].http_fallback),
        ("http", false)
    );
}

#[test]
fn the_newest_version_is_read_and_a_file_without_one_is_version_one() {
    let registry = registry_of(
        "version = 4\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/four\"\n",
    )
    .expect("a config");
    assert_eq!(
        registry.hosts,
        Hosts::ConfigPath(vec![PathBuf::from("/four")])
    );
    for header in ["", "version = 1\n"] {
        let registry = registry_of(&format!(
            "{header}[plugins.cri.registry]\nconfig_path = \"/legacy\"\n"
        ))
        .expect("a config");
        assert_eq!(
            registry.hosts,
            Hosts::ConfigPath(vec![PathBuf::from("/legacy")]),
            "{header:?}"
        );
    }
}

#[test]
fn plugin_lists_name_uris_unless_version_one_renames_them() {
    let error = registry_of("version = 2\ndisabled_plugins = [\"cri\"]\n").expect_err("a refusal");
    assert!(
        matches!(
            error,
            LoadError::PluginUri {
                list: "disabled",
                ..
            }
        ),
        "{error:?}"
    );
    let error = registry_of("version = 2\nrequired_plugins = [\"io.x.y\", \"cri\"]\n")
        .expect_err("a refusal");
    assert!(
        matches!(
            error,
            LoadError::PluginUri {
                list: "required",
                ..
            }
        ),
        "{error:?}"
    );
    registry_of("version = 2\ndisabled_plugins = [\"io.x.y\"]\n").expect("a config");
    registry_of("version = 1\ndisabled_plugins = [\"cri\"]\n").expect("a config");
    // The lists of all files are merged, and the merge is checked.
    let dir = tempfile::tempdir().expect("a temporary directory");
    write(
        dir.path(),
        "extra.toml",
        "version = 2\ndisabled_plugins = [\"cri\"]\n",
    );
    let main = write(
        dir.path(),
        "config.toml",
        "version = 2\nimports = [\"extra.toml\"]\n",
    );
    assert!(matches!(
        config::load(&main),
        Err(LoadError::PluginUri { .. })
    ));
}
