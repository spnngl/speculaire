//! What preflight and the required plugins say of a containerd on a temporary tree.

use crate::detect::Runtime;
use crate::fixture::{Tree, has, put};
use crate::wiring::Error;

fn configured() -> Tree {
    Tree::configured(Runtime::Containerd)
}

fn exports(tree: &Tree, discard: bool, path: &str) {
    tree.update(|answers| {
        answers.image_exports = Some((discard, path.to_owned()));
    });
}

#[test]
fn the_nri_validator_names_the_plugins_it_requires() {
    let node = Tree::new(Runtime::Containerd);
    node.containerd();
    let config = node.containerd_config();
    let text = std::fs::read_to_string(&config).unwrap();
    let nri = "\n[plugins.\"io.containerd.nri.v1.nri\".default_validator]\n  enable = true\n  required_plugins = [\"speculaire\"]\n";
    std::fs::write(&config, format!("{text}{nri}")).unwrap();
    let required = node.node.settings().required_plugins().unwrap();
    assert_eq!(required.runtime, "containerd");
    assert!(required.key.contains("required_plugins"), "{required:?}");
    assert_eq!(required.plugins, ["speculaire"]);
    // Another plugin is another plugin.
    std::fs::write(&config, text + &nri.replace("speculaire", "other")).unwrap();
    assert_eq!(
        node.node.settings().required_plugins().unwrap().plugins,
        ["other"]
    );
}

#[test]
fn containerd_without_a_config_file_has_no_required_plugin_but_a_bad_config_is_an_error() {
    let node = Tree::new(Runtime::Containerd);
    // No `config.toml`: containerd's defaults, and so no NRI validator.
    assert_eq!(
        node.node.settings().required_plugins().unwrap().plugins,
        Vec::<String>::new()
    );
    // A `config.toml` that cannot be read is not the same as none.
    std::fs::create_dir_all(node.containerd_config()).unwrap();
    let err = node.node.settings().required_plugins().unwrap_err();
    assert!(matches!(err, Error::Containerd { .. }), "{err}");
}

#[test]
fn a_missing_import_is_an_error_as_containerd_refuses_to_load_it() {
    let node = Tree::new(Runtime::Containerd);
    node.containerd();
    let config = node.containerd_config();
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, format!("imports = [\"gone.toml\"]\n{text}")).unwrap();
    let err = node.node.settings().required_plugins().unwrap_err();
    assert!(err.to_string().contains("gone.toml"), "{err}");
}

#[test]
fn containerd_2_4_is_asked_for_what_its_image_service_runs_with() {
    let node = configured();
    exports(&node, true, "/etc/containerd/certs.d");
    let problems = node.preflight();
    assert!(
        has(
            &problems,
            &[
                "/etc/containerd/config.toml",
                "`discard_unpacked_layers = true`",
                "set it to false"
            ]
        ),
        "{problems:?}"
    );
    exports(&node, false, "");
    let problems = node.preflight();
    assert!(
        has(
            &problems,
            &[
                "/etc/containerd/config.toml",
                "`config_path` is not set",
                "\"/etc/containerd/certs.d\""
            ]
        ),
        "{problems:?}"
    );
    node.update(|answers| answers.image_exports = None);
    assert!(has(
        &node.preflight(),
        &["/run/containerd.sock", "`io.containerd.cri.v1.images`"]
    ));
    node.update(|answers| {
        answers.image_exports = Some((false, "/etc/containerd/certs.d".to_owned()));
        answers.plugins_unavailable = true;
    });
    assert!(has(
        &node.preflight(),
        &["/run/containerd.sock", "Unavailable"]
    ));
    node.update(|answers| answers.plugins_unavailable = false);
    // The config file says false, the running image service true: the running one counts.
    put(
        &node.containerd_config(),
        "version = 3\n[plugins.'io.containerd.cri.v1.images']\ndiscard_unpacked_layers = false\n",
    );
    exports(&node, true, "/x");
    assert!(has(
        &node.preflight(),
        &["`discard_unpacked_layers = true`"]
    ));
}

#[test]
fn containerd_2_3_has_its_image_settings_read_from_the_config_file() {
    let node = configured();
    node.version("containerd", "v2.3.7");
    // The running image service is not asked: these exports would be refused.
    node.update(|answers| answers.plugins_unavailable = true);
    assert_eq!(node.preflight(), Vec::<String>::new());
    for (text, key) in [
        (
            "version = 3\n[plugins.'io.containerd.cri.v1.images']\ndiscard_unpacked_layers = true\n",
            "`discard_unpacked_layers = true`",
        ),
        (
            "version = 2\n[plugins.'io.containerd.grpc.v1.cri'.containerd]\ndiscard_unpacked_layers = true\n[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.runc]\nruntime_type = 'x'\n",
            "`discard_unpacked_layers = true`",
        ),
        (
            "version = 2\n[plugins.'io.containerd.grpc.v1.cri'.registry.mirrors.'docker.io']\nendpoint = ['https://m.io']\n",
            "`config_path` is not set",
        ),
    ] {
        put(&node.containerd_config(), text);
        let problems = node.preflight();
        assert!(
            has(&problems, &["/etc/containerd/config.toml", key]),
            "{text}: {problems:?}"
        );
    }
    // Without a config file, containerd runs on its defaults: config_path set, nothing discarded.
    std::fs::remove_file(node.containerd_config()).unwrap();
    assert_eq!(node.preflight(), Vec::<String>::new());
    // An invalid registry section is named; so is a config that is no TOML.
    put(
        &node.containerd_config(),
        "version = 3\n[plugins.'io.containerd.cri.v1.images'.registry]\nconfig_path = '/x'\n[plugins.'io.containerd.cri.v1.images'.registry.mirrors.'a.io']\nendpoint = ['https://m.io']\n",
    );
    assert!(has(
        &node.preflight(),
        &[
            "the registry section is invalid",
            "`mirrors` cannot be set when `config_path` is provided"
        ]
    ));
    put(&node.containerd_config(), "version = ");
    assert!(has(
        &node.preflight(),
        &[
            "/etc/containerd/config.toml",
            "cannot read containerd's config"
        ]
    ));
}

#[test]
fn nri_that_is_off_or_closed_is_refused_naming_each_key() {
    let node = configured();
    for (text, parts) in [
        (
            "version = 3\n[plugins.'io.containerd.nri.v1.nri']\ndisable = true\n",
            &[
                "`disable = true` in [plugins.'io.containerd.nri.v1.nri']",
                "set it to false",
            ][..],
        ),
        (
            "version = 3\n[plugins.'io.containerd.nri.v1.nri']\ndisable_connections = true\n",
            &[
                "`disable_connections = true` in [plugins.'io.containerd.nri.v1.nri']",
                "restart containerd",
            ],
        ),
        (
            "version = 3\ndisabled_plugins = ['io.containerd.nri.v1.nri']\n",
            &[
                "`io.containerd.nri.v1.nri` is in `disabled_plugins`",
                "remove it",
            ],
        ),
    ] {
        put(&node.containerd_config(), text);
        let problems = node.preflight();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            has(&problems, &["/etc/containerd/config.toml", "(D54)"]),
            "{problems:?}"
        );
        assert!(has(&problems, parts), "{problems:?}");
    }
    put(
        &node.containerd_config(),
        "version = 3\ndisabled_plugins = ['io.containerd.nri.v1.nri']\n[plugins.'io.containerd.nri.v1.nri']\ndisable = true\ndisable_connections = true\n",
    );
    assert_eq!(node.preflight().len(), 3);
}
