//! CRI-O's registry config against go.podman.io/image v5.40.0's own code (D66, D70): `registries.conf` and its drop-ins,
//! the per-host certificate directories and the credential files.
//!
//! The cases are the test data of go.podman.io/image (the seeds of the fuzz targets, and a mutation of each), the
//! files of the e2e CRI-O node, and the layouts of directories the library searches.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use secrecy::ExposeSecret;
use serde::Serialize;
use serde_json::{Value, json};
use speculaire_registry_config::crio::auth::{self, Lookup};
use speculaire_registry_config::crio::{Context, certs, registries};

use super::{CA, KEY, expect_same, oracle, seeds, seeds_and_mutations};

/// The files of the CRI-O e2e node: the only one is a drop-in named like the main file (`e2e/node/crio`).
const NODE_REGISTRIES: &str = include_str!("../data/crio/node-registries.conf");

/// A digest, to make references that have one.
const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// A layout of registry and auth cases: a label, the files, and what else the case sets.
type Layout<'a> = (&'a str, Vec<(&'a str, &'a str)>, fn(&mut Setup));

/// A layout of certificate cases: a label, the files, the host and port, and the uid.
type CertsLayout = (&'static str, Vec<(String, String)>, &'static str, u32);

/// The directory layout and the process inputs of one case; paths are relative to `root`.
#[derive(Clone, Serialize)]
struct Setup {
    root: PathBuf,
    files: BTreeMap<String, String>,
    uid: u32,
    home: String,
    xdg_config_home: Option<String>,
    xdg_runtime_dir: Option<String>,
    docker_config: Option<String>,
    env_registries_conf: Option<String>,
    env_registries_conf_override: Option<String>,
    registries_conf: Option<String>,
    registries_conf_dir: Option<String>,
    auth_file: Option<String>,
}

impl Setup {
    fn new(root: &Path, files: &[(&str, &str)]) -> Self {
        Self {
            root: root.to_owned(),
            files: files
                .iter()
                .map(|(name, text)| ((*name).to_owned(), (*text).to_owned()))
                .collect(),
            uid: 0,
            home: "home".to_owned(),
            xdg_config_home: None,
            xdg_runtime_dir: None,
            docker_config: None,
            env_registries_conf: None,
            env_registries_conf_override: None,
            registries_conf: None,
            registries_conf_dir: None,
            auth_file: None,
        }
    }

    fn context(&self) -> Context {
        let at = |path: &Option<String>| path.as_ref().map(|path| self.root.join(path));
        Context {
            root: self.root.clone(),
            uid: self.uid,
            home: self.root.join(&self.home),
            xdg_config_home: at(&self.xdg_config_home),
            xdg_runtime_dir: at(&self.xdg_runtime_dir),
            docker_config: at(&self.docker_config),
            env_registries_conf: at(&self.env_registries_conf),
            env_registries_conf_override: at(&self.env_registries_conf_override),
            registries_conf: at(&self.registries_conf),
            registries_conf_dir: at(&self.registries_conf_dir),
            auth_file: at(&self.auth_file),
        }
    }

    /// Lays the files out, as the oracle does.
    fn write(&self) {
        for (name, text) in &self.files {
            let path = self.root.join(name);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
            std::fs::write(path, text).expect("a file");
        }
    }
}

fn labelled<T: Serialize>(
    cases: &[(String, T)],
    subcommand: &str,
    ours: impl Fn(&T) -> Value,
    adjust: impl Fn(&mut Value, &mut Value),
) {
    let Some(oracle) = oracle() else { return };
    let asked: Vec<_> = cases.iter().map(|(_, case)| case).collect();
    let theirs: Vec<Value> = oracle.ask(subcommand, &asked).expect("the oracle answers");
    let both: Vec<(String, Value, Value)> = cases
        .iter()
        .zip(theirs)
        .map(|(case, mut theirs)| {
            let mut ours = ours(&case.1);
            adjust(&mut ours, &mut theirs);
            (case.0.clone(), ours, theirs)
        })
        .collect();
    expect_same(subcommand, &both);
}

// ---- registries ----

#[derive(Serialize)]
struct RegistriesCase {
    #[serde(flatten)]
    env: Setup,
    references: Vec<String>,
}

fn endpoint(e: &registries::Endpoint) -> Value {
    json!({
        "location": e.location,
        "insecure": e.insecure,
        "pull_from_mirror": e.pull_from_mirror,
    })
}

fn our_registries(case: &RegistriesCase) -> Value {
    case.env.write();
    let Ok(config) = registries::load(&case.env.context()) else {
        return json!({
            "error": true,
            "registries": [],
            "credential_helpers": [],
            "resolutions": [],
        });
    };
    let registries: Vec<Value> = config
        .registries
        .iter()
        .map(|r| {
            json!({
                "prefix": r.prefix,
                "location": r.endpoint.location,
                "insecure": r.endpoint.insecure,
                "blocked": r.blocked,
                "mirror_by_digest_only": r.mirror_by_digest_only,
                "mirrors": r.mirrors.iter().map(endpoint).collect::<Vec<_>>(),
            })
        })
        .collect();
    let resolutions: Vec<Value> = case
        .references
        .iter()
        .map(|reference| {
            let name = name_of(reference);
            let Some(registry) = config.find_registry(name) else {
                return json!({"reference": reference, "prefix": "", "sources": []});
            };
            match registry.pull_sources(reference) {
                Ok(sources) => json!({
                    "reference": reference,
                    "prefix": registry.prefix,
                    "sources": sources.iter().map(|s| {
                        let mut source = endpoint(s.endpoint);
                        source["reference"] = json!(s.reference);
                        source
                    }).collect::<Vec<_>>(),
                }),
                Err(_) => json!({
                    "reference": reference,
                    "prefix": registry.prefix,
                    "sources": [],
                    "error": true,
                }),
            }
        })
        .collect();
    json!({
        "registries": registries,
        "credential_helpers": config.credential_helpers,
        "resolutions": resolutions,
    })
}

/// `Name()` of a normalized reference: without its digest and tag.
fn name_of(reference: &str) -> &str {
    let reference = reference.split('@').next().unwrap_or(reference);
    match reference.rfind(':') {
        Some(colon) if !reference[colon..].contains('/') => &reference[..colon],
        _ => reference,
    }
}

/// References to ask about: the registries of the end-to-end suites, and every prefix and location of `text`.
fn references_for(text: &str) -> Vec<String> {
    let mut references: Vec<String> = [
        "docker.io/library/busybox:1.37",
        "registry.k8s.io/pause:3.10",
        "quay.io/org/image:v1",
        "ghcr.io/spnngl/speculaire:main",
        "registry.test:5000/app:1",
    ]
    .map(str::to_owned)
    .into();
    references.push(format!("docker.io/library/busybox@{DIGEST}"));
    for line in text.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !matches!(key.trim(), "prefix" | "location") {
            continue;
        }
        let value = value.trim().trim_matches('"').trim_end_matches('/');
        let value = value
            .strip_prefix("*")
            .map_or_else(|| value.to_owned(), |domain| format!("sub{domain}"));
        let first = value.split('/').next().unwrap_or_default();
        if !(first.contains('.') || first.contains(':') || first == "localhost")
            || !value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"./:-_".contains(&b))
        {
            continue;
        }
        // Docker Hub's names are normalized: a bare `docker.io` gains `library`, and `index.docker.io` is `docker.io`.
        let value = match value.as_str() {
            "docker.io" => "docker.io/library".to_owned(),
            other => other.to_owned(),
        };
        if value.starts_with("index.docker.io") {
            continue;
        }
        for reference in [format!("{value}/app:1"), format!("{value}/app@{DIGEST}")] {
            if !references.contains(&reference) && references.len() < 24 {
                references.push(reference);
            }
        }
    }
    references
}

fn registries_case(root: &Path, files: &[(&str, &str)], text: &str) -> RegistriesCase {
    RegistriesCase {
        env: Setup::new(root, files),
        references: references_for(text),
    }
}

/// Go's answer where its own parse of a rewritten reference failed is not ours to compare: only the prefix is.
fn adjust_registries(ours: &mut Value, theirs: &mut Value) {
    // The library parses every alias as a reference; this does not read aliases (D80): only a file that fails
    // for another reason, or none, is compared.
    if theirs["error"]
        .as_str()
        .is_some_and(|message| message.contains("validating short-name aliases"))
    {
        *ours = Value::Null;
        *theirs = Value::Null;
        return;
    }
    let (Some(ours), Some(theirs)) = (
        ours["resolutions"].as_array_mut(),
        theirs["resolutions"].as_array_mut(),
    ) else {
        return;
    };
    for (ours, theirs) in ours.iter_mut().zip(theirs.iter_mut()) {
        if theirs["error"].is_string() {
            // No prefix with an error: the library could not parse the reference, which is not a case.
            let unparsed = theirs["prefix"] == "";
            for resolution in [&mut *ours, &mut *theirs] {
                resolution["sources"] = Value::Null;
                resolution["error"] = Value::Null;
                if unparsed {
                    resolution["prefix"] = Value::Null;
                }
            }
        }
    }
}

fn layout_cases(root: &Path) -> Vec<(String, RegistriesCase)> {
    let admin = "[[registry]]\nprefix = \"docker.io\"\nlocation = \"docker.io\"\n[[registry.mirror]]\nlocation = \"127.0.0.1:7480/docker.io\"\npull-from-mirror = \"all\"\n[[registry]]\nprefix = \"registry.test:5000\"\nlocation = \"registry.test:5000\"\ninsecure = true\n";
    let other = "[[registry]]\nprefix = \"docker.io\"\nlocation = \"mirror.example/docker.io\"\n[[registry]]\nprefix = \"*.example.com\"\nlocation = \"\"\nblocked = true\n";
    let helpers = "credential-helpers = [\"containers-auth.json\"]\n";
    let layouts: Vec<Layout<'_>> = vec![
        (
            "the e2e node",
            vec![(
                "etc/containers/registries.conf.d/registries.conf",
                NODE_REGISTRIES,
            )],
            |_| {},
        ),
        ("no file at all", vec![], |_| {}),
        (
            "the e2e node with an admin drop-in",
            vec![
                (
                    "etc/containers/registries.conf.d/registries.conf",
                    NODE_REGISTRIES,
                ),
                ("etc/containers/registries.conf.d/99-admin.conf", admin),
            ],
            |_| {},
        ),
        (
            "the drop-in of a later name replaces the registry of its prefix",
            vec![
                ("etc/containers/registries.conf", other),
                ("etc/containers/registries.conf.d/50-a.conf", admin),
                ("etc/containers/registries.conf.d/10-z.conf", other),
            ],
            |_| {},
        ),
        (
            "the admin file hides the system file; drop-ins of both are read",
            vec![
                ("etc/containers/registries.conf", admin),
                ("usr/share/containers/registries.conf", other),
                ("usr/share/containers/registries.conf.d/20-sys.conf", other),
                ("etc/containers/registries.conf.d/30-adm.conf", helpers),
            ],
            |_| {},
        ),
        (
            "the system file alone",
            vec![("usr/share/containers/registries.conf", other)],
            |_| {},
        ),
        (
            "a drop-in of the same name in both directories: the admin's wins",
            vec![
                ("etc/containers/registries.conf.d/10-x.conf", admin),
                ("usr/share/containers/registries.conf.d/10-x.conf", other),
            ],
            |_| {},
        ),
        (
            "the rootful directories as root",
            vec![
                ("etc/containers/registries.rootful.conf.d/10-r.conf", admin),
                ("etc/containers/registries.rootless.conf.d/10-l.conf", other),
                ("etc/containers/registries.conf.d/05-c.conf", other),
            ],
            |_| {},
        ),
        (
            "the rootless directories of uid 1000",
            vec![
                ("etc/containers/registries.rootful.conf.d/10-r.conf", admin),
                ("etc/containers/registries.rootless.conf.d/10-l.conf", other),
                (
                    "etc/containers/registries.rootless.conf.d/1000/20-u.conf",
                    admin,
                ),
                ("etc/containers/registries.conf.d/05-c.conf", other),
            ],
            |e| e.uid = 1000,
        ),
        (
            "the user's file and drop-ins, from $HOME",
            vec![
                ("home/.config/containers/registries.conf", other),
                ("home/.config/containers/registries.conf.d/10-u.conf", admin),
                ("etc/containers/registries.conf", admin),
            ],
            |_| {},
        ),
        (
            "the user's file, from $XDG_CONFIG_HOME",
            vec![
                ("xdg/containers/registries.conf", other),
                ("home/.config/containers/registries.conf", admin),
            ],
            |e| e.xdg_config_home = Some("xdg".to_owned()),
        ),
        (
            "a named registries.conf and drop-in directory",
            vec![
                ("named/main.conf", admin),
                ("named/d/10-a.conf", other),
                ("etc/containers/registries.conf", other),
                ("etc/containers/registries.conf.d/10-b.conf", other),
            ],
            |e| {
                e.registries_conf = Some("named/main.conf".to_owned());
                e.registries_conf_dir = Some("named/d".to_owned());
            },
        ),
        (
            "a named registries.conf that is missing",
            vec![("etc/containers/registries.conf", other)],
            |e| e.registries_conf = Some("named/none.conf".to_owned()),
        ),
        (
            "the environment's file, and no drop-ins",
            vec![
                ("env/registries.conf", admin),
                ("etc/containers/registries.conf.d/10-b.conf", other),
            ],
            |e| e.env_registries_conf = Some("env/registries.conf".to_owned()),
        ),
        (
            "the environment's file that is missing",
            vec![("etc/containers/registries.conf", other)],
            |e| e.env_registries_conf = Some("env/none.conf".to_owned()),
        ),
        (
            "the environment's override after the drop-ins",
            vec![
                ("etc/containers/registries.conf", other),
                ("etc/containers/registries.conf.d/10-b.conf", other),
                ("env/override.conf", admin),
            ],
            |e| e.env_registries_conf_override = Some("env/override.conf".to_owned()),
        ),
        (
            "the environment's override that is missing",
            vec![("etc/containers/registries.conf", other)],
            |e| e.env_registries_conf_override = Some("env/none.conf".to_owned()),
        ),
        (
            "files that are not drop-ins",
            vec![
                ("etc/containers/registries.conf.d/10-a.txt", other),
                (
                    "etc/containers/registries.conf.d/dir.conf/inner.conf",
                    other,
                ),
                ("etc/containers/registries.conf.d/20-b.conf", admin),
            ],
            |_| {},
        ),
        (
            "a file that is not valid",
            vec![
                ("etc/containers/registries.conf", "[[registry]\n"),
                ("etc/containers/registries.conf.d/10-a.conf", admin),
            ],
            |_| {},
        ),
        (
            "a drop-in that is not valid",
            vec![
                ("etc/containers/registries.conf", admin),
                (
                    "etc/containers/registries.conf.d/10-a.conf",
                    "[[registry]]\nlocation = \"https://x.io\"\n",
                ),
            ],
            |_| {},
        ),
        (
            "credential helpers of a drop-in replace those of the file",
            vec![
                (
                    "etc/containers/registries.conf",
                    "credential-helpers = [\"a\", \"b\"]\n",
                ),
                (
                    "etc/containers/registries.conf.d/10-a.conf",
                    "credential-helpers = []\n",
                ),
            ],
            |_| {},
        ),
        (
            "the empty array of a drop-in does not hide the helpers of the file",
            vec![
                (
                    "etc/containers/registries.conf",
                    "credential-helpers = [\"a\"]\n",
                ),
                ("etc/containers/registries.conf.d/10-a.conf", admin),
            ],
            |_| {},
        ),
    ];
    layouts
        .into_iter()
        .enumerate()
        .map(|(n, (label, files, set))| {
            let text: String = files.iter().map(|(_, text)| *text).collect();
            let mut case = registries_case(&root.join(format!("layout-{n}")), &files, &text);
            set(&mut case.env);
            (format!("layout {n}: {label}"), case)
        })
        .collect()
}

#[test]
fn registries_agree_with_go_podman_io_image() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut cases = layout_cases(dir.path());
    let files = seeds("registries_conf");
    // The test data of the library, each file as `registries.conf`.
    for (n, bytes) in files.iter().enumerate() {
        let text = String::from_utf8_lossy(bytes).into_owned();
        cases.push((
            format!("seed {n}"),
            registries_case(
                &dir.path().join(format!("data-{n}")),
                &[("etc/containers/registries.conf", &text)],
                &text,
            ),
        ));
    }
    for (n, text) in seeds_and_mutations("registries_conf", 100)
        .into_iter()
        .enumerate()
    {
        cases.push((
            format!("mutation {n}: {text:?}"),
            registries_case(
                &dir.path().join(format!("mutation-{n}")),
                &[("etc/containers/registries.conf", &text)],
                &text,
            ),
        ));
    }
    // A struct is read from a table alone, and a map from anything but a table is none.
    for (n, text) in [
        "registry = [[\"a.io\"]]\n",
        "registry = [[\"a.io\", \"a.io\"]]\n",
        "[[registry]]\nprefix = \"a.io\"\nmirror = [[\"m.io\"]]\n",
        "registries = []\n",
        "[registries]\nsearch = [[\"a.io\"]]\n",
        "aliases = 1\n",
        "aliases = [\"x\"]\n",
        "aliases = 1\n[[registry]]\nlocation = \"a.io\"\n",
    ]
    .into_iter()
    .enumerate()
    {
        cases.push((
            format!("types {n}: {text:?}"),
            registries_case(
                &dir.path().join(format!("types-{n}")),
                &[("etc/containers/registries.conf", text)],
                text,
            ),
        ));
    }
    labelled(&cases, "registries", our_registries, adjust_registries);
}

// ---- certs ----

#[derive(Serialize)]
struct CertsCase {
    #[serde(flatten)]
    env: Setup,
    host_port: String,
}

fn our_certs(case: &CertsCase) -> Value {
    case.env.write();
    let ctx = case.env.context();
    let relative = |path: &Path| {
        path.strip_prefix(&case.env.root)
            .expect("below the root")
            .to_string_lossy()
            .into_owned()
    };
    match certs::cert_dir(&ctx, &case.host_port) {
        Err(_) => json!({"dir": "", "error": true, "clients": 0}),
        Ok(None) => json!({"dir": "", "clients": 0}),
        Ok(Some(dir)) => {
            let shown = format!("/{}", relative(&dir));
            match certs::setup(&dir) {
                Ok(found) => json!({"dir": shown, "clients": found.client.len()}),
                Err(_) => json!({"dir": shown, "error": true, "clients": 0}),
            }
        }
    }
}

fn certs_cases(root: &Path) -> Vec<(String, CertsCase)> {
    let pair = |dir: &str| -> Vec<(String, String)> {
        vec![
            (format!("{dir}/ca.crt"), CA.to_owned()),
            (format!("{dir}/client.cert"), CA.to_owned()),
            (format!("{dir}/client.key"), KEY.to_owned()),
        ]
    };
    let layouts: Vec<CertsLayout> = vec![
        (
            "containers/certs.d",
            pair("etc/containers/certs.d/reg.test:5000"),
            "reg.test:5000",
            0,
        ),
        (
            "docker/certs.d",
            pair("etc/docker/certs.d/reg.test:5000"),
            "reg.test:5000",
            0,
        ),
        (
            "containers first",
            [
                pair("etc/containers/certs.d/reg.test"),
                pair("etc/docker/certs.d/reg.test"),
            ]
            .concat(),
            "reg.test",
            0,
        ),
        (
            "system",
            pair("usr/share/containers/certs.d/reg.test"),
            "reg.test",
            0,
        ),
        (
            "rootful",
            pair("etc/containers/certs.rootful.d/reg.test"),
            "reg.test",
            0,
        ),
        (
            "rootless of root",
            pair("etc/containers/certs.rootless.d/reg.test"),
            "reg.test",
            0,
        ),
        (
            "rootless of 1000",
            pair("etc/containers/certs.rootless.d/1000/reg.test"),
            "reg.test",
            1000,
        ),
        (
            "rootless without uid dir",
            pair("etc/containers/certs.rootless.d/reg.test"),
            "reg.test",
            1000,
        ),
        (
            "user",
            pair("home/.config/containers/certs.d/reg.test"),
            "reg.test",
            0,
        ),
        (
            "other host",
            pair("etc/containers/certs.d/other.test"),
            "reg.test",
            0,
        ),
        ("no directory", vec![], "reg.test", 0),
        (
            "ca only",
            vec![(
                "etc/containers/certs.d/reg.test/ca.crt".to_owned(),
                CA.to_owned(),
            )],
            "reg.test",
            0,
        ),
        (
            "cert without key",
            vec![(
                "etc/containers/certs.d/reg.test/client.cert".to_owned(),
                CA.to_owned(),
            )],
            "reg.test",
            0,
        ),
        (
            "key without cert",
            vec![(
                "etc/containers/certs.d/reg.test/client.key".to_owned(),
                KEY.to_owned(),
            )],
            "reg.test",
            0,
        ),
        (
            "two pairs and a ca",
            [
                pair("etc/containers/certs.d/reg.test"),
                vec![
                    (
                        "etc/containers/certs.d/reg.test/second.cert".to_owned(),
                        CA.to_owned(),
                    ),
                    (
                        "etc/containers/certs.d/reg.test/second.key".to_owned(),
                        KEY.to_owned(),
                    ),
                    (
                        "etc/containers/certs.d/reg.test/other.txt".to_owned(),
                        String::new(),
                    ),
                ],
            ]
            .concat(),
            "reg.test",
            0,
        ),
        (
            "an empty directory",
            vec![(
                "etc/containers/certs.d/reg.test/.keep".to_owned(),
                String::new(),
            )],
            "reg.test",
            0,
        ),
        (
            "upper-case extensions are not certificates",
            vec![
                (
                    "etc/containers/certs.d/reg.test/CA.CRT".to_owned(),
                    CA.to_owned(),
                ),
                (
                    "etc/containers/certs.d/reg.test/c.CERT".to_owned(),
                    CA.to_owned(),
                ),
            ],
            "reg.test",
            0,
        ),
    ];
    layouts
        .into_iter()
        .enumerate()
        .map(|(n, (label, files, host_port, uid))| {
            let files: Vec<(&str, &str)> = files
                .iter()
                .map(|(name, text)| (name.as_str(), text.as_str()))
                .collect();
            let mut env = Setup::new(&root.join(format!("certs-{n}")), &files);
            env.uid = uid;
            (
                format!("certs {n}: {label}"),
                CertsCase {
                    env,
                    host_port: host_port.to_owned(),
                },
            )
        })
        .collect()
}

#[test]
fn certs_agree_with_go_podman_io_image() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let cases = certs_cases(dir.path());
    labelled(&cases, "certs", our_certs, |_, _| {});
}

// ---- auth ----

#[derive(Serialize)]
struct AuthCase {
    #[serde(flatten)]
    env: Setup,
    keys: Vec<String>,
}

fn our_auth(case: &AuthCase) -> Value {
    case.env.write();
    let ctx = case.env.context();
    let helpers = match registries::load(&ctx) {
        Ok(config) => config.credential_helpers,
        Err(_) => {
            return Value::Array(
                case.keys
                    .iter()
                    .map(|key| json!({"key": key, "login": null, "error": true}))
                    .collect(),
            );
        }
    };
    Value::Array(
        case.keys
            .iter()
            .map(|key| match auth::credentials(&ctx, &helpers, key) {
                Ok(Lookup::Found(found)) => json!({
                    "key": key,
                    "login": {
                        "username": found.username,
                        "password": found.password.expose_secret(),
                        "identity_token": found.identity_token.expose_secret(),
                    },
                }),
                Ok(Lookup::NotFound) => json!({"key": key, "login": null}),
                // The library runs the helper, which is not installed here: it fails.
                Ok(Lookup::Helper(_)) | Err(_) => json!({"key": key, "login": null, "error": true}),
            })
            .collect(),
    )
}

/// The keys to look up for the entries of an auth file: each entry and the namespaces above it, and a few more.
fn keys_for(text: &str) -> Vec<String> {
    let mut keys: Vec<String> = [
        "docker.io",
        "docker.io/library/busybox",
        "registry-1.docker.io",
        "quay.io/org/image",
        "example.com",
        "localhost:5000/app",
        "registry.test:5000",
    ]
    .map(str::to_owned)
    .into();
    let mut entries = Vec::new();
    if let Ok(Value::Object(file)) = serde_json::from_str::<Value>(text) {
        for (name, value) in &file {
            if let (true, Value::Object(map)) = (name.eq_ignore_ascii_case("auths"), value) {
                entries.extend(map.keys().cloned());
            } else {
                entries.push(name.clone());
            }
        }
    }
    for entry in entries {
        let entry = entry
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_owned();
        if entry.is_empty() || entry.contains(['@', ' ']) {
            continue;
        }
        for key in [entry.clone(), format!("{entry}/ns/image")] {
            if !keys.contains(&key) && keys.len() < 24 && !key.contains("/ns/image:") {
                keys.push(key);
            }
        }
    }
    keys
}

fn auth_case(root: &Path, uid: u32, files: &[(&str, &str)], text: &str) -> AuthCase {
    let mut env = Setup::new(root, files);
    env.uid = uid;
    AuthCase {
        env,
        keys: keys_for(text),
    }
}

const LOGIN: &str = r#"{"auths": {"docker.io": {"auth": "dXNlcjpwYXNz"}, "quay.io/org": {"auth": "b3JnOnRva2Vu"}, "example.com": {"auth": "ZXhhbXBsZTpwdw==", "identitytoken": "tok"}}}"#;
const OTHER: &str = r#"{"auths": {"docker.io": {"auth": "b3RoZXI6b3RoZXI="}, "https://index.docker.io/v1/": {"auth": "aGlzdG9yaWM6cGFzcw=="}, "registry.test:5000": {"auth": "dGVzdDpwdw=="}}, "credHelpers": {"helper.test": "nonexistent"}}"#;
const LEGACY: &str = r#"{"https://registry.test:5000/v1/": {"auth": "bGVnYWN5OnB3"}}"#;

fn auth_layouts(root: &Path, uid: u32) -> Vec<(String, AuthCase)> {
    let run = format!("run/containers/{uid}/auth.json");
    let run = run.as_str();
    let layouts: Vec<Layout<'_>> = vec![
        ("no file", vec![], |_| {}),
        ("the runtime file", vec![(run, LOGIN)], |_| {}),
        (
            "the runtime file, then the config home",
            vec![(run, LOGIN), ("home/.config/containers/auth.json", OTHER)],
            |_| {},
        ),
        (
            "the config home, then Docker's",
            vec![
                ("home/.config/containers/auth.json", LOGIN),
                ("home/.docker/config.json", OTHER),
            ],
            |_| {},
        ),
        (
            "Docker's file",
            vec![("home/.docker/config.json", OTHER)],
            |_| {},
        ),
        (
            "DOCKER_CONFIG",
            vec![
                ("dc/config.json", OTHER),
                ("home/.docker/config.json", LOGIN),
            ],
            |e| e.docker_config = Some("dc".to_owned()),
        ),
        (
            "XDG_CONFIG_HOME",
            vec![
                ("xdg/containers/auth.json", OTHER),
                ("home/.config/containers/auth.json", LOGIN),
            ],
            |e| e.xdg_config_home = Some("xdg".to_owned()),
        ),
        ("the legacy file", vec![("home/.dockercfg", LEGACY)], |_| {}),
        (
            "a named file is the only one",
            vec![
                ("named.json", LOGIN),
                ("home/.docker/config.json", OTHER),
                (run, OTHER),
            ],
            |e| e.auth_file = Some("named.json".to_owned()),
        ),
        (
            "a named file that is missing",
            vec![("home/.docker/config.json", OTHER)],
            |e| e.auth_file = Some("none.json".to_owned()),
        ),
        (
            "a file that is not valid",
            vec![(run, "{"), ("home/.docker/config.json", OTHER)],
            |_| {},
        ),
        (
            "an empty file",
            vec![(run, ""), ("home/.docker/config.json", OTHER)],
            |_| {},
        ),
        (
            "a login that is not base64",
            vec![
                (run, r#"{"auths": {"docker.io": {"auth": "!!"}}}"#),
                ("home/.docker/config.json", OTHER),
            ],
            |_| {},
        ),
        (
            "a login without a colon is skipped, in this file only",
            vec![
                (run, r#"{"auths": {"docker.io": {"auth": "dXNlcg=="}}}"#),
                ("home/.docker/config.json", OTHER),
            ],
            |_| {},
        ),
        (
            "an empty login is not one",
            vec![
                (run, r#"{"auths": {"docker.io": {"auth": "Og=="}}}"#),
                ("home/.docker/config.json", OTHER),
            ],
            |_| {},
        ),
        (
            "keys in any case",
            vec![(
                run,
                r#"{"AUTHS": {"docker.io": {"AUTH": "dXNlcjpwYXNz", "IdentityToken": "t"}}}"#,
            )],
            |_| {},
        ),
        (
            "credential helpers that are not the files",
            vec![
                (run, LOGIN),
                (
                    "etc/containers/registries.conf",
                    "credential-helpers = [\"nonexistent\"]\n",
                ),
            ],
            |_| {},
        ),
        (
            "the helper of the files, named",
            vec![
                (run, LOGIN),
                (
                    "etc/containers/registries.conf",
                    "credential-helpers = [\"containers-auth.json\"]\n",
                ),
            ],
            |_| {},
        ),
    ];
    layouts
        .into_iter()
        .enumerate()
        .map(|(n, (label, files, set))| {
            let text: String = files.iter().map(|(_, text)| *text).collect();
            let mut case = auth_case(&root.join(format!("auth-{n}")), uid, &files, &text);
            set(&mut case.env);
            (format!("auth {n}: {label}"), case)
        })
        .collect()
}

#[test]
fn credentials_agree_with_go_podman_io_image() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    // The library puts the user's runtime file at the uid of the process, which the oracle cannot be told.
    let uid = std::fs::metadata(dir.path()).expect("a directory").uid();
    let mut cases = auth_layouts(dir.path(), uid);
    for (n, bytes) in seeds("auth_json").iter().enumerate() {
        let text = String::from_utf8_lossy(bytes).into_owned();
        let run = format!("run/containers/{uid}/auth.json");
        cases.push((
            format!("seed {n}"),
            auth_case(
                &dir.path().join(format!("data-{n}")),
                uid,
                &[(&run, &text)],
                &text,
            ),
        ));
    }
    for (n, text) in seeds_and_mutations("auth_json", 100)
        .into_iter()
        .enumerate()
    {
        let run = format!("run/containers/{uid}/auth.json");
        cases.push((
            format!("mutation {n}: {text:?}"),
            auth_case(
                &dir.path().join(format!("mutation-{n}")),
                uid,
                &[(&run, &text)],
                &text,
            ),
        ));
    }
    labelled(&cases, "auth", our_auth, |_, _| {});
}
