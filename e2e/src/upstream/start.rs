//! What `just e2e-up` starts beside the cluster (D94, D112): the four upstreams, the test images on each, the recorded
//! Sigstore fixtures on two (D141), and each node's runtime config for them.

use std::path::Path;
use std::time::Instant;

use speculaire_artifacts::testing::{Expected, Signer};

use super::{Kind, Upstream};
use crate::registry::{
    self, Access, COPY_IMAGE, COSIGN_IMAGE, Certificates, Container, LABEL, NETWORK, PASSWORD,
    PLATFORM, REFERRERS_IMAGE, Registry, TokenServer, USER, docker, fail, regctl_after, scratch,
};
use crate::{Cluster, Failure, Runtime, TEST_IMAGE, hub};

/// The signed test image on every upstream: a Sigstore bundle signature, a SLSA provenance and an SPDX attestation as
/// referrers, and a legacy `.sig` and `.att` tag (D112). For discovery tests only: signed with no transparency log
/// entry, it never verifies (D142); a test that needs an allowed image runs [`RUNNABLE`].
pub const SIGNED: &str = "e2e/signed:1";
/// [`TEST_IMAGE`] with another annotation, so another digest, and nothing that refers to it.
pub const UNSIGNED: &str = "e2e/unsigned:1";
/// Each node's copy of the public key that verifies [`SIGNED`], PEM; each `just e2e-up` makes a new key pair.
pub const COSIGN_PUBLIC_KEY: &str = "/etc/speculaire-e2e/cosign.pub";
/// The auth file CRI-O's `global_auth_file` names, which holds the private upstream's login (D89).
pub const CRIO_AUTH_FILE: &str = "/etc/crio/e2e-auth.json";
/// The repository of the recorded Sigstore fixtures (D141) on zot and on the plain upstream, one tag per case.
pub const FIXTURES: &str = "e2e/fixtures";
/// The fixture case a pod runs, a tag of [`FIXTURES`]: [`TEST_IMAGE`] with a file of its own, for `linux/amd64` and
/// `linux/arm64`, signed keyless by the recording workflow (D164). [`runnable_policy`] allows it.
pub const RUNNABLE: &str = "runnable";

/// A `ClusterImagePolicy` that allows [`RUNNABLE`] from the upstream at `host` by the identity the recording names.
///
/// # Panics
///
/// When the recording names no keyless signer for [`RUNNABLE`].
#[must_use]
pub fn runnable_policy(host: &str) -> String {
    let (san, issuer) = match Expected::of(RUNNABLE).signer {
        Some(Signer::Keyless { san, issuer }) => Some((san, issuer)),
        Some(Signer::Key { .. }) | None => None,
    }
    .expect("the recording names the runnable case's keyless signer");
    format!(
        "apiVersion: policy.sigstore.dev/v1beta1\nkind: ClusterImagePolicy\nmetadata:\n  name: {RUNNABLE}\nspec:\n  \
         images:\n  - glob: {host}/{FIXTURES}\n  authorities:\n  - keyless:\n      identities:\n      - issuer: {issuer}\n        \
         subject: {san}\n"
    )
}

/// The fixtures' OCI layouts, one directory per case.
const LAYOUTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/sigstore/layouts");

/// zot on port 80, plain HTTP: a name with a port is not mirrored on CRI-O (D88).
const ZOT_CONFIG: &str = r#"{"distSpecVersion":"1.1.1","storage":{"rootDirectory":"/var/lib/registry"},"http":{"address":"0.0.0.0","port":"80"},"log":{"level":"info"}}"#;
/// The predicates of the attestations.
const SLSA: &str = include_str!("../../fixtures/slsa.json");
/// See [`SLSA`].
const SPDX: &str = include_str!("../../fixtures/spdx.json");
/// Signs with the run's key, and nothing else: no Fulcio, no Rekor, no TUF fetch of the public-good signing config.
const OFFLINE: [&str; 6] = [
    "--key",
    "cosign.key",
    "--tlog-upload=false",
    "--use-signing-config=false",
    "--allow-http-registry",
    "--allow-insecure-registry",
];

/// Starts the upstreams of [`Kind`], pushes [`SIGNED`] and [`UNSIGNED`] to each and [`FIXTURES`] to zot and the plain
/// one, pins the fixtures' trusted root on every node and points its runtime at them. They live as long as the cluster;
/// what fails on the way is removed.
///
/// # Errors
///
/// When a container, a `regctl` or `cosign` command, or a node's command fails.
pub fn start(cluster: &Cluster) -> Result<(), Failure> {
    let [plain, referrers, private, public] = Kind::ALL.map(|kind| cluster.upstream(kind));
    let token = format!("{}-token.e2e.test", cluster.name);
    let private_tls = Certificates::new(
        &format!("{}-private", cluster.name),
        &[private.address(), &token],
    )?;
    let public_tls = Certificates::new(&format!("{}-public", cluster.name), &[public.address()])?;
    let registries = [
        Registry::start(plain.address(), &Access::Open, None)?,
        Registry::start(
            private.address(),
            &Access::Token {
                certificates: &private_tls,
                realm: &format!("https://{token}:5001/auth"),
            },
            None,
        )?,
        Registry::start(public.address(), &Access::Tls(&public_tls), None)?,
    ];
    let token_server = TokenServer::start(&token, &private_tls, &registry::htpasswd()?)?;
    let zot = start_zot(referrers.address())?;

    let building = Instant::now();
    let public_key = build(cluster, &referrers)?;
    copy(&referrers, &[&plain, &private, &public])?;
    push_fixtures(&[&referrers, &plain])?;
    eprintln!(
        "e2e: the test images and fixtures took {:.1} s",
        building.elapsed().as_secs_f64()
    );

    for node in cluster.nodes()? {
        let node = &node.name;
        cluster.write(node, COSIGN_PUBLIC_KEY, &public_key)?;
        cluster.pin(node)?;
        // The public upstream's CA, only in the system trust store.
        cluster.write(
            node,
            "/usr/local/share/ca-certificates/speculaire-e2e-public.crt",
            public_tls.ca(),
        )?;
        cluster.sh(node, "update-ca-certificates >/dev/null")?;
        match cluster.runtime {
            Runtime::Containerd => {
                for upstream in [&plain, &referrers] {
                    let host = upstream.address();
                    cluster.write(
                        node,
                        &format!("/etc/containerd/certs.d/{host}/hosts.toml"),
                        &format!(
                            "server = \"http://{host}\"\n\n[host.\"http://{host}\"]\n  capabilities = [\"pull\", \"resolve\"]\n"
                        ),
                    )?;
                }
            }
            Runtime::Crio => {
                let entry = |upstream: &Upstream, insecure: bool| {
                    let host = upstream.address();
                    format!(
                        "[[registry]]\nprefix = \"{host}\"\nlocation = \"{host}\"\ninsecure = {insecure}\n"
                    )
                };
                // The private upstream has an entry too, so that `speculaire configure` mirrors it.
                cluster.write(
                    node,
                    "/etc/containers/registries.conf.d/50-e2e-upstream.conf",
                    &format!(
                        "{}\n{}\n{}",
                        entry(&plain, true),
                        entry(&referrers, true),
                        entry(&private, false)
                    ),
                )?;
            }
        }
        log_in(cluster, node, private.address(), private_tls.ca())?;
        // The runtime reads its logins and the system trust store when it starts.
        let unit = match cluster.runtime {
            Runtime::Containerd => "containerd",
            Runtime::Crio => "crio",
        };
        cluster.sh(node, &format!("systemctl restart {unit}"))?;
    }

    for registry in registries {
        registry.keep();
    }
    token_server.keep();
    zot.keep();
    Ok(())
}

/// Writes the login of [`super::USER`] to `host`, and its CA, into the node's runtime config, where the agent reads
/// them too (D89): on containerd, `registry.configs."<host>".auth` of `config.toml` and the `ca` of the host's
/// `hosts.toml`; on CRI-O, the auth file `global_auth_file` names and `/etc/containers/certs.d/<host>/ca.crt`. The
/// runtime reads them at its next start.
fn log_in(cluster: &Cluster, node: &str, host: &str, ca: &str) -> Result<(), Failure> {
    let login = format!("{USER}:{PASSWORD}");
    match cluster.runtime {
        Runtime::Containerd => {
            let dir = format!("/etc/containerd/certs.d/{host}");
            cluster.write(node, &format!("{dir}/ca.crt"), ca)?;
            cluster.write(
                node,
                &format!("{dir}/hosts.toml"),
                &format!(
                    "server = \"https://{host}\"\n\n[host.\"https://{host}\"]\n  capabilities = [\"pull\", \"resolve\"]\n  ca = \"{dir}/ca.crt\"\n"
                ),
            )?;
            // The node's config is of version 2, which keeps the registry under the CRI plugin. Once: a table twice
            // is a TOML error.
            let table =
                format!("[plugins.\"io.containerd.grpc.v1.cri\".registry.configs.\"{host}\".auth]");
            cluster.sh(
                node,
                &format!(
                    "grep -qF '{table}' /etc/containerd/config.toml \
                     || printf '\\n%s\\n  username = \"{USER}\"\\n  password = \"{PASSWORD}\"\\n' '{table}' \
                     >>/etc/containerd/config.toml"
                ),
            )?;
        }
        Runtime::Crio => {
            cluster.write(node, &format!("/etc/containers/certs.d/{host}/ca.crt"), ca)?;
            cluster.write(
                node,
                "/etc/crio/crio.conf.d/30-e2e-auth.conf",
                &format!("[crio.image]\nglobal_auth_file = \"{CRIO_AUTH_FILE}\"\n"),
            )?;
            cluster.sh(
                node,
                &format!(
                    "auth=$(printf %s '{login}' | base64) \
                     && printf '{{\"auths\":{{\"{host}\":{{\"auth\":\"%s\"}}}}}}\\n' \"$auth\" >{CRIO_AUTH_FILE}"
                ),
            )?;
        }
    }
    Ok(())
}

/// Starts zot as `name`, the upstream of [`Kind::Referrers`].
fn start_zot(name: &str) -> Result<Container, Failure> {
    let scratch = scratch(name)?;
    let config = scratch.join("config.json");
    std::fs::write(&config, ZOT_CONFIG).map_err(|e| fail("write zot's config", &e))?;
    let container = Container::start(
        name,
        REFERRERS_IMAGE,
        &[],
        &[(&config, "/etc/zot/config.json")],
        &["serve", "/etc/zot/config.json"],
    )?;
    // zot sets up its UI routes last, then listens; it logs no line of its own when it does.
    container.wait_for_log("ui routes")?;
    let _ = std::fs::remove_dir_all(&scratch);
    Ok(container)
}

/// Pushes [`SIGNED`] and [`UNSIGNED`] to `zot`, then signs and attests [`SIGNED`] there with a new key pair, offline,
/// and returns its public key.
fn build(cluster: &Cluster, zot: &Upstream) -> Result<String, Failure> {
    let host = zot.address();
    let push = |image: &str| {
        let copy = hub::from_first(TEST_IMAGE, |source| {
            format!("regctl image copy --platform {PLATFORM} {source} {host}/{image}")
        });
        format!(
            "{copy} \
             && regctl image mod --replace --annotation dev.speculaire.e2e.image={image} {host}/{image} >/dev/null"
        )
    };
    zot.regctl(&format!("{} && {}", push(SIGNED), push(UNSIGNED)))?;
    let digest = zot.digest(SIGNED)?;
    let repository = SIGNED
        .split_once(':')
        .map_or(SIGNED, |(repository, _)| repository);
    let reference = format!("{host}/{repository}@{digest}");

    let work = Volume::create(&format!("{}-cosign", cluster.name))?;
    work.sh(&format!(
        "cat >slsa.json <<'EOF'\n{SLSA}EOF\ncat >spdx.json <<'EOF'\n{SPDX}EOF\n"
    ))?;
    work.cosign(&["generate-key-pair"])?;
    // Referrers in the bundle format, then the legacy `.sig` and `.att` tags.
    for bundle in ["--new-bundle-format=true", "--new-bundle-format=false"] {
        work.cosign(&[&["sign", bundle][..], &OFFLINE, &[&reference]].concat())?;
        let slsa = [
            "attest",
            bundle,
            "--type",
            "slsaprovenance1",
            "--predicate",
            "slsa.json",
        ];
        work.cosign(&[&slsa[..], &OFFLINE, &[&reference]].concat())?;
    }
    let spdx = ["attest", "--type", "spdxjson", "--predicate", "spdx.json"];
    work.cosign(&[&spdx[..], &OFFLINE, &[&reference]].concat())?;
    work.sh("cat cosign.pub")
}

/// Copies [`SIGNED`], with its referrers and its digest tags, and [`UNSIGNED`] from `from` to each of `to`. On a
/// registry without the referrers API, `regctl` writes the fallback tag, `sha256-<hex>`, instead.
fn copy(from: &Upstream, to: &[&Upstream]) -> Result<(), Failure> {
    let setup: Vec<String> = std::iter::once(from)
        .chain(to.iter().copied())
        .map(Upstream::reach)
        .collect();
    let source = from.address();
    let script: Vec<String> = to
        .iter()
        .map(|to| {
            let target = to.address();
            format!(
                "regctl image copy --referrers --digest-tags {source}/{SIGNED} {target}/{SIGNED} \
                 && regctl image copy {source}/{UNSIGNED} {target}/{UNSIGNED}"
            )
        })
        .collect();
    regctl_after(&setup.join(" && "), &script.join(" && "), None).map(drop)
}

/// Copies each fixture's layout to each of `to` as [`FIXTURES`]`:<case>`, with its referrers and its digest tags: zot
/// gets the referrers as such, a registry without the referrers API the recorded fallback tags.
fn push_fixtures(to: &[&Upstream]) -> Result<(), Failure> {
    let layouts = Path::new(LAYOUTS)
        .canonicalize()
        .map_err(|e| fail(LAYOUTS, &e))?;
    let setup: Vec<String> = to.iter().copied().map(Upstream::reach).collect();
    let targets: Vec<&str> = to.iter().map(|upstream| upstream.address()).collect();
    let script = format!(
        "for case in $(ls /layouts); do for target in {}; do \
         regctl image copy --referrers --digest-tags \"ocidir:///layouts/$case:$case\" \"$target/{FIXTURES}:$case\" \
         || exit 1; done; done",
        targets.join(" ")
    );
    let volume = format!("{}:/layouts:ro", layouts.display());
    regctl_after(&setup.join(" && "), &script, Some(&volume)).map(drop)
}

/// A Docker volume, the working directory of the containers that [`Volume::run`] starts; removed when this drops.
struct Volume {
    name: String,
}

impl Volume {
    fn create(name: &str) -> Result<Self, Failure> {
        let _ = docker(&["volume", "rm", "-f", name]);
        docker(&["volume", "create", "--label", LABEL, name])?;
        Ok(Self {
            name: name.to_owned(),
        })
    }

    /// Runs `image_and_command` (the image, then its command) as root, in the volume, on kind's network, with what
    /// `cosign` needs to sign unattended, and returns its stdout.
    fn run(&self, image_and_command: &[&str]) -> Result<String, Failure> {
        let mount = format!("{}:/work", self.name);
        let mut args = vec![
            "run",
            "--rm",
            "--network",
            NETWORK,
            "--label",
            LABEL,
            "--user",
            "0",
            "--volume",
            &mount,
            "--workdir",
            "/work",
            "--env",
            "COSIGN_PASSWORD=",
            "--env",
            "COSIGN_YES=true",
        ];
        args.extend(image_and_command);
        docker(&args)
    }

    /// Runs `cosign` with `args`.
    fn cosign(&self, args: &[&str]) -> Result<String, Failure> {
        self.run(&[&[COSIGN_IMAGE][..], args].concat())
    }

    /// Runs `script` in a shell.
    fn sh(&self, script: &str) -> Result<String, Failure> {
        self.run(&[
            "--entrypoint",
            "sh",
            &hub::pulled(COPY_IMAGE)?,
            "-c",
            script,
        ])
    }
}

impl Drop for Volume {
    fn drop(&mut self) {
        let _ = docker(&["volume", "rm", "-f", &self.name]);
    }
}
