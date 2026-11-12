//! The mirror as a relay (D66, D67, D88): on CRI-O it is in every pull's path; on containerd it falls through.
//!
//! The upstreams are registries and a proxy on kind's network, which a worker reaches by name; the worker's own
//! registry config names them, and `speculaire configure` puts the mirror in front of each. The tests change the same
//! worker and put it back, so they run one at a time.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use e2e::registry::{
    self, Access, Certificates, LARGE_IMAGE, PASSWORD, Proxy, Registry, TokenServer, USER,
};
use e2e::{Cluster, Output, Runtime, TEST_IMAGE};

static SERIAL: Mutex<()> = Mutex::new(());

/// Held by each test: they change the same worker.
fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a runtime accepts of a manifest.
const ACCEPT: &str = "-H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'";
const CACHE: &str = "/var/lib/speculaire/blobs";
const CONFIG: &str = "/etc/speculaire/config.toml";
const MIRROR_DIR: &str = "/var/lib/speculaire/mirror";
const MIRROR: &str = "https://127.0.0.1:7480";

/// The worker the test drives, and what to undo on it when the test ends, however it ends.
struct Worker {
    cluster: Cluster,
    name: String,
    undo: Vec<String>,
    configured: bool,
    agent_changed: bool,
}

impl Worker {
    /// The worker, on a cluster of `runtime`; `None` on the other runtime, where the test has nothing to check.
    fn on(runtime: Runtime) -> Option<Self> {
        let cluster = Cluster::from_env();
        if cluster.runtime() != runtime {
            return None;
        }
        let name = cluster
            .nodes()
            .unwrap()
            .into_iter()
            .map(|n| n.name)
            .find(|name| name.ends_with("-worker"))
            .expect("a worker");
        let worker = Self {
            cluster,
            name,
            undo: Vec::new(),
            configured: false,
            agent_changed: false,
        };
        // A test that failed before the guard dropped leaves the agent as it was: start from a ready one, with an empty
        // blob cache (the agent counts what it holds, so it restarts).
        worker.wait_ready();
        if runtime == Runtime::Crio {
            worker.sh(&format!(
                "systemctl stop speculaire && rm -rf {CACHE}/blobs {CACHE}/tmp && systemctl reset-failed speculaire; systemctl start speculaire"
            ));
            worker.wait_ready();
        }
        worker.forget();
        Some(worker)
    }

    fn sh(&self, script: &str) -> String {
        self.cluster
            .exec(&self.name, &["sh", "-c", script])
            .unwrap()
    }

    fn sh_output(&self, script: &str) -> Output {
        self.cluster
            .exec_output(&self.name, &["sh", "-c", script])
            .unwrap()
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let ready = self.sh_output(
                "curl -sf -o /dev/null http://127.0.0.1:7482/readyz && crictl version >/dev/null 2>&1",
            );
            if ready.success {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{}: the agent and the runtime are not both ready",
                self.name
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Writes a file of the node, and removes it at the end.
    fn file(&mut self, path: &str, text: &str) {
        let dir = path.rsplit_once('/').unwrap().0;
        self.sh(&format!(
            "mkdir -p {dir} && cat > {path} <<'EOF'\n{text}EOF\n"
        ));
        self.undo.push(format!("rm -f {path}"));
    }

    /// Copies a file to the node.
    fn copy(&mut self, host: &str, path: &str) {
        let dir = path.rsplit_once('/').unwrap().0;
        self.sh(&format!("mkdir -p {dir}"));
        let status = Command::new("docker")
            .args(["cp", host, &format!("{}:{path}", self.name)])
            .status()
            .unwrap();
        assert!(status.success());
        self.undo.push(format!("rm -f {path}"));
    }

    /// Runs `speculaire configure`, which puts the mirror in front of what the registry config names now.
    fn configure(&mut self) {
        self.configured = true;
        self.sh("speculaire configure");
        // The agent reads the registry config again at once, rather than at its next poll (D91).
        self.sh("systemctl reload speculaire");
        self.wait_ready();
    }

    /// Names a registry in the worker's own config: it is pulled from without TLS verification, at `address`.
    fn registry_conf(&mut self, tag: &str, address: &str, tls: bool) {
        let insecure = if tls { "" } else { "insecure = true\n" };
        self.file(
            &format!("/etc/containers/registries.conf.d/50-e2e-{tag}.conf"),
            &format!("[[registry]]\nprefix = \"{address}\"\nlocation = \"{address}\"\n{insecure}"),
        );
        self.configure();
    }

    /// Edits the agent's config with `sed` scripts and restarts it.
    fn agent_config(&mut self, scripts: &[&str]) {
        if !self.agent_changed {
            self.sh(&format!("cp {CONFIG} {CONFIG}.e2e"));
            self.agent_changed = true;
        }
        for script in scripts {
            self.sh(&format!("sed -i '{script}' {CONFIG}"));
        }
        self.sh("systemctl reset-failed speculaire; systemctl restart speculaire");
        self.wait_ready();
    }

    /// Edits the agent's config with `sed` scripts and has it read again, as `systemctl reload` does.
    fn live_config(&mut self, scripts: &[&str]) {
        if !self.agent_changed {
            self.sh(&format!("cp {CONFIG} {CONFIG}.e2e"));
            self.agent_changed = true;
        }
        for script in scripts {
            self.sh(&format!("sed -i '{script}' {CONFIG}"));
        }
        self.sh("systemctl reload speculaire");
    }

    fn series(&self, name: &str) -> f64 {
        let text = self.sh("curl -sf http://127.0.0.1:7482/metrics");
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.trim().parse().ok())
            .unwrap_or(0.0)
    }

    fn upstream_bytes(&self) -> f64 {
        self.series(r#"speculaire_mirror_bytes_total{source="upstream"}"#)
    }

    fn local_bytes(&self) -> f64 {
        self.series(r#"speculaire_mirror_bytes_total{source="local"}"#)
    }

    fn blobs(&self, result: &str) -> f64 {
        self.series(&format!(
            r#"speculaire_mirror_requests_total{{kind="blob",result="{result}"}}"#
        ))
    }

    fn manifests(&self, result: &str) -> f64 {
        self.series(&format!(
            r#"speculaire_mirror_requests_total{{kind="manifest",result="{result}"}}"#
        ))
    }

    /// `crictl pull`, and `crictl rmi` of it at the end.
    fn pull(&mut self, image: &str, credentials: Option<&str>) -> Output {
        self.undo
            .push(format!("crictl rmi {image} >/dev/null 2>&1"));
        let credentials = credentials.map_or(String::new(), |c| format!("--creds {c}"));
        self.sh_output(&format!("crictl pull {credentials} {image}"))
    }

    /// Removes the images of the suite from the runtime, whatever they are called: a pull of an image it has under
    /// another name fetches no blob, which these tests count.
    /// Removes the test images; a pod that was deleted a moment ago may still hold one, so it tries for 30 s.
    fn forget(&self) {
        self.sh(
            "crictl rmp -f $(crictl pods --namespace default -q) >/dev/null 2>&1; for i in $(seq 30); do ids=$(crictl images | awk '/busybox|nginx|e2e[.]test\\/app\\// {print $3}' | sort -u); [ -z \"$ids\" ] && exit 0; crictl ps -a | awk '/busybox|nginx|e2e[.]test\\/app\\// {print $1}' | xargs -r crictl rm -f >/dev/null 2>&1; crictl rmi $ids >/dev/null 2>&1 && exit 0; sleep 1; done; crictl rmi $ids",
        );
    }

    fn rmi(&self, image: &str) {
        self.sh(&format!("crictl rmi {image}"));
    }

    /// The names of the files the blob cache keeps.
    fn cached(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .sh(&format!("ls {CACHE}/blobs/sha256 2>/dev/null; true"))
            .lines()
            .map(str::to_owned)
            .collect();
        names.sort();
        names
    }

    /// The names of files of the blob cache whose content is not their digest: there must be none.
    fn corrupt(&self) -> String {
        self.sh(&format!(
            "cd {CACHE}/blobs/sha256 2>/dev/null || exit 0; for f in *; do [ -f \"$f\" ] || continue; [ \"$(sha256sum < \"$f\" | cut -d' ' -f1)\" = \"$f\" ] || echo \"$f\"; done"
        ))
    }

    fn leftovers(&self) -> String {
        self.sh(&format!("ls {CACHE}/tmp 2>/dev/null; true"))
    }

    fn curl_mirror(&self, path: &str, extra: &str) -> Output {
        self.sh_output(&format!(
            "curl -s -o /tmp/e2e-body -w '%{{http_code}} %{{size_download}}' {extra} --cacert {MIRROR_DIR}/ca.crt --cert {MIRROR_DIR}/client.pem {MIRROR}{path}"
        ))
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        for command in self.undo.iter().rev() {
            let _ = self.cluster.exec_output(&self.name, &["sh", "-c", command]);
        }
        if self.configured {
            let _ = self
                .cluster
                .exec_output(&self.name, &["speculaire", "configure"]);
        }
        if self.agent_changed {
            let _ = self.cluster.exec_output(
                &self.name,
                &[
                    "sh",
                    "-c",
                    &format!("mv {CONFIG}.e2e {CONFIG} && systemctl reset-failed speculaire; systemctl restart speculaire"),
                ],
            );
        }
        // Some of these tests provoke warnings on purpose; `unit.rs` asserts the journal holds none, so the
        // journal is emptied and the agent restarted for the entries it writes at start.
        let _ = self.cluster.exec_output(
            &self.name,
            &[
                "sh",
                "-c",
                "journalctl --rotate && journalctl --vacuum-time=1s; systemctl reset-failed speculaire; systemctl restart speculaire",
            ],
        );
        // A second panic while a failed test unwinds would abort the whole binary; the next `Worker::on` waits anyway.
        if !std::thread::panicking() {
            self.wait_ready();
        }
    }
}

/// An open registry with `image` pushed as `app/web:1`.
fn seeded(name: &str, image: &str) -> Registry {
    let registry = Registry::start(name, &Access::Open, None).unwrap();
    registry.copy_in(image, "app/web:1").unwrap();
    registry
}

fn assert_pulled(pull: &Output) {
    assert!(pull.success, "{pull:?}");
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn on_crio_a_pull_by_tag_goes_through_the_mirror_and_a_second_one_is_served_from_the_blob_cache() {
    let _serial = serial();
    let Some(mut worker) = Worker::on(Runtime::Crio) else {
        return;
    };
    let upstream = seeded("open.e2e.test", TEST_IMAGE);
    let image = format!("{}/app/web:1", upstream.address());
    worker.registry_conf("open", &upstream.address(), false);
    assert_eq!(worker.cached(), Vec::<String>::new());

    let (served, bytes) = (worker.manifests("served"), worker.upstream_bytes());
    assert_pulled(&worker.pull(&image, None));
    assert!(
        worker.manifests("served") > served,
        "the pull sent the mirror no manifest it served"
    );
    assert!(
        worker.upstream_bytes() > bytes + 1_000_000.0,
        "upstream bytes: {bytes} then {}",
        worker.upstream_bytes()
    );
    // The index, the manifest, the config and the layer.
    let cached = worker.cached();
    assert!(cached.len() >= 3, "{cached:?}");
    assert_eq!(
        worker.corrupt(),
        "",
        "a file of the blob cache is not its digest"
    );
    assert_eq!(worker.leftovers(), "");
    assert!(worker.series("speculaire_blob_cache_bytes") > 1_000_000.0);

    // Removed from CRI-O and pulled again: the blobs come from the cache.
    worker.rmi(&image);
    let (requests, upstream_bytes, local) = (
        upstream.blob_requests().unwrap(),
        worker.upstream_bytes(),
        worker.local_bytes(),
    );
    assert!(
        requests >= 2,
        "the registry log has {requests} blob requests: is its access log on?"
    );
    assert_pulled(&worker.pull(&image, None));
    assert_eq!(
        upstream.blob_requests().unwrap(),
        requests,
        "the second pull asked upstream for a blob"
    );
    assert!(
        worker.local_bytes() > local + 1_000_000.0,
        "local bytes: {local} then {}",
        worker.local_bytes()
    );
    assert!(
        worker.upstream_bytes() - upstream_bytes < 10_000.0,
        "the second pull moved more than a manifest from upstream"
    );
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn on_crio_a_kubelet_pod_by_tag_goes_through_the_mirror() {
    let _serial = serial();
    let Some(mut worker) = Worker::on(Runtime::Crio) else {
        return;
    };
    let upstream = seeded("open.e2e.test", TEST_IMAGE);
    let image = format!("{}/app/web:1", upstream.address());
    worker.registry_conf("open", &upstream.address(), false);
    worker
        .undo
        .push(format!("crictl rmi {image} >/dev/null 2>&1"));
    let bytes = worker.upstream_bytes();
    let pod = "speculaire-e2e-relay";
    let overrides = format!(r#"{{"spec":{{"nodeName":"{}"}}}}"#, worker.name);
    worker
        .cluster
        .kubectl(&[
            "run",
            pod,
            "--image",
            &image,
            "--image-pull-policy=Always",
            "--restart=Never",
            &format!("--overrides={overrides}"),
            "--command",
            "--",
            "sleep",
            "3600",
        ])
        .unwrap();
    let ready = worker.cluster.kubectl(&[
        "wait",
        "--for=condition=Ready",
        &format!("pod/{pod}"),
        "--timeout=120s",
    ]);
    let _ = worker
        .cluster
        .kubectl(&["delete", "pod", pod, "--now", "--timeout=60s"]);
    ready.unwrap();
    assert!(
        worker.upstream_bytes() > bytes + 1_000_000.0,
        "upstream bytes: {bytes} then {}",
        worker.upstream_bytes()
    );
    assert!(worker.cached().len() >= 3, "{:?}", worker.cached());
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn on_crio_an_image_that_needs_a_pull_secret_is_pulled_from_upstream_with_it() {
    let _serial = serial();
    let Some(mut worker) = Worker::on(Runtime::Crio) else {
        return;
    };
    let open = seeded("seed.e2e.test", TEST_IMAGE);
    let basic = Registry::start(
        "basic.e2e.test",
        &Access::Basic(&registry::htpasswd().unwrap()),
        Some(&open),
    )
    .unwrap();
    let image = format!("{}/app/web:1", basic.address());
    worker.registry_conf("basic", &basic.address(), false);

    let (fall_through, bytes) = (worker.manifests("fall_through"), worker.upstream_bytes());
    // The pod's pull secret reaches CRI-O in the pull; the mirror never sees it and the node has no login of its own.
    assert_pulled(&worker.pull(&image, Some(&format!("{USER}:{PASSWORD}"))));
    assert!(
        worker.manifests("fall_through") > fall_through,
        "the mirror did not answer 404 to the manifest"
    );
    assert!(
        (worker.upstream_bytes() - bytes).abs() < 1.0,
        "the relay fetched what it has no login for"
    );
    assert_eq!(worker.cached(), Vec::<String>::new());
    // Without the secret, nobody can pull it.
    worker.rmi(&image);
    let without = worker.pull(&image, None);
    assert!(!without.success, "{without:?}");
}

/// A registry behind a Bearer token server, with `app/web:1` in it, whose CA the worker trusts: the node's own
/// registry config holds it, and a login is only what the test writes.
struct Private {
    address: String,
    image: String,
    _seed: Registry,
    _token: TokenServer,
    _registry: Registry,
}

impl Private {
    fn start(worker: &mut Worker) -> Self {
        let seed = seeded("seed.e2e.test", TEST_IMAGE);
        let certificates =
            Certificates::new("bearer", &["private.e2e.test", "token.e2e.test"]).unwrap();
        let line = registry::htpasswd().unwrap();
        let token = TokenServer::start("token.e2e.test", &certificates, &line).unwrap();
        let registry = Registry::start(
            "private.e2e.test",
            &Access::Token {
                certificates: &certificates,
                realm: "https://token.e2e.test:5001/auth",
            },
            Some(&seed),
        )
        .unwrap();
        let address = registry.address();
        let scratch =
            std::env::temp_dir().join(format!("speculaire-e2e-ca-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap();
        let ca = scratch.join("ca.crt");
        std::fs::write(&ca, certificates.ca()).unwrap();
        worker.copy(
            &ca.display().to_string(),
            &format!("/etc/containers/certs.d/{address}/ca.crt"),
        );
        let _ = std::fs::remove_dir_all(&scratch);
        worker.registry_conf("private", &address, true);
        Self {
            image: format!("{address}/app/web:1"),
            address,
            _seed: seed,
            _token: token,
            _registry: registry,
        }
    }
}

/// `user:password` in base64, as a credential file holds it.
fn basic_credentials() -> String {
    use std::io::Write;
    let mut encoder = Command::new("base64")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    encoder
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{USER}:{PASSWORD}").as_bytes())
        .unwrap();
    String::from_utf8(encoder.wait_with_output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned()
}

fn auth_file(address: &str, basic: &str) -> String {
    format!("{{\"auths\":{{\"{address}\":{{\"auth\":\"{basic}\"}}}}}}\n")
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn on_crio_the_relay_logs_in_with_the_nodes_credentials_and_ca_and_logs_no_secret() {
    let _serial = serial();
    let Some(mut worker) = Worker::on(Runtime::Crio) else {
        return;
    };
    let private = Private::start(&mut worker);
    let image = private.image.clone();
    let basic = basic_credentials();
    // The login, only in the node's own credential file.
    worker.file(
        "/run/containers/0/auth.json",
        &auth_file(&private.address, &basic),
    );
    worker.agent_config(&["s/^filter = .*/filter = \"trace\"/"]);
    let since = worker.sh("date '+%Y-%m-%d %H:%M:%S'");

    let bytes = worker.upstream_bytes();
    let pulled = worker.pull(&image, None);
    assert_pulled(&pulled);
    assert!(
        worker.upstream_bytes() > bytes + 1_000_000.0,
        "the relay moved no bytes: {} then {}",
        bytes,
        worker.upstream_bytes()
    );
    assert!(worker.cached().len() >= 3, "{:?}", worker.cached());

    let journal = worker.sh(&format!(
        "journalctl -u speculaire --no-pager -o cat --since '{}'",
        since.trim()
    ));
    assert!(
        journal.lines().count() > 10 && journal.contains("upstream request"),
        "the journal does not hold trace events:\n{journal}"
    );
    for secret in [PASSWORD, basic.as_str(), "eyJ"] {
        assert!(
            !journal.contains(secret),
            "the journal holds a secret ({} bytes of it matched)",
            secret.len()
        );
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn on_crio_a_login_added_to_the_auth_file_is_used_by_the_next_pull_without_a_restart() {
    let _serial = serial();
    let Some(mut worker) = Worker::on(Runtime::Crio) else {
        return;
    };
    let private = Private::start(&mut worker);
    let image = private.image.clone();
    // Nobody has a login yet.
    let without = worker.pull(&image, None);
    assert!(!without.success, "{without:?}");

    worker.file(
        "/run/containers/0/auth.json",
        &auth_file(&private.address, &basic_credentials()),
    );
    // No SIGHUP and no restart: a poll finds the file, within `config.poll_interval` (10 s).
    std::thread::sleep(Duration::from_secs(15));
    let bytes = worker.upstream_bytes();
    assert_pulled(&worker.pull(&image, None));
    assert!(
        worker.upstream_bytes() > bytes + 1_000_000.0,
        "the relay did not use the new login: {} then {}",
        bytes,
        worker.upstream_bytes()
    );
    assert!(worker.cached().len() >= 3, "{:?}", worker.cached());
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn on_crio_lowering_the_bound_of_the_blob_cache_evicts_at_the_next_fill_without_a_restart() {
    let _serial = serial();
    let Some(mut worker) = Worker::on(Runtime::Crio) else {
        return;
    };
    let small = seeded("open.e2e.test", TEST_IMAGE);
    small.copy_in(LARGE_IMAGE, "app/large:1").unwrap();
    worker.registry_conf("open", &small.address(), false);
    let first = format!("{}/app/web:1", small.address());
    assert_pulled(&worker.pull(&first, None));
    let older = worker.cached();
    assert_ne!(older.len(), 0);
    worker.rmi(&first);

    worker.live_config(&["s/^#max_size = .*/max_size = \"12MiB\"/"]);
    // Nothing is evicted until a blob is kept.
    std::thread::sleep(Duration::from_secs(3));
    assert!(worker.series("speculaire_blob_cache_evictions_total") < 1.0);
    assert_eq!(worker.cached(), older);

    assert_pulled(&worker.pull(&format!("{}/app/large:1", small.address()), None));
    let deadline = Instant::now() + Duration::from_secs(60);
    while worker.series("speculaire_blob_cache_bytes") > 12.0 * 1024.0 * 1024.0 {
        assert!(
            Instant::now() < deadline,
            "the cache did not shrink:\n{}",
            worker.sh("grep -n max_size /etc/speculaire/config.toml; journalctl -u speculaire --no-pager -o cat | tail -n 15")
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    let left = worker.cached();
    for name in &older {
        assert!(!left.contains(name), "{name} is still cached: {left:?}");
    }
    assert_eq!(worker.corrupt(), "");
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn on_crio_a_corrupt_upstream_leaves_nothing_in_the_cache_and_the_client_never_gets_the_whole_blob()
{
    let _serial = serial();
    let Some(mut worker) = Worker::on(Runtime::Crio) else {
        return;
    };
    let upstream = seeded("open.e2e.test", TEST_IMAGE);
    // A proxy that flips the 100th byte of every blob.
    let proxy = Proxy::start("proxy.e2e.test", &upstream.address(), Some(100), None).unwrap();
    let image = format!("{}/app/web:1", proxy.address());
    worker.registry_conf("proxy", &proxy.address(), false);

    let pull = worker.pull(&image, None);
    assert!(
        !pull.success,
        "a pull of a corrupt image succeeded: {pull:?}"
    );
    assert!(proxy.blob_requests().unwrap() >= 1);
    // The manifests are verified by their digest and are kept; no blob is.
    assert_eq!(worker.corrupt(), "");
    assert_eq!(worker.leftovers(), "");
    let cached = worker.cached();
    assert!(cached.len() <= 2, "a blob was kept: {cached:?}");

    // The layer, asked of the mirror directly: it ends short, whatever the client does with it.
    let path = format!("/v2/{}/app/web", proxy.address());
    let index = worker.curl_mirror(&format!("{path}/manifests/1"), ACCEPT);
    assert!(
        index.success && index.stdout.starts_with("200 "),
        "{index:?}"
    );
    let manifest = worker.sh("cat /tmp/e2e-body");
    let layer = first_layer(&worker, &path, &manifest);
    let blob = worker.curl_mirror(&format!("{path}/blobs/{}", layer.digest), "");
    let downloaded: u64 = blob
        .stdout
        .split(' ')
        .nth(1)
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    assert!(
        !blob.success && downloaded < layer.size,
        "curl got {downloaded} of {} bytes of a corrupt blob: {blob:?}",
        layer.size
    );
    assert_eq!(worker.corrupt(), "");
    assert!(worker.cached().len() <= 2, "{:?}", worker.cached());
}

struct Layer {
    digest: String,
    size: u64,
}

/// The first layer of an image manifest, or of the first manifest of an index, which `path` serves.
fn first_layer(worker: &Worker, path: &str, body: &str) -> Layer {
    let json: serde_json::Value = serde_json::from_str(body).unwrap();
    let json = if let Some(manifests) = json.get("manifests") {
        let digest = manifests[0]["digest"].as_str().unwrap().to_owned();
        let out = worker.curl_mirror(&format!("{path}/manifests/{digest}"), ACCEPT);
        assert!(out.success, "{out:?}");
        serde_json::from_str(&worker.sh("cat /tmp/e2e-body")).unwrap()
    } else {
        json
    };
    let layer = &json["layers"][0];
    Layer {
        digest: layer["digest"].as_str().unwrap().to_owned(),
        size: layer["size"].as_u64().unwrap(),
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn on_crio_above_the_bound_the_least_recently_served_blobs_go_first() {
    let _serial = serial();
    let Some(mut worker) = Worker::on(Runtime::Crio) else {
        return;
    };
    let small = seeded("open.e2e.test", TEST_IMAGE);
    small.copy_in(LARGE_IMAGE, "app/large:1").unwrap();
    worker.registry_conf("open", &small.address(), false);
    worker.agent_config(&["s/^#max_size = .*/max_size = \"12MiB\"/"]);
    let first = format!("{}/app/web:1", small.address());
    assert_pulled(&worker.pull(&first, None));
    let older = worker.cached();
    assert_ne!(older.len(), 0);
    // The blobs of an image CRI-O lists go last (D67): the first image must be gone from its list to be the first out.
    worker.rmi(&first);
    let evictions = worker.series("speculaire_blob_cache_evictions_total");
    assert!(evictions < 1.0, "{evictions}");

    assert_pulled(&worker.pull(&format!("{}/app/large:1", small.address()), None));
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let size = worker.series("speculaire_blob_cache_bytes");
        if size <= 12.0 * 1024.0 * 1024.0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the cache stayed at {size} bytes"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    let left = worker.cached();
    assert!(
        worker.series("speculaire_blob_cache_evictions_total")
            >= f64::from(u32::try_from(older.len()).unwrap()),
        "evictions: {}",
        worker.series("speculaire_blob_cache_evictions_total")
    );
    for name in &older {
        assert!(
            !left.contains(name),
            "{name}, served before the large image, is still cached: {left:?}"
        );
    }
    assert_eq!(worker.corrupt(), "");
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn on_crio_killing_the_agent_mid_pull_fails_that_pull_and_the_next_one_succeeds() {
    let _serial = serial();
    let Some(mut worker) = Worker::on(Runtime::Crio) else {
        return;
    };
    let upstream = seeded("open.e2e.test", TEST_IMAGE);
    upstream.copy_in(LARGE_IMAGE, "app/large:1").unwrap();
    // 2 MB/s a blob: the pull takes seconds.
    let proxy = Proxy::start("slow.e2e.test", &upstream.address(), None, Some(2_000_000)).unwrap();
    worker.registry_conf("slow", &proxy.address(), false);
    let image = format!("{}/app/large:1", proxy.address());
    worker
        .undo
        .push(format!("crictl rmi {image} >/dev/null 2>&1"));

    let mut pull: Child = Command::new("docker")
        .args(["exec", &worker.name, "crictl", "pull", &image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // A blob is in flight when a file is in the cache's `tmp/`.
    let deadline = Instant::now() + Duration::from_secs(60);
    while worker.leftovers().trim().is_empty() {
        assert!(Instant::now() < deadline, "no blob was ever in flight");
        std::thread::sleep(Duration::from_millis(100));
    }
    worker.sh("systemctl kill --signal=SIGKILL speculaire");
    let status = pull.wait().unwrap();
    assert!(!status.success(), "the pull went on without the agent");

    // The kubelet retries: the agent is down or just back, and the pull succeeds either way.
    assert_pulled(&worker.pull(&image, None));
    worker.wait_ready();
    // The restart deleted what the kill left.
    assert_eq!(worker.leftovers().trim(), "");
    assert_eq!(worker.corrupt(), "");
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn on_crio_the_relay_costs_at_most_18_ms_of_cpu_per_mb() {
    let _serial = serial();
    let Some(mut worker) = Worker::on(Runtime::Crio) else {
        return;
    };
    let upstream = Registry::start("open.e2e.test", &Access::Open, None).unwrap();
    upstream.copy_in(LARGE_IMAGE, "app/large:1").unwrap();
    worker.registry_conf("open", &upstream.address(), false);
    let image = format!("{}/app/large:1", upstream.address());

    let ticks = |worker: &Worker| -> f64 {
        worker
            .sh("awk '{print $14 + $15}' /proc/$(systemctl show -p MainPID --value speculaire)/stat")
            .trim()
            .parse()
            .unwrap()
    };
    let before = ticks(&worker);
    assert_pulled(&worker.pull(&image, None));
    let after = ticks(&worker);
    let megabytes: f64 = worker
        .sh(&format!("du -sb {CACHE}/blobs | cut -f1"))
        .trim()
        .parse::<f64>()
        .unwrap()
        / 1_000_000.0;
    let hertz: f64 = worker.sh("getconf CLK_TCK").trim().parse().unwrap();
    let per_megabyte = (after - before) * 1000.0 / hertz / megabytes;
    println!("relay CPU: {per_megabyte:.1} ms per MB over {megabytes:.1} MB");
    assert!(megabytes > 10.0, "{megabytes} MB cached");
    assert!(
        per_megabyte <= 18.0,
        "the relay used {per_megabyte:.1} ms of CPU per MB over {megabytes:.1} MB"
    );
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn on_containerd_the_mirror_sends_no_upstream_request() {
    let _serial = serial();
    let Some(mut worker) = Worker::on(Runtime::Containerd) else {
        return;
    };
    let upstream = seeded("open.e2e.test", TEST_IMAGE);
    let address = upstream.address();
    worker.file(
        &format!("/etc/containerd/certs.d/{address}/hosts.toml"),
        &format!("server = \"http://{address}\"\n\n[host.\"http://{address}\"]\n  capabilities = [\"pull\", \"resolve\"]\n"),
    );
    worker
        .undo
        .push(format!("rmdir /etc/containerd/certs.d/{address}"));
    worker.configure();
    // containerd fetches no blob it holds: let it collect what an earlier pull of the image left.
    worker.forget();
    std::thread::sleep(Duration::from_secs(10));
    let image = format!("{address}/app/web:1");
    let fall_throughs =
        |worker: &Worker| worker.manifests("fall_through") + worker.blobs("fall_through");
    let before = fall_throughs(&worker);
    assert_pulled(&worker.pull(&image, None));
    assert!(
        fall_throughs(&worker) > before,
        "the pull did not go through the mirror"
    );
    assert!(worker.upstream_bytes() < 1.0, "{}", worker.upstream_bytes());
    assert_eq!(worker.cached(), Vec::<String>::new());
}
