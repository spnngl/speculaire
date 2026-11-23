//! Upstream rate limits (D38, D128): a `429` to discovery pauses that registry host for every image until its
//! `Retry-After`, and discovery takes up both images it held back on its own once the window ends.
//!
//! The suite waits out a 45 s window, so it runs in the IPv4 pass only (D130).
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};

use e2e::logs::tail;
use e2e::node::Rules;
use e2e::registry::Proxy;
use e2e::upstream::{Digest, Kind, Request, SIGNED, Upstream};
use e2e::{Cluster, IpFamily, Runtime};

const STORE: &str = "/var/lib/speculaire/artifacts";

/// The peer API's port when `peer.address` is `"auto"` (D36).
const PEER_PORT: u16 = 7481;

/// The proxy in front of the plain upstream, which the worker's runtime config names.
const HOST: &str = "limited.e2e.test";

/// The `Retry-After` of the proxy's `429`, and how long after it the store must hold both images' artifacts. The
/// window is longer than the first backoff step, 30 s (D128): an agent that ignored `Retry-After` would ask again
/// within [`QUIET`].
const WINDOW: Duration = Duration::from_secs(45);
const WITHIN: Duration = Duration::from_secs(55);

/// How long the proxy's log must show nothing of either image: the window, less the gap between the agent's 429 and
/// the test seeing it.
const QUIET: Duration = Duration::from_secs(40);

/// The repository of the second signed image, an image of its own (CRI-O would merge a copy of [`SIGNED`] that keeps
/// its config into one image whose roots each have both names) with one bundle.
const REPOSITORY: &str = "e2e/limited";

/// The second signed image.
const LIMITED: &str = "e2e/limited:1";

/// An image of the plain upstream, as discovery must keep it.
struct Image {
    /// Its name, without the host.
    reference: &'static str,
    root: Digest,
    /// Every digest the store must hold: each artifact's manifest and its blobs.
    digests: Vec<String>,
}

impl Image {
    /// Read from `plain`, where `regctl` wrote the fallback tag and the `.sig` tag, if any.
    fn read(plain: &Upstream, reference: &'static str) -> Self {
        let root = plain.digest(reference).unwrap();
        let name = format!(
            "{}/{}",
            plain.address(),
            reference.split_once(':').unwrap().0
        );
        let get = |reference: &str| -> serde_json::Value {
            let body = plain
                .regctl(&format!(
                    "regctl manifest get --format raw-body {name}{reference}"
                ))
                .unwrap();
            serde_json::from_str(&body).unwrap()
        };
        let mut manifests: Vec<String> = get(&format!(":sha256-{}", root.hex()))["manifests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|listed| listed["digest"].as_str().unwrap().to_owned())
            .collect();
        let sig = plain.regctl(&format!(
            "regctl image digest {name}:sha256-{}.sig",
            root.hex()
        ));
        if let Ok(sig) = sig {
            manifests.push(sig.trim().to_owned());
        }
        let mut digests = Vec::new();
        for manifest in manifests {
            let body = get(&format!("@{manifest}"));
            digests.extend(
                std::iter::once(&body["config"])
                    .chain(body["layers"].as_array().unwrap())
                    .map(|descriptor| descriptor["digest"].as_str().unwrap().to_owned()),
            );
            digests.push(manifest);
        }
        Self {
            reference,
            root,
            digests,
        }
    }

    /// Whether `request` asks for an artifact of the image: its referrers, its fallback or `.sig` tag, or a digest of
    /// one of its artifacts.
    fn artifact(&self, request: &Request) -> bool {
        request.path.contains(&format!("/referrers/{}", self.root))
            || request
                .path
                .contains(&format!("sha256-{}", self.root.hex()))
            || self
                .digests
                .iter()
                .any(|d| request.path.contains(d.as_str()))
    }
}

/// Pushes [`LIMITED`] to `plain`, new, with a Sigstore bundle as referrer.
fn push_limited(plain: &Upstream) {
    let name = plain.address();
    let bundle = "application/vnd.dev.sigstore.bundle.v0.3+json";
    plain.push(REPOSITORY, 1024).unwrap();
    plain
        .regctl(&format!(
            "printf '{{\"e2e\":\"limited\"}}' >/tmp/bundle.json \
             && regctl artifact put --subject {name}/{LIMITED} --artifact-type {bundle} \
                --file /tmp/bundle.json --file-media-type {bundle} >/dev/null"
        ))
        .unwrap();
}

/// The worker no reflector runs on (D94), and what to undo on it when the test ends, however it ends.
struct Worker {
    cluster: Cluster,
    name: String,
    undo: Vec<String>,
}

impl Worker {
    fn new(cluster: Cluster) -> Self {
        let reflectors = cluster.reflectors();
        let name = cluster
            .nodes()
            .unwrap()
            .into_iter()
            .map(|n| n.name)
            .find(|name| !reflectors.contains(name))
            .expect("a node no reflector runs on");
        Self {
            cluster,
            name,
            undo: Vec::new(),
        }
    }

    fn sh(&self, script: &str) -> String {
        let output = self
            .cluster
            .exec_output(&self.name, &["sh", "-c", script])
            .unwrap();
        assert!(output.success, "{script}: {output:?}");
        output.stdout
    }

    /// Names [`HOST`] in the runtime's config, on plain HTTP, and puts the mirror in front of it.
    fn name_host(&mut self) {
        let (dir, path, text) = match self.cluster.runtime() {
            Runtime::Containerd => (
                format!("/etc/containerd/certs.d/{HOST}"),
                format!("/etc/containerd/certs.d/{HOST}/hosts.toml"),
                format!(
                    "server = \"http://{HOST}\"\n\n[host.\"http://{HOST}\"]\n  capabilities = [\"pull\", \"resolve\"]\n"
                ),
            ),
            Runtime::Crio => (
                "/etc/containers/registries.conf.d".to_owned(),
                "/etc/containers/registries.conf.d/50-e2e-limited.conf".to_owned(),
                format!(
                    "[[registry]]\nprefix = \"{HOST}\"\nlocation = \"{HOST}\"\ninsecure = true\n"
                ),
            ),
        };
        self.sh(&format!(
            "mkdir -p {dir} && cat > {path} <<'EOF'\n{text}EOF\n"
        ));
        self.undo.push(format!(
            "rm -f {path}; rmdir /etc/containerd/certs.d/{HOST} 2>/dev/null; speculaire configure"
        ));
        // The agent reads the registry config again at once, rather than at its next poll (D91).
        self.sh("speculaire configure");
        self.cluster.reload_agent(&self.name).unwrap();
        self.cluster.wait_ready(&self.name).unwrap();
    }

    /// The script that removes `images` from the runtime under each name the worker may hold them by.
    fn rmi(&self, images: &[&Image]) -> String {
        let mut hosts: Vec<String> = Kind::ALL
            .iter()
            .map(|kind| self.cluster.upstream(*kind).address().to_owned())
            .collect();
        hosts.push(HOST.to_owned());
        let names: Vec<String> = images
            .iter()
            .flat_map(|image| {
                hosts
                    .iter()
                    .map(|host| format!("{host}/{}", image.reference))
            })
            .collect();
        format!(
            "for image in {}; do crictl rmi $image >/dev/null 2>&1; done; true",
            names.join(" ")
        )
    }

    /// Removes `images` from the runtime, and their artifacts and records from the store, with the agent stopped: the
    /// agent discovers each again once it is listed.
    fn forget(&mut self, images: &[&Image]) {
        let files: Vec<String> = images
            .iter()
            .flat_map(|image| {
                image
                    .digests
                    .iter()
                    .map(|d| format!("{STORE}/blobs/sha256/{}", d.trim_start_matches("sha256:")))
                    .chain(std::iter::once(format!(
                        "{STORE}/roots/sha256/{}.json",
                        image.root.hex()
                    )))
            })
            .collect();
        self.cluster.stop_agent(&self.name).unwrap();
        self.sh(&format!("{}; rm -f {}", self.rmi(images), files.join(" ")));
        self.cluster.start_agent(&self.name).unwrap();
        self.cluster.wait_ready(&self.name).unwrap();
        self.undo.push(self.rmi(images));
    }

    /// Cuts the worker off from the other nodes' peer APIs while the rules live: peers that hold the artifacts would
    /// serve them, and discovery would not ask upstream (D126).
    fn alone(&self) -> Vec<Rules<'_>> {
        self.cluster
            .nodes()
            .unwrap()
            .into_iter()
            .map(|n| n.name)
            .filter(|name| *name != self.name)
            .map(|other| {
                self.cluster
                    .reject_port(&self.name, &other, PEER_PORT)
                    .unwrap()
            })
            .collect()
    }

    /// Waits until the agent's logs since `since` have a message holding `line`, 10 s at most.
    fn logs(&self, since: SystemTime, line: &str) {
        let start = Instant::now();
        loop {
            let logs = self.cluster.agent_logs(&self.name, Some(since)).unwrap();
            if logs.iter().any(|entry| entry.message.contains(line)) {
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "no `{line}` in the logs:\n{}",
                tail(&logs, 30)
            );
            sleep(Duration::from_millis(200));
        }
    }

    /// Whether the store holds every artifact of `image`.
    fn holds(&self, image: &Image) -> bool {
        let test = image
            .digests
            .iter()
            .map(|d| {
                format!(
                    "test -f {STORE}/blobs/sha256/{}",
                    d.trim_start_matches("sha256:")
                )
            })
            .collect::<Vec<_>>()
            .join(" && ");
        self.cluster
            .exec_output(&self.name, &["sh", "-c", &test])
            .unwrap()
            .success
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self
            .cluster
            .exec_output(&self.name, &["sh", "-c", &self.undo.join("; ")]);
        let restarted = self.cluster.restart_agent(&self.name);
        if !std::thread::panicking() {
            restarted.unwrap();
            self.cluster.wait_ready(&self.name).unwrap();
        }
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_429_to_discovery_pauses_its_host_for_every_image_until_retry_after() {
    let cluster = Cluster::from_env();
    if cluster.ip_family() == IpFamily::Dual {
        return;
    }
    let runtime = cluster.runtime();
    let plain = cluster.upstream(Kind::Plain);
    push_limited(&plain);
    let signed = Image::read(&plain, SIGNED);
    let limited = Image::read(&plain, LIMITED);
    let proxy = Proxy::start(HOST, plain.address(), None, None).unwrap();
    let mut worker = Worker::new(cluster);
    worker.name_host();
    worker.forget(&[&signed, &limited]);
    let since = worker.cluster.clock(&worker.name).unwrap();
    let _alone = worker.alone();
    proxy.throttle("/referrers/", WINDOW, Some(1)).unwrap();

    worker.sh(&format!("crictl pull {HOST}/{SIGNED}"));
    // The time of the 429, as the test sees it: the agent got it a moment before.
    let start = Instant::now();
    let (refused, refused_at) = loop {
        let requests = proxy.requests().unwrap();
        if let Some(at) = requests.iter().position(|r| r.status == 429) {
            break (at, Instant::now());
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "no 429: {requests:?}"
        );
        sleep(Duration::from_millis(100));
    };
    for image in [&signed, &limited] {
        if image.reference == LIMITED {
            // The second image, pulled from the same host within the window.
            worker.sh(&format!("crictl pull {HOST}/{LIMITED}"));
        }
        worker.logs(
            since,
            &format!(
                "discovery of {}: unverifiable: upstream rate limited: {HOST}",
                image.root
            ),
        );
    }

    // Until the window ends, nothing of either image's artifacts; on containerd, where the runtime pulls by itself,
    // nothing from the agent at all.
    sleep((refused_at + QUIET).saturating_duration_since(Instant::now()));
    let quiet: Vec<Request> = proxy.requests().unwrap().split_off(refused + 1);
    assert!(
        quiet
            .iter()
            .all(|r| !signed.artifact(r) && !limited.artifact(r)),
        "{quiet:?}"
    );
    if runtime == Runtime::Containerd {
        assert!(
            quiet
                .iter()
                .all(|r| !r.user_agent.starts_with("speculaire/")),
            "{quiet:?}"
        );
    }

    // Then both images' artifacts, without another pull.
    while !(worker.holds(&signed) && worker.holds(&limited)) {
        assert!(
            refused_at.elapsed() < WITHIN,
            "the store lacks artifacts {} s after the 429: {:?}\n{}{}",
            refused_at.elapsed().as_secs(),
            proxy.requests().unwrap().split_off(refused + 1),
            worker.sh(&format!("ls -R {STORE}")),
            tail(
                &worker
                    .cluster
                    .agent_logs(&worker.name, Some(since))
                    .unwrap(),
                30
            )
        );
        sleep(Duration::from_millis(200));
    }
    println!(
        "both images' artifacts held {} ms after the 429",
        refused_at.elapsed().as_millis()
    );
    // The second image has no `.sig`: a head, never a get (D38).
    let sig = format!("sha256-{}.sig", limited.root.hex());
    let asked: Vec<Request> = proxy
        .requests()
        .unwrap()
        .into_iter()
        .filter(|r| r.path.ends_with(&sig))
        .collect();
    assert!(
        !asked.is_empty() && asked.iter().all(|r| r.method == "HEAD" && r.status == 404),
        "{asked:?}"
    );
}
