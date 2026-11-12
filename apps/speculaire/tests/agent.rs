//! `speculaire agent` as a process: startup, reloads, logs, `/metrics` and shutdown (D30, D34, D37, D42, D45).
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "the helpers of a test fail it by panicking"
)]

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant, SystemTime};

use secrecy::ExposeSecret as _;
use speculaire_fake_runtime::{Answers, Fake};
use speculaire_pki::mirror::{Mirror, Part};

const WAIT: Duration = Duration::from_secs(10);
const PROTOBUF: &str =
    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited";

/// The node under test: a fake containerd on a socket, and containerd's config in a directory of its own, so that
/// the agent runs where there is no runtime, as on the CI runner and on macOS (D86).
struct Node {
    dir: tempfile::TempDir,
    _fake: Fake,
}

impl Node {
    /// containerd 2.4.2, with no `config.toml`: it runs on its defaults.
    fn healthy() -> Self {
        Self::new(Answers::containerd("v2.4.2"), None)
    }

    /// A fake that answers `answers`, and `containerd_config` as `config.toml` when there is one, with `@DIR@` for the
    /// directory of the node.
    fn new(answers: Answers, containerd_config: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake::start(&dir.path().join("containerd.sock"), answers).unwrap();
        if let Some(text) = containerd_config {
            let text = text.replace("@DIR@", &dir.path().display().to_string());
            std::fs::write(dir.path().join("config.toml"), text).unwrap();
        }
        Self { dir, _fake: fake }
    }

    /// The `[runtime]` table naming this node's files; CRI-O has none.
    fn table(&self) -> String {
        let dir = self.dir.path().display();
        format!(
            "[runtime]\ncontainerd_socket = \"{dir}/containerd.sock\"\ncontainerd_config = \"{dir}/config.toml\"\ncrio_socket = \"{dir}/crio.sock\"\n"
        )
    }
}

/// A running `speculaire agent`, killed on drop.
struct Agent {
    child: Child,
    port: u16,
    mirror_port: u16,
    config: PathBuf,
    node: Node,
    stderr: Receiver<String>,
    seen: Vec<String>,
}

impl Agent {
    /// Starts the agent on a free port with `extra` appended to its config.
    fn start(extra: &str) -> Self {
        Self::start_with_env(extra, &[])
    }

    /// As [`Agent::start`], with `env` added to the agent's environment.
    fn start_with_env(extra: &str, env: &[(&str, &str)]) -> Self {
        let port = free_port();
        let config = scratch_file();
        let agent = Self::spawn(port, config, extra, env);
        wait_until(|| get(port, "/livez", "").is_some_and(|r| r.status == 200));
        agent
    }

    fn spawn(port: u16, config: PathBuf, extra: &str, env: &[(&str, &str)]) -> Self {
        Self::spawn_on(Node::healthy(), port, config, extra, env)
    }

    fn spawn_on(node: Node, port: u16, config: PathBuf, extra: &str, env: &[(&str, &str)]) -> Self {
        let mirror_port = free_port();
        write_config(&config, port, mirror_port, &node, extra);
        let mut child = Command::new(env!("CARGO_BIN_EXE_speculaire"))
            .args(["agent", "--config"])
            .arg(&config)
            .envs(env.iter().copied())
            .env_remove("JOURNAL_STREAM")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (send, stderr) = channel();
        let pipe = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            port,
            mirror_port,
            config,
            node,
            stderr,
            seen: Vec::new(),
        }
    }

    fn rewrite(&self, extra: &str) {
        write_config(&self.config, self.port, self.mirror_port, &self.node, extra);
    }

    fn signal(&self, name: &str) {
        let status = Command::new("kill")
            .arg(format!("-{name}"))
            .arg(self.child.id().to_string())
            .status()
            .unwrap();
        assert!(status.success(), "kill -{name}");
    }

    /// Waits for a stderr line containing every needle, and returns it.
    fn line(&mut self, needles: &[&str]) -> String {
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.stderr.recv_timeout(left) {
                Ok(line) => {
                    self.seen.push(line.clone());
                    if needles.iter().all(|n| line.contains(n)) {
                        return line;
                    }
                }
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                    panic!("no stderr line with {needles:?}; saw {:#?}", self.seen)
                }
            }
        }
    }

    /// Sends SIGTERM and returns the exit status and every stderr line.
    fn stop(mut self) -> (ExitStatus, Vec<String>) {
        self.signal("TERM");
        let status = wait_exit(&mut self.child);
        let mut lines = std::mem::take(&mut self.seen);
        lines.extend(self.stderr.try_iter());
        (status, lines)
    }

    fn get(&self, path: &str, accept: &str) -> Response {
        get(self.port, path, accept).expect("the status listener answers")
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        // The test already failed or the agent already exited; either way only cleanup is left.
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.config);
    }
}

/// The socket systemd listens on for a `Type=notify` unit, named by `NOTIFY_SOCKET` (D69).
struct Notifications {
    socket: UnixDatagram,
    path: PathBuf,
}

impl Notifications {
    fn bind() -> Self {
        let path = scratch_file().with_extension("sock");
        let socket = UnixDatagram::bind(&path).unwrap();
        socket.set_read_timeout(Some(WAIT)).unwrap();
        Self { socket, path }
    }

    fn path(&self) -> &str {
        self.path.to_str().unwrap()
    }

    /// The next message, waiting up to `WAIT`.
    fn next(&self) -> String {
        let mut message = [0; 64];
        let len = self.socket.recv(&mut message).expect("a notification");
        String::from_utf8(message[..len].to_vec()).unwrap()
    }
}

impl Drop for Notifications {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

struct Response {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

impl Response {
    fn text(&self) -> String {
        String::from_utf8(self.body.clone()).unwrap()
    }
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn scratch_file() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "speculaire-agent-test-{}-{n}.toml",
        std::process::id()
    ))
}

/// The mirror's certificates, made once: `configure` makes them on a node (D82); these tests do not run as root.
fn mirror_certificates() -> &'static Path {
    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
    DIRECTORY.get_or_init(|| {
        let directory = std::env::temp_dir().join(format!(
            "speculaire-agent-test-{}-mirror",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let mirror = Mirror::generate(Ipv4Addr::LOCALHOST.into(), SystemTime::now()).unwrap();
        for part in Part::ALL {
            std::fs::write(
                directory.join(part.file_name()),
                mirror.contents(part).expose_secret(),
            )
            .unwrap();
        }
        directory
    })
}

/// Writes a config listening on `port` and, for the mirror, on `mirror_port`, on `node`; `extra` holds further tables.
fn write_config(path: &Path, port: u16, mirror_port: u16, node: &Node, extra: &str) {
    std::fs::write(
        path,
        format!(
            "[metrics]\naddress = \"127.0.0.1:{port}\"\n{extra}\n{}\n[mirror]\naddress = \"127.0.0.1:{mirror_port}\"\ndirectory = \"{}\"\n",
            node.table(),
            mirror_certificates().display()
        ),
    )
    .unwrap();
}

fn wait_until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !ready() {
        assert!(Instant::now() < deadline, "timed out");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_exit(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "the agent did not exit");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A one-request HTTP/1.1 client; `None` when nothing listens.
fn get(port: u16, path: &str, accept: &str) -> Option<Response> {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept: {accept}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a complete head");
    let head = String::from_utf8(raw[..split].to_vec()).unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    let content_type = head
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(": ")?;
            name.eq_ignore_ascii_case("content-type")
                .then(|| value.to_owned())
        })
        .unwrap_or_default();
    Some(Response {
        status,
        content_type,
        body: raw[split + 4..].to_vec(),
    })
}

fn reload_failures(agent: &Agent) -> String {
    let text = agent.get("/metrics", "").text();
    text.lines()
        .find(|l| l.starts_with("speculaire_config_reload_failures_total "))
        .unwrap()
        .to_owned()
}

#[test]
fn a_healthy_start_is_ready_and_logs_nothing_below_warn() {
    let agent = Agent::start("");
    assert_eq!(agent.get("/livez", "").status, 200);
    assert_eq!(agent.get("/readyz", "").status, 200);
    let (status, lines) = agent.stop();
    assert!(status.success(), "{status}");
    let loud: Vec<_> = lines
        .iter()
        .filter(|l| l.contains(r#""level":"WARN""#) || l.contains(r#""level":"ERROR""#))
        .collect();
    assert!(loud.is_empty(), "{loud:#?}");
}

#[test]
fn an_invalid_config_stops_startup_before_the_listener_opens() {
    let port = free_port();
    let mut agent = Agent::spawn(port, scratch_file(), "[gate]\nunmached = \"deny\"\n", &[]);
    let line = agent.line(&["gate.unmached"]);
    assert!(line.starts_with("error: invalid config"), "{line}");
    let status = wait_exit(&mut agent.child);
    assert_eq!(status.code(), Some(1));
    assert!(
        get(port, "/livez", "").is_none(),
        "nothing listens on {port}"
    );
}

#[test]
fn an_invalid_reload_keeps_the_previous_config() {
    let mut agent = Agent::start("");
    agent.rewrite("[gate]\nunmached = \"deny\"\n");
    agent.signal("HUP");
    let line = agent.line(&[r#""level":"ERROR""#, "gate.unmached"]);
    assert!(line.contains("line 4, column 1"), "{line}");
    assert_eq!(
        reload_failures(&agent),
        "speculaire_config_reload_failures_total 1"
    );
    assert_eq!(agent.get("/readyz", "").status, 200);
    let (status, lines) = agent.stop();
    assert!(status.success(), "{status}");
    let errors = lines
        .iter()
        .filter(|l| l.contains(r#""level":"ERROR""#))
        .count();
    assert_eq!(errors, 1, "{lines:#?}");
}

#[test]
fn sighup_applies_log_filter() {
    let mut agent = Agent::start("");
    agent.rewrite("[log]\nfilter = \"debug\"\n");
    agent.signal("HUP");
    agent.line(&[r#""level":"DEBUG""#, "config reloaded"]);
}

#[test]
fn a_poll_reloads_a_changed_file() {
    let mut agent = Agent::start("[config]\npoll_interval = \"1s\"\n");
    agent.rewrite("[config]\npoll_interval = \"1s\"\n[log]\nfilter = \"debug\"\n");
    agent.line(&[r#""level":"DEBUG""#, "config reloaded"]);
}

#[test]
fn a_restart_key_keeps_its_running_value() {
    let mut agent = Agent::start("");
    let other = free_port();
    std::fs::write(
        &agent.config,
        format!("[metrics]\naddress = \"127.0.0.1:{other}\"\n"),
    )
    .unwrap();
    agent.signal("HUP");
    agent.line(&[r#""level":"WARN""#, r#""key":"metrics.address""#]);
    assert_eq!(agent.get("/livez", "").status, 200);
    assert!(
        get(other, "/livez", "").is_none(),
        "nothing listens on {other}"
    );
}

#[test]
fn metrics_are_protobuf_when_asked_and_text_otherwise() {
    let agent = Agent::start("");
    let text = agent.get("/metrics", "");
    assert!(
        text.content_type.starts_with("text/plain"),
        "{}",
        text.content_type
    );
    let protobuf = agent.get("/metrics", PROTOBUF);
    assert_eq!(protobuf.content_type, PROTOBUF);
    assert!(
        protobuf
            .body
            .windows(21)
            .any(|w| w == b"speculaire_build_info")
    );
}

#[test]
fn every_exported_metric_is_in_the_catalog() {
    let agent = Agent::start("");
    let catalog = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/metrics.md"),
    )
    .unwrap();
    let text = agent.get("/metrics", "").text();
    let names: Vec<_> = text
        .lines()
        .filter_map(|l| l.strip_prefix("# TYPE ")?.split(' ').next())
        .collect();
    assert!(names.contains(&"speculaire_build_info"), "{names:?}");
    let missing: Vec<_> = names
        .iter()
        .filter(|n| !catalog.contains(&format!("| `{n}` |")))
        .collect();
    assert!(
        missing.is_empty(),
        "exported but not in docs/metrics.md: {missing:?}"
    );
}

#[test]
fn the_agent_tells_systemd_when_it_is_ready_and_when_it_stops() {
    let notifications = Notifications::bind();
    let agent = Agent::start_with_env("", &[("NOTIFY_SOCKET", notifications.path())]);
    assert_eq!(notifications.next(), "READY=1\n");
    let (status, _) = agent.stop();
    assert!(status.success(), "{status}");
    // No `WATCHDOG_USEC`: no pings in between.
    assert_eq!(notifications.next(), "STOPPING=1\n");
}

#[test]
fn the_watchdog_is_pinged_every_half_of_its_timeout() {
    let notifications = Notifications::bind();
    let _agent = Agent::start_with_env(
        "",
        &[
            ("NOTIFY_SOCKET", notifications.path()),
            ("WATCHDOG_USEC", "1000000"),
        ],
    );
    let mut pings = Vec::new();
    while pings.len() < 3 {
        if notifications.next() == "WATCHDOG=1\n" {
            pings.push(Instant::now());
        }
    }
    // The first ping is at once, then one every 0.5 s: the third comes after 1 s, not after the 4 s of a ping
    // every timeout.
    let spread = pings[2] - pings[0];
    assert!(spread < Duration::from_millis(2500), "{spread:?}");
}

#[test]
fn a_new_poll_interval_applies_to_the_next_poll() {
    let mut agent = Agent::start("[config]\npoll_interval = \"1h\"\n");
    let fast = "[config]\npoll_interval = \"1s\"\n[log]\nfilter = \"debug\"\n";
    agent.rewrite(fast);
    agent.signal("HUP");
    agent.line(&[r#""level":"DEBUG""#, "config reloaded"]);
    // Only a poll at the new interval sees this: the old one is an hour. The pause puts the write past the reload's
    // start even when the kernel's coarse file clock dates it a few milliseconds early.
    std::thread::sleep(Duration::from_millis(100));
    agent.rewrite(fast);
    agent.line(&[r#""level":"DEBUG""#, "config reloaded"]);
}

#[test]
fn the_mirror_listens_while_the_agent_runs_and_stops_with_it() {
    let agent = Agent::start("");
    let mirror = (Ipv4Addr::LOCALHOST, agent.mirror_port);
    assert!(
        TcpStream::connect(mirror).is_ok(),
        "nothing listens on the mirror address"
    );
    let mirror_port = agent.mirror_port;
    let (status, _) = agent.stop();
    assert!(status.success(), "{status}");
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, mirror_port)).is_err());
}

#[test]
fn the_agent_stops_at_startup_without_the_mirror_certificates_and_says_how_to_make_them() {
    let node = Node::healthy();
    let (status, stderr) = refused(&node, "[mirror]\ndirectory = \"/nonexistent/mirror\"\n");
    assert_eq!(status, Some(1), "{stderr}");
    assert!(
        stderr.contains("/nonexistent/mirror/ca.crt") && stderr.contains("speculaire configure"),
        "{stderr}"
    );
}

/// `speculaire <command> --config <a config on node>` with `mirror` as the `[mirror]` table: the exit code and stderr.
fn run_on(node: &Node, command: &str, mirror: &str) -> (Option<i32>, String) {
    let config = node.dir.path().join("agent.toml");
    std::fs::write(
        &config,
        format!(
            "[metrics]\naddress = \"127.0.0.1:{}\"\n{}\n{mirror}\n",
            free_port(),
            node.table()
        ),
    )
    .unwrap();
    let mut args = vec![command];
    if command == "agent" || command == "configure" {
        args.push("--config");
    }
    let out = Command::new(env!("CARGO_BIN_EXE_speculaire"))
        .args(args)
        .arg(&config)
        .env_remove("JOURNAL_STREAM")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The agent on `node`, which does not start: its exit code and stderr.
fn refused(node: &Node, mirror: &str) -> (Option<i32>, String) {
    run_on(node, "agent", mirror)
}

/// A `[mirror]` table with the certificates every test shares.
fn certificates() -> String {
    format!(
        "[mirror]\ndirectory = \"{}\"\n",
        mirror_certificates().display()
    )
}

const IMAGES: &str = "[plugins.'io.containerd.cri.v1.images']";
const NRI: &str = "[plugins.'io.containerd.nri.v1.nri']";

#[test]
fn preflight_refuses_a_containerd_older_than_2_3_and_names_its_version() {
    let node = Node::new(Answers::containerd("v2.2.9"), None);
    let (code, stderr) = refused(&node, &certificates());
    assert_eq!(code, Some(1), "{stderr}");
    assert!(
        stderr.contains("1 problem on this node keeps the agent from starting")
            && stderr.contains("containerd 2.2.9 is older than 2.3.0")
            && stderr.contains("containerd.sock"),
        "{stderr}"
    );
}

#[test]
fn preflight_refuses_what_the_running_image_service_discards_or_leaves_unset() {
    let mut answers = Answers::containerd("v2.4.2");
    answers.image_exports = Some((true, "/etc/containerd/certs.d".to_owned()));
    let (code, stderr) = refused(&Node::new(answers, None), &certificates());
    assert_eq!(code, Some(1), "{stderr}");
    assert!(
        stderr.contains("config.toml: `discard_unpacked_layers = true`")
            && stderr.contains("set it to false"),
        "{stderr}"
    );
    let mut answers = Answers::containerd("v2.4.2");
    answers.image_exports = Some((false, String::new()));
    let (code, stderr) = refused(&Node::new(answers, None), &certificates());
    assert_eq!(code, Some(1), "{stderr}");
    assert!(
        stderr.contains("config.toml: `config_path` is not set"),
        "{stderr}"
    );
}

#[test]
fn preflight_refuses_an_nri_that_is_off_or_closed_naming_the_key() {
    for (config, key) in [
        (
            format!("version = 3\n{NRI}\ndisable = true\n"),
            "`disable = true`",
        ),
        (
            format!("version = 3\n{NRI}\ndisable_connections = true\n"),
            "`disable_connections = true`",
        ),
    ] {
        let node = Node::new(Answers::containerd("v2.4.2"), Some(&config));
        let (code, stderr) = refused(&node, &certificates());
        assert_eq!(code, Some(1), "{stderr}");
        assert!(
            stderr.contains(&format!("config.toml: {key} in {NRI}")),
            "{stderr}"
        );
    }
}

#[test]
fn a_containerd_2_3_has_its_settings_read_from_the_config_file() {
    let mut answers = Answers::containerd("v2.3.7");
    answers.image_exports = None;
    let config = format!("version = 3\n{IMAGES}\ndiscard_unpacked_layers = true\n");
    let (code, stderr) = refused(&Node::new(answers.clone(), Some(&config)), &certificates());
    assert_eq!(code, Some(1), "{stderr}");
    assert!(
        stderr.contains("`discard_unpacked_layers = true`"),
        "{stderr}"
    );
    // Its config says nothing of it: the agent starts.
    let agent = Agent::spawn_on(
        Node::new(answers, Some("version = 3\n")),
        free_port(),
        scratch_file(),
        "",
        &[],
    );
    wait_until(|| get(agent.port, "/readyz", "").is_some_and(|r| r.status == 200));
}

#[test]
fn a_mirror_address_that_is_not_loopback_stops_startup() {
    let (code, stderr) = refused(
        &Node::healthy(),
        &format!(
            "[mirror]\naddress = \"10.0.0.1:7480\"\ndirectory = \"{}\"\n",
            mirror_certificates().display()
        ),
    );
    assert_eq!(code, Some(1), "{stderr}");
    assert!(
        stderr.contains("mirror.address") && stderr.contains("loopback"),
        "{stderr}"
    );
}

#[test]
fn an_agent_that_cannot_open_the_mirror_stops_and_one_that_can_is_ready() {
    // The mirror address is held by someone else.
    let holder = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let node = Node::healthy();
    let mirror = format!(
        "[mirror]\naddress = \"127.0.0.1:{}\"\ndirectory = \"{}\"\n",
        holder.local_addr().unwrap().port(),
        mirror_certificates().display()
    );
    let (code, stderr) = refused(&node, &mirror);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains("listening on mirror.address"), "{stderr}");
    // `/readyz` is 200 only once the mirror listens, and this agent is ready.
    let agent = Agent::start("");
    assert_eq!(agent.get("/readyz", "").status, 200);
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, agent.mirror_port)).is_ok());
}

#[test]
fn check_config_exits_1_with_the_same_messages_and_0_on_a_node_that_is_right() {
    // A node `configure` has run on: config_path in the node's directory, the certificates in a directory of its own.
    let config = "version = 3\n[plugins.'io.containerd.cri.v1.images'.registry]\nconfig_path = \"@DIR@/certs.d\"\n";
    let node = Node::new(Answers::containerd("v2.4.2"), Some(config));
    let mirror = format!(
        "[mirror]\ndirectory = \"{}/mirror\"\n",
        node.dir.path().display()
    );
    let (code, stderr) = run_on(&node, "check-config", &mirror);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(
        stderr.contains("mirror/ca.crt") && stderr.contains("hosts.toml"),
        "{stderr}"
    );
    let (code, stderr) = run_on(&node, "configure", &mirror);
    assert_eq!(code, Some(0), "{stderr}");
    let (code, stderr) = run_on(&node, "check-config", &mirror);
    assert_eq!((code, stderr.as_str()), (Some(0), ""));
    // The problems the agent refuses to start on, each once.
    let mut answers = Answers::containerd("v2.4.2");
    answers.image_exports = Some((true, String::new()));
    let broken = Node::new(answers, Some(config));
    let mirror = format!(
        "[mirror]\ndirectory = \"{}/mirror\"\n",
        broken.dir.path().display()
    );
    assert_eq!(run_on(&broken, "configure", &mirror).0, Some(0));
    let (code, stderr) = run_on(&broken, "check-config", &mirror);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(
        stderr.contains("`discard_unpacked_layers = true`"),
        "{stderr}"
    );
    assert!(stderr.contains("`config_path` is not set"), "{stderr}");
    assert!(stderr.contains("2 problems with the runtime"), "{stderr}");
    let (code, agent) = refused(&broken, &mirror);
    assert_eq!(code, Some(1), "{agent}");
    assert!(
        agent.contains("2 problems on this node keep the agent from starting"),
        "{agent}"
    );
}
