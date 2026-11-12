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
use speculaire_pki::mirror::{Mirror, Part};

const WAIT: Duration = Duration::from_secs(10);
const PROTOBUF: &str =
    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited";

/// A running `speculaire agent`, killed on drop.
struct Agent {
    child: Child,
    port: u16,
    mirror_port: u16,
    config: PathBuf,
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
        let mirror_port = free_port();
        write_config(&config, port, mirror_port, extra);
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
            stderr,
            seen: Vec::new(),
        }
    }

    fn rewrite(&self, extra: &str) {
        write_config(&self.config, self.port, self.mirror_port, extra);
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

/// Writes a config listening on `port` and, for the mirror, on `mirror_port`; `extra` holds further tables.
fn write_config(path: &Path, port: u16, mirror_port: u16, extra: &str) {
    std::fs::write(
        path,
        format!(
            "[metrics]\naddress = \"127.0.0.1:{port}\"\n{extra}\n[mirror]\naddress = \"127.0.0.1:{mirror_port}\"\ndirectory = \"{}\"\n",
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
    let config = scratch_file();
    std::fs::write(
        &config,
        format!(
            "[metrics]\naddress = \"127.0.0.1:{}\"\n[mirror]\naddress = \"127.0.0.1:{}\"\ndirectory = \"/nonexistent/mirror\"\n",
            free_port(),
            free_port()
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_speculaire"))
        .args(["agent", "--config"])
        .arg(&config)
        .env_remove("JOURNAL_STREAM")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("/nonexistent/mirror") && stderr.contains("speculaire configure"),
        "{stderr}"
    );
}
