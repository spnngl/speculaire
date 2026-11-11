//! `speculaire agent` as a process: startup, reloads, logs, `/metrics` and shutdown (D30, D34, D37, D42, D45).
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "the helpers of a test fail it by panicking"
)]

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(10);
const PROTOBUF: &str =
    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited";

/// A running `speculaire agent`, killed on drop.
struct Agent {
    child: Child,
    port: u16,
    config: PathBuf,
    stderr: Receiver<String>,
    seen: Vec<String>,
}

impl Agent {
    /// Starts the agent on a free port with `extra` appended to its config.
    fn start(extra: &str) -> Self {
        let port = free_port();
        let config = scratch_file();
        let agent = Self::spawn(port, config, extra);
        wait_until(|| get(port, "/livez", "").is_some_and(|r| r.status == 200));
        agent
    }

    fn spawn(port: u16, config: PathBuf, extra: &str) -> Self {
        write_config(&config, port, extra);
        let mut child = Command::new(env!("CARGO_BIN_EXE_speculaire"))
            .args(["agent", "--config"])
            .arg(&config)
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
            config,
            stderr,
            seen: Vec::new(),
        }
    }

    fn rewrite(&self, extra: &str) {
        write_config(&self.config, self.port, extra);
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

/// Writes a config listening on `port`; `extra` holds further tables.
fn write_config(path: &Path, port: u16, extra: &str) {
    std::fs::write(
        path,
        format!("[metrics]\naddress = \"127.0.0.1:{port}\"\n{extra}"),
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
    let mut agent = Agent::spawn(port, scratch_file(), "[gate]\nunmached = \"deny\"\n");
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
