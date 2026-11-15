//! A node of the runs: `speculaire agent` on a fake containerd, in a process of its own, so that its RSS and its
//! profile are its own (D33, D116). The reflector under load is one with `role = "reflector"`.

use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context as _, bail, ensure};
use secrecy::ExposeSecret as _;
use speculaire_fake_runtime::{Answers, Fake};
use speculaire_pki::mirror::{Mirror, Part};
use speculaire_pki::testing::Cluster;
use speculaire_runtime::containerd::CONTENT_PLUGIN;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};

use crate::exposition::{self, Buckets, PROTOBUF};

/// The reflector's node, which its certificate names and its one member is.
pub(crate) const NODE: &str = "load-reflector";
/// The containerd version the nodes' fakes answer.
const CONTAINERD: &str = "v2.4.2";
/// The variable that names a node's process for a wrapper, such as `just profile`'s, which names its output after it.
const NODE_VARIABLE: &str = "SPECULAIRE_LOAD_NODE";

/// How long an agent may take to answer `/readyz` 200, under Valgrind too.
const READY: Duration = Duration::from_mins(2);
/// How long it may take to exit after SIGTERM: its drain, and Valgrind's leak check.
const EXIT: Duration = Duration::from_mins(2);
/// How often the gauges are read while waiting for them.
const POLL: Duration = Duration::from_millis(250);
/// How often a wait for the gauges logs them.
const PROGRESS: Duration = Duration::from_secs(5);

/// A node's files: its config, certificates and fake containerd, removed on drop.
pub(crate) struct Node {
    dir: tempfile::TempDir,
    _containerd: Fake,
    name: &'static str,
    /// Where the reflector listens for agents.
    pub(crate) listen: SocketAddr,
    /// Where the node's mirror listens.
    pub(crate) mirror: SocketAddr,
    metrics: SocketAddr,
}

impl Node {
    /// Writes the files of a reflector whose certificate `cluster` issues, on ports free now.
    pub(crate) fn new(cluster: &Cluster) -> anyhow::Result<Self> {
        let listen = free_port()?;
        Self::write(
            cluster,
            NODE,
            Answers::containerd(CONTAINERD),
            listen,
            "role = \"reflector\"\n",
            &format!(
                "[reflector]\nlisten = \"{listen}\"\nmembers = [{{ node = \"{NODE}\", address = \"{listen}\" }}]\n"
            ),
        )
    }

    /// Writes the files of the agent `name`, whose certificate `cluster` issues, which announces the `content` its fake
    /// containerd lists to the reflector of `reflector`, and serves peers on a port free now.
    pub(crate) fn agent(
        cluster: &Cluster,
        name: &'static str,
        content: Vec<String>,
        reflector: &Self,
    ) -> anyhow::Result<Self> {
        let peer = free_port()?;
        let mut containerd = Answers::containerd(CONTAINERD);
        containerd.content = content;
        Self::write(
            cluster,
            name,
            containerd,
            reflector.listen,
            "",
            &format!(
                "[peer]\naddress = \"{peer}\"\n[reflector]\nurl = \"https://{}\"\n",
                reflector.listen
            ),
        )
    }

    /// Writes the files of the node `name`, whose fake containerd gives `containerd`: its config is `top`, the tables
    /// every node has, and `tables`.
    fn write(
        cluster: &Cluster,
        name: &'static str,
        containerd: Answers,
        listen: SocketAddr,
        top: &str,
        tables: &str,
    ) -> anyhow::Result<Self> {
        let dir = tempfile::tempdir()?;
        let path = dir.path();
        let containerd = Fake::start(&path.join("containerd.sock"), containerd)?;
        let mirror = Mirror::generate(Ipv4Addr::LOCALHOST.into(), SystemTime::now())?;
        std::fs::create_dir(path.join("mirror"))?;
        for part in Part::ALL {
            std::fs::write(
                path.join("mirror").join(part.file_name()),
                mirror.contents(part).expose_secret(),
            )?;
        }
        std::fs::write(path.join("ca.crt"), cluster.ca())?;
        std::fs::write(path.join("node.pem"), cluster.kubelet(name))?;
        let (mirror, metrics) = (free_port()?, free_port()?);
        let d = path.display();
        std::fs::write(
            path.join("containerd.toml"),
            format!("version = 3\nroot = \"{d}/root\"\n"),
        )?;
        std::fs::write(
            path.join("config.toml"),
            format!(
                "{top}\
                 [identity]\ncertificate = \"{d}/node.pem\"\nca = \"{d}/ca.crt\"\n\
                 [runtime]\ncontainerd_socket = \"{d}/containerd.sock\"\ncontainerd_config = \"{d}/containerd.toml\"\n\
                 crio_socket = \"{d}/crio.sock\"\n\
                 [mirror]\naddress = \"{mirror}\"\ndirectory = \"{d}/mirror\"\n\
                 [blob_cache]\ndirectory = \"{d}/blobs\"\n\
                 [metrics]\naddress = \"{metrics}\"\n\
                 {tables}"
            ),
        )?;
        Ok(Self {
            dir,
            _containerd: containerd,
            name,
            listen,
            mirror,
            metrics,
        })
    }

    /// The CA certificate file, which the agents trust.
    pub(crate) fn ca(&self) -> PathBuf {
        self.dir.path().join("ca.crt")
    }

    /// A directory for the agents' files.
    pub(crate) fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The content directory below the `root` of the node's containerd config, where its agent reads blobs (D110).
    pub(crate) fn content(&self) -> PathBuf {
        self.path().join("root").join(CONTENT_PLUGIN)
    }
}

/// A port nobody listens on now; an agent binds it a moment later, and again after its restart.
fn free_port() -> std::io::Result<SocketAddr> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?.local_addr()
}

/// A running agent, killed on drop.
pub(crate) struct Agent {
    child: Child,
    pid: u32,
    metrics: SocketAddr,
}

impl Agent {
    /// Starts `command` followed by `agent --config` and `node`'s config, with the node's name in [`NODE_VARIABLE`],
    /// and returns once `/readyz` answers 200.
    pub(crate) async fn start(command: &[OsString], node: &Node) -> anyhow::Result<Self> {
        let (program, args) = command.split_first().context("no agent command")?;
        let mut child = Command::new(program)
            .args(args)
            .args([
                "agent".as_ref(),
                "--config".as_ref(),
                node.path().join("config.toml").as_os_str(),
            ])
            .env_remove("JOURNAL_STREAM")
            .env(NODE_VARIABLE, node.name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("cannot start {}", program.display()))?;
        let name = node.name;
        let pid = child
            .id()
            .with_context(|| format!("{name} exited at once"))?;
        let deadline = Instant::now() + READY;
        loop {
            if let Some(status) = child.try_wait()? {
                bail!("{name} exited before it was ready: {status}");
            }
            if let Ok((200, _)) = get(node.metrics, "/readyz", "").await {
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "{name} was not ready within {READY:?}"
            );
            tokio::time::sleep(POLL).await;
        }
        Ok(Self {
            child,
            pid,
            metrics: node.metrics,
        })
    }

    /// Waits until the reflector holds `pairs` digests of `agents` agents, and returns how long that took; `None`
    /// when it still does not after `within`.
    pub(crate) async fn settled(
        &self,
        agents: usize,
        pairs: usize,
        within: Duration,
    ) -> anyhow::Result<Option<Duration>> {
        let start = Instant::now();
        #[expect(
            clippy::cast_precision_loss,
            reason = "both counts stay far below 2^53"
        )]
        let wanted = (agents as f64, pairs as f64);
        let mut found = (None, None);
        let mut progress = start;
        let settling = async {
            loop {
                let text = String::from_utf8(get(self.metrics, "/metrics", "").await?.1)?;
                found = (
                    exposition::gauge(&text, "speculaire_reflector_agents"),
                    exposition::gauge(&text, "speculaire_reflector_pairs"),
                );
                // The gauges hold exact integers.
                if found == (Some(wanted.0), Some(wanted.1)) {
                    return anyhow::Ok(start.elapsed());
                }
                if progress.elapsed() >= PROGRESS {
                    progress = Instant::now();
                    let elapsed = start.elapsed();
                    tracing::info!(?found, ?elapsed, "settling");
                }
                tokio::time::sleep(POLL).await;
            }
        };
        if let Ok(settled) = tokio::time::timeout(within, settling).await {
            return settled.map(Some);
        }
        tracing::warn!(?found, ?wanted, "the reflector did not settle in time");
        Ok(None)
    }

    /// The lookups the reflector has answered, `speculaire_reflector_lookup_seconds`.
    pub(crate) async fn lookups(&self) -> anyhow::Result<Buckets> {
        let (status, body) = get(self.metrics, "/metrics", PROTOBUF).await?;
        ensure!(status == 200, "/metrics answered {status}");
        Buckets::parse(&body, "speculaire_reflector_lookup_seconds")
    }

    /// A size in `/proc/<pid>/status`, such as `VmRSS` or `VmHWM`, in bytes.
    pub(crate) fn memory(&self, field: &str) -> anyhow::Result<u64> {
        let status = std::fs::read_to_string(format!("/proc/{}/status", self.pid))
            .context("cannot read the reflector's /proc status: the load runs on Linux")?;
        kilobytes(&status, field)
            .map(|kb| kb << 10)
            .with_context(|| format!("no {field} in the reflector's /proc status"))
    }

    /// Sends SIGTERM and waits for the agent to exit with success.
    pub(crate) async fn stop(mut self) -> anyhow::Result<()> {
        let kill = Command::new("kill")
            .args(["-TERM", &self.pid.to_string()])
            .status()
            .await?;
        ensure!(kill.success(), "kill -TERM {}: {kill}", self.pid);
        let status = tokio::time::timeout(EXIT, self.child.wait())
            .await
            .context("the agent did not exit after SIGTERM")??;
        ensure!(status.success(), "the agent exited with {status}");
        Ok(())
    }
}

/// The value of `field` in a `/proc/<pid>/status`, such as `VmRSS:\t  1234 kB`, in kB.
fn kilobytes(status: &str, field: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        line.strip_prefix(field)?
            .strip_prefix(':')?
            .trim()
            .strip_suffix(" kB")?
            .parse()
            .ok()
    })
}

/// A one-request HTTP/1.1 `GET`: the status and the body.
async fn get(to: SocketAddr, path: &str, accept: &str) -> anyhow::Result<(u16, Vec<u8>)> {
    let mut stream = TcpStream::connect(to).await?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept: {accept}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    response(raw)
}

/// The status and body of an HTTP/1.1 response sent whole with `Content-Length`, as the agent sends them.
fn response(mut raw: Vec<u8>) -> anyhow::Result<(u16, Vec<u8>)> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("an HTTP response without a complete head")?;
    let head = std::str::from_utf8(&raw[..split])?;
    ensure!(
        !head
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked"),
        "a chunked HTTP response"
    );
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("an HTTP response without a status")?;
    Ok((status, raw.split_off(split + 4)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_status_sizes_are_read_in_kilobytes() {
        let status = "Name:\tspeculaire\nVmHWM:\t  204800 kB\nVmRSS:\t  102400 kB\nThreads:\t9\n";
        assert_eq!(kilobytes(status, "VmRSS"), Some(102_400));
        assert_eq!(kilobytes(status, "VmHWM"), Some(204_800));
        assert_eq!(kilobytes(status, "Vm"), None);
        assert_eq!(kilobytes(status, "Threads"), None);
    }

    #[test]
    fn a_response_is_split_into_status_and_body() {
        let (status, body) =
            response(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 2\r\n\r\nno".to_vec())
                .unwrap();
        assert_eq!((status, body.as_slice()), (503, b"no".as_slice()));
        assert!(response(b"HTTP/1.1 200 OK\r\n".to_vec()).is_err());
        assert!(
            response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec()).is_err()
        );
        assert!(response(b"garbage\r\n\r\n".to_vec()).is_err());
    }
}
