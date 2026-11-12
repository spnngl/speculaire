//! The registries and the proxy that the relay suite pulls from (D66, D67, D88).
//!
//! Each is a container on kind's Docker network, which the nodes reach by name, and each is removed when its guard
//! drops. `just e2e-down` removes what a killed run left, by label.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::{Failure, run};

/// The registry, which also serves as the upstream of every pull the suite makes.
pub const REGISTRY_IMAGE: &str = "docker.io/library/registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e";
/// A registry that trusts a token's key by the libtrust identifier `docker_auth` stamps on it; v3 trusts RFC 7638 thumbprints.
pub const TOKEN_REGISTRY_IMAGE: &str = "docker.io/library/registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373";

/// The token server of the Bearer registry.
pub const TOKEN_SERVER_IMAGE: &str = "docker.io/cesanta/docker_auth:1.14.0@sha256:98e0307e0d2dcbafe10098814a97d248143b78ca478693f78c3c0d67fe776ab4";
/// The image that copies images between registries.
pub const COPY_IMAGE: &str = "docker.io/regclient/regctl:v0.8.3-alpine@sha256:e50f92394d7826dde8f6558511178988b4ce64267519b8b0a9c6c47fbeae6a16";
/// The image that has `htpasswd`.
pub const HTPASSWD_IMAGE: &str = "docker.io/library/httpd:2.4.66-alpine@sha256:968c8b4098fcecb473762b45f6c541a3b2b2cfab2caccb1edbd2cece071ef160";
/// The image the proxy runs in.
pub const PROXY_IMAGE: &str = "docker.io/library/python:3.14-alpine@sha256:5862d971d1f0ae26b258cefa4e893556b1d3aba81bd2ff30888704ad378bab67";
/// An image of about 25 MB in seven layers, for the pulls that need bytes.
pub const LARGE_IMAGE: &str = "docker.io/library/nginx:alpine@sha256:713fc2ebfd92e8217db451477182ee91944b123d2b1ee9fd5a8c6e91ca6c3a11";

/// The label of every container the suite starts.
const LABEL: &str = "speculaire-e2e";
/// kind's Docker network.
const NETWORK: &str = "kind";
/// The user and the password of the registries that want a login.
pub const USER: &str = "alice";
/// See [`USER`].
pub const PASSWORD: &str = "s3cret";

fn docker(args: &[&str]) -> Result<String, Failure> {
    run(Command::new("docker").args(args))
}

fn fail(command: &str, detail: &dyn ToString) -> Failure {
    Failure {
        command: command.to_owned(),
        detail: detail.to_string(),
    }
}

/// A container that is removed when this drops.
pub struct Container {
    name: String,
}

impl Container {
    /// Creates the container, copies `files` (host path, path in the container) into it, and starts it.
    fn start(
        name: &str,
        image: &str,
        env: &[(&str, &str)],
        files: &[(&Path, &str)],
        command: &[&str],
    ) -> Result<Self, Failure> {
        // What an earlier, killed run left.
        let _ = docker(&["rm", "-f", name]);
        let mut args = vec![
            "create",
            "--name",
            name,
            "--network",
            NETWORK,
            "--label",
            LABEL,
        ];
        let envs: Vec<String> = env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        for env in &envs {
            args.extend(["-e", env]);
        }
        args.push(image);
        args.extend(command);
        docker(&args)?;
        let container = Self {
            name: name.to_owned(),
        };
        for (host, inside) in files {
            docker(&[
                "cp",
                &host.display().to_string(),
                &format!("{name}:{inside}"),
            ])?;
        }
        docker(&["start", name])?;
        Ok(container)
    }

    /// What the container wrote to stdout and stderr.
    ///
    /// # Errors
    ///
    /// When `docker` cannot start.
    pub fn logs(&self) -> Result<String, Failure> {
        let out = Command::new("docker")
            .args(["logs", &self.name])
            .output()
            .map_err(|e| fail("docker logs", &e))?;
        Ok(format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ))
    }

    fn wait_for_log(&self, needle: &str) -> Result<(), Failure> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if self.logs()?.contains(needle) {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(fail(
                    &format!("docker logs {}", self.name),
                    &format!("no {needle:?} in 60 s"),
                ));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", "-v", &self.name]);
    }
}

/// How a registry asks for a login.
pub enum Access<'a> {
    /// None.
    Open,
    /// HTTP Basic, with the [`USER`] of [`htpasswd`].
    Basic(&'a str),
    /// TLS with `certificates`, and a Bearer challenge to the token server `realm`.
    Token {
        /// The certificates the registry serves with and whose key the token server signs with.
        certificates: &'a Certificates,
        /// The token server's URL, `https://<name>:5001/auth`.
        realm: &'a str,
    },
}

/// A registry on kind's network, which the host can push to.
pub struct Registry {
    container: Container,
    name: String,
}

impl Registry {
    /// Starts a registry named `name` that asks for `access`, with the storage of `from` when it has one.
    ///
    /// # Errors
    ///
    /// When `docker` fails or the registry does not start.
    pub fn start(
        name: &str,
        access: &Access<'_>,
        from: Option<&Registry>,
    ) -> Result<Self, Failure> {
        let scratch = scratch(name)?;
        let htpasswd_path = scratch.join("htpasswd");
        // On the default port of its scheme: a name with a port is not mirrored on CRI-O (D88).
        let mut env: Vec<(&str, &str)> = Vec::new();
        let mut files: Vec<(&Path, &str)> = Vec::new();
        let (crt, key);
        match access {
            Access::Open => env.push(("REGISTRY_HTTP_ADDR", ":80")),
            Access::Basic(line) => {
                std::fs::write(&htpasswd_path, line).map_err(|e| fail("write htpasswd", &e))?;
                files.push((&htpasswd_path, "/htpasswd"));
                env.extend([
                    ("REGISTRY_HTTP_ADDR", ":80"),
                    ("REGISTRY_AUTH_HTPASSWD_REALM", "e2e"),
                    ("REGISTRY_AUTH_HTPASSWD_PATH", "/htpasswd"),
                ]);
            }
            Access::Token {
                certificates,
                realm,
            } => {
                crt = certificates.dir.join("server.crt");
                key = certificates.dir.join("server.key");
                files.push((&crt, "/server.crt"));
                files.push((&key, "/server.key"));
                env.extend([
                    ("REGISTRY_HTTP_ADDR", ":443"),
                    ("REGISTRY_HTTP_TLS_CERTIFICATE", "/server.crt"),
                    ("REGISTRY_HTTP_TLS_KEY", "/server.key"),
                    ("REGISTRY_AUTH_TOKEN_REALM", realm),
                    ("REGISTRY_AUTH_TOKEN_SERVICE", "e2e-registry"),
                    ("REGISTRY_AUTH_TOKEN_ISSUER", "e2e-auth"),
                    ("REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE", "/server.crt"),
                ]);
            }
        }
        // The storage of `from` goes in before the registry starts: a registry indexes nothing, it reads the tree.
        let storage = scratch.join("storage");
        if let Some(from) = from {
            docker(&[
                "cp",
                &format!("{}:/var/lib/registry", from.container.name),
                &storage.display().to_string(),
            ])?;
        }
        let image = match access {
            Access::Token { .. } => TOKEN_REGISTRY_IMAGE,
            _ => REGISTRY_IMAGE,
        };
        let container = Container::start(name, image, &env, &files, &[])?;
        if from.is_some() {
            docker(&["stop", name])?;
            docker(&[
                "cp",
                &format!("{}/.", storage.display()),
                &format!("{name}:/var/lib/registry"),
            ])?;
            docker(&["start", name])?;
        }
        container.wait_for_log("listening on")?;
        let _ = std::fs::remove_dir_all(&scratch);
        Ok(Self {
            container,
            name: name.to_owned(),
        })
    }

    /// The name a node pulls by.
    #[must_use]
    pub fn address(&self) -> String {
        self.name.clone()
    }

    /// The registry's own log: one line per request.
    ///
    /// # Errors
    ///
    /// When `docker` cannot start.
    pub fn logs(&self) -> Result<String, Failure> {
        self.container.logs()
    }

    /// How many blob requests the registry has served: the `GET`s of `/blobs/sha256:` in its log.
    ///
    /// # Errors
    ///
    /// When `docker` cannot start.
    pub fn blob_requests(&self) -> Result<usize, Failure> {
        Ok(self
            .logs()?
            .lines()
            .filter(|line| {
                line.contains("/blobs/sha256:")
                    && line.contains("GET")
                    && line.contains("response completed")
            })
            .count())
    }

    /// Copies `source`, an image of a public registry, into this one as `reference`, for the host's platform, which is
    /// the nodes'. A container on kind's network does it: the Docker daemon cannot always reach a port it published.
    ///
    /// # Errors
    ///
    /// When `docker` fails.
    pub fn copy_in(&self, source: &str, reference: &str) -> Result<(), Failure> {
        let platform = match std::env::consts::ARCH {
            "aarch64" => "linux/arm64",
            _ => "linux/amd64",
        };
        let address = self.address();
        docker(&[
            "run",
            "--rm",
            "--network",
            NETWORK,
            "--label",
            LABEL,
            "--entrypoint",
            "sh",
            COPY_IMAGE,
            "-c",
            &format!(
                "regctl registry set --tls disabled {address} && regctl image copy --platform {platform} {source} {address}/{reference}"
            ),
        ])
        .map(drop)
    }
}

/// A line of an `htpasswd` file for [`USER`] with [`PASSWORD`], bcrypt-hashed.
///
/// # Errors
///
/// When `docker` fails.
pub fn htpasswd() -> Result<String, Failure> {
    docker(&[
        "run",
        "--rm",
        "--entrypoint",
        "htpasswd",
        HTPASSWD_IMAGE,
        "-nbB",
        USER,
        PASSWORD,
    ])
}

fn scratch(name: &str) -> Result<PathBuf, Failure> {
    let dir = std::env::temp_dir().join(format!("speculaire-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| fail("create a scratch directory", &e))?;
    Ok(dir)
}

/// A CA and one certificate for several names, in a directory of `ca.crt`, `server.crt` and `server.key`.
pub struct Certificates {
    dir: PathBuf,
    ca: String,
}

impl Certificates {
    /// Makes them for `names`.
    ///
    /// # Errors
    ///
    /// When a key or a file cannot be made.
    pub fn new(label: &str, names: &[&str]) -> Result<Self, Failure> {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
        let err = |e: rcgen::Error| fail("rcgen", &e);
        let ca_key = KeyPair::generate().map_err(err)?;
        let mut ca_params = CertificateParams::new(Vec::new()).map_err(err)?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = ca_params.self_signed(&ca_key).map_err(err)?;
        let issuer = Issuer::new(ca_params, &ca_key);
        // RSA: the token server signs with this key, and the registry finds it by the ID that libtrust makes of it,
        // which is the path docker_auth's own documentation takes.
        let server_key = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).map_err(err)?;
        let server_params =
            CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
                .map_err(err)?;
        let server = server_params.signed_by(&server_key, &issuer).map_err(err)?;
        let dir = scratch(label)?;
        let write = |file: &str, text: &str| {
            std::fs::write(dir.join(file), text).map_err(|e| fail("write a certificate", &e))
        };
        write("ca.crt", &ca.pem())?;
        write("server.crt", &server.pem())?;
        write("server.key", &server_key.serialize_pem())?;
        Ok(Self { dir, ca: ca.pem() })
    }

    /// The CA certificate, PEM.
    #[must_use]
    pub fn ca(&self) -> &str {
        &self.ca
    }
}

impl Drop for Certificates {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The token server of a Bearer registry, with [`USER`] and [`PASSWORD`] allowed everything.
pub struct TokenServer {
    _container: Container,
}

impl TokenServer {
    /// Starts it as `name`, signing with the key of `certificates`.
    ///
    /// # Errors
    ///
    /// When `docker` fails or the server does not start.
    pub fn start(
        name: &str,
        certificates: &Certificates,
        htpasswd_line: &str,
    ) -> Result<Self, Failure> {
        let scratch = scratch(name)?;
        let hash = htpasswd_line
            .trim()
            .split_once(':')
            .map_or("", |(_, hash)| hash);
        let config = scratch.join("auth_config.yml");
        std::fs::write(
            &config,
            format!(
                "server:\n  addr: \":5001\"\n  certificate: \"/server.crt\"\n  key: \"/server.key\"\ntoken:\n  issuer: \"e2e-auth\"\n  expiration: 900\nusers:\n  \"{USER}\":\n    password: \"{hash}\"\nacl:\n  - match: {{account: \"{USER}\"}}\n    actions: [\"*\"]\n"
            ),
        )
        .map_err(|e| fail("write auth_config.yml", &e))?;
        let crt = certificates.dir.join("server.crt");
        let key = certificates.dir.join("server.key");
        let container = Container::start(
            name,
            TOKEN_SERVER_IMAGE,
            &[],
            &[
                (&config, "/auth_config.yml"),
                (&crt, "/server.crt"),
                (&key, "/server.key"),
            ],
            &["--logtostderr", "/auth_config.yml"],
        )?;
        container.wait_for_log("Serving on")?;
        let _ = std::fs::remove_dir_all(&scratch);
        Ok(Self {
            _container: container,
        })
    }
}

/// A transparent proxy, on port 80, in front of a registry that can flip a byte of every blob, and slow every blob down.
pub struct Proxy {
    container: Container,
    name: String,
}

const PROXY_SCRIPT: &str = r#"import http.client, http.server, os, socketserver, sys, time

HOST, _, PORT = os.environ["UPSTREAM"].partition(":")
PORT = PORT or "80"
FLIP = int(os.environ.get("FLIP", "-1"))
RATE = int(os.environ.get("RATE", "0"))


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        upstream = http.client.HTTPConnection(HOST, int(PORT))
        upstream.request(
            self.command,
            self.path,
            headers={k: v for k, v in self.headers.items() if k.lower() != "host"},
        )
        response = upstream.getresponse()
        self.send_response(response.status)
        for key, value in response.getheaders():
            if key.lower() not in ("transfer-encoding", "connection"):
                self.send_header(key, value)
        self.end_headers()
        if self.command == "HEAD":
            return
        blob = "/blobs/" in self.path
        if blob:
            print("blob " + self.path, flush=True)
        position = 0
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            if blob and position <= FLIP < position + len(chunk):
                flipped = bytearray(chunk)
                flipped[FLIP - position] ^= 0xFF
                chunk = bytes(flipped)
            self.wfile.write(chunk)
            self.wfile.flush()
            position += len(chunk)
            if blob and RATE:
                time.sleep(len(chunk) / RATE)

    do_HEAD = do_GET


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


print("serving", flush=True)
Server(("0.0.0.0", 80), Handler).serve_forever()
"#;

impl Proxy {
    /// Starts it as `name` in front of `upstream` (`host:port`). `flip` is the offset of the byte to flip in every blob,
    /// `rate` the bytes per second to send of every blob; either is `None` to leave blobs alone.
    ///
    /// # Errors
    ///
    /// When `docker` fails or the proxy does not start.
    pub fn start(
        name: &str,
        upstream: &str,
        flip: Option<u64>,
        rate: Option<u64>,
    ) -> Result<Self, Failure> {
        let scratch = scratch(name)?;
        let script = scratch.join("proxy.py");
        std::fs::write(&script, PROXY_SCRIPT).map_err(|e| fail("write proxy.py", &e))?;
        let flip = flip.map_or_else(|| "-1".to_owned(), |f| f.to_string());
        let rate = rate.unwrap_or(0).to_string();
        let container = Container::start(
            name,
            PROXY_IMAGE,
            &[("UPSTREAM", upstream), ("FLIP", &flip), ("RATE", &rate)],
            &[(&script, "/proxy.py")],
            &["python", "-u", "/proxy.py"],
        )?;
        container.wait_for_log("serving")?;
        let _ = std::fs::remove_dir_all(&scratch);
        Ok(Self {
            container,
            name: name.to_owned(),
        })
    }

    /// The name a node pulls by.
    #[must_use]
    pub fn address(&self) -> String {
        self.name.clone()
    }

    /// How many blob requests went through.
    ///
    /// # Errors
    ///
    /// When `docker` cannot start.
    pub fn blob_requests(&self) -> Result<usize, Failure> {
        Ok(self
            .container
            .logs()?
            .lines()
            .filter(|l| l.starts_with("blob "))
            .count())
    }
}
