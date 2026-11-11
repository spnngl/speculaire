//! Spikes 04, CRI-O 03 and CRI-O 04: a TLS mirror that requires a client certificate.
//!
//! `mirror-spike certs` writes ca.crt, server.crt, server.key, client.pem (certificate + key, containerd)
//! and client.cert + client.key (CRI-O).
//! `mirror-spike serve` listens on 127.0.0.1:7480 (MIRROR_ADDR) and serves `blobs/<digest>` and
//! `manifests/<digest or tag>` files; a manifest file `<name>` has its media type in `<name>.type`.
//! Env: MIRROR_DIR (default /var/lib/speculaire/mirror), MIRROR_BLOBS (default <dir>/blobs),
//! MIRROR_MANIFESTS (default <dir>/manifests), MIRROR_CHALLENGE=1 answers 401 with a Basic
//! challenge to requests without an Authorization header.
//! MIRROR_PROXY=1 answers a miss from MIRROR_UPSTREAM (default https://registry-1.docker.io, whose paths
//! drop the leading registry host; another mirror keeps them) with the anonymous Bearer flow, streams it,
//! and keeps it in the store if its digest matches. MIRROR_UPSTREAM_CA and MIRROR_UPSTREAM_CLIENT
//! (combined PEM) authenticate to another mirror. MIRROR_CORRUPT=1 flips one byte of each proxied blob.

use std::collections::HashMap;
use std::io::Write as _;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use x509_parser::prelude::{FromDer, X509Certificate};

type Tls = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

const MANIFEST_TYPES: &str = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";

fn dir() -> PathBuf {
    PathBuf::from(std::env::var("MIRROR_DIR").unwrap_or_else(|_| "/var/lib/speculaire/mirror".into()))
}

fn flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| v == "1")
}

fn write_private(path: &Path, contents: &str) -> Result<()> {
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

fn certs() -> Result<()> {
    let dir = dir();
    std::fs::create_dir_all(&dir)?;
    let ca_key = KeyPair::generate()?;
    let mut ca = CertificateParams::new(vec![])?;
    ca.distinguished_name.push(DnType::CommonName, "speculaire mirror ca");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_cert = ca.self_signed(&ca_key)?;

    let server_key = KeyPair::generate()?;
    let mut server = CertificateParams::new(vec![])?;
    server.distinguished_name.push(DnType::CommonName, "speculaire mirror");
    let mut sans = vec![SanType::IpAddress(IpAddr::from([127, 0, 0, 1]))];
    // CRI-O spike 04 chains a second node's mirror to this one over the node network.
    if let Ok(ip) = std::env::var("MIRROR_SERVER_IP") {
        sans.push(SanType::IpAddress(ip.parse().context("MIRROR_SERVER_IP")?));
    }
    server.subject_alt_names = sans;
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server.signed_by(&server_key, &ca_cert, &ca_key)?;

    let client_key = KeyPair::generate()?;
    let mut client = CertificateParams::new(vec![])?;
    client.distinguished_name.push(DnType::CommonName, "speculaire runtime");
    client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client.signed_by(&client_key, &ca_cert, &ca_key)?;

    std::fs::write(dir.join("ca.crt"), ca_cert.pem())?;
    std::fs::write(dir.join("server.crt"), server_cert.pem())?;
    write_private(&dir.join("server.key"), &server_key.serialize_pem())?;
    write_private(&dir.join("client.pem"), &format!("{}{}", client_cert.pem(), client_key.serialize_pem()))?;
    std::fs::write(dir.join("client.cert"), client_cert.pem())?;
    write_private(&dir.join("client.key"), &client_key.serialize_pem())?;
    println!("wrote certificates in {}", dir.display());
    Ok(())
}

/// Where a proxied miss is fetched from.
struct Upstream {
    client: reqwest::Client,
    base: String,
    /// Docker Hub paths have no registry host segment; another mirror's do.
    strip_host: bool,
    corrupt: bool,
    /// Bearer tokens by repository.
    tokens: Mutex<HashMap<String, String>>,
}

impl Upstream {
    fn from_env() -> Result<Self> {
        let base = std::env::var("MIRROR_UPSTREAM").unwrap_or_else(|_| "https://registry-1.docker.io".into());
        let mut builder = reqwest::Client::builder();
        if let Ok(ca) = std::env::var("MIRROR_UPSTREAM_CA") {
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(ca)?)?);
        }
        if let Ok(client) = std::env::var("MIRROR_UPSTREAM_CLIENT") {
            builder = builder.identity(reqwest::Identity::from_pem(&std::fs::read(client)?)?);
        }
        Ok(Self {
            client: builder.build()?,
            strip_host: base.contains("registry-1.docker.io"),
            base,
            corrupt: flag("MIRROR_CORRUPT"),
            tokens: Mutex::new(HashMap::new()),
        })
    }

    /// The upstream URL and repository for a mirror path `/v2/<host>/<repo>/(manifests|blobs)/<ref>`.
    fn locate(&self, path: &str) -> Option<(String, String)> {
        let rest = path.strip_prefix("/v2/")?;
        let (_, repo_and_ref) = rest.split_once('/')?;
        let repo = repo_and_ref.rsplit_once("/manifests/").or_else(|| repo_and_ref.rsplit_once("/blobs/"))?.0.to_owned();
        let upstream_path = if self.strip_host { format!("/v2/{repo_and_ref}") } else { path.to_owned() };
        Some((format!("{}{upstream_path}", self.base), repo))
    }

    async fn get(&self, url: &str, repo: &str, accept: Option<&str>) -> Result<reqwest::Response> {
        for attempt in 0..2 {
            let mut req = self.client.get(url);
            if let Some(a) = accept {
                req = req.header(reqwest::header::ACCEPT, a);
            }
            if let Some(t) = self.tokens.lock().await.get(repo) {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await?;
            if resp.status() != reqwest::StatusCode::UNAUTHORIZED || attempt == 1 {
                return Ok(resp);
            }
            let challenge = resp.headers().get(reqwest::header::WWW_AUTHENTICATE).and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
            let token = self.token(&challenge).await?;
            self.tokens.lock().await.insert(repo.to_owned(), token);
        }
        unreachable!("the loop returns on its second attempt")
    }

    /// The anonymous Bearer flow: `Bearer realm="…",service="…",scope="…"`.
    async fn token(&self, challenge: &str) -> Result<String> {
        let params = challenge.strip_prefix("Bearer ").context("not a Bearer challenge")?;
        let field = |k: &str| params.split(',').find_map(|p| p.trim().strip_prefix(&format!("{k}=\"")).map(|v| v.trim_end_matches('"').to_owned()));
        let realm = field("realm").context("no realm")?;
        // Docker Hub's service and scope values need no percent-encoding beyond ':' and '/', which a query allows.
        let query: Vec<String> = ["service", "scope"].into_iter().filter_map(|k| field(k).map(|v| format!("{k}={v}"))).collect();
        let bytes = self.client.get(format!("{realm}?{}", query.join("&"))).send().await?.bytes().await?;
        let body: serde_json::Value = serde_json::from_slice(&bytes)?;
        body.get("token").or_else(|| body.get("access_token")).and_then(|t| t.as_str()).map(str::to_owned).context("no token")
    }
}

struct Store {
    blobs: PathBuf,
    manifests: PathBuf,
    challenge: bool,
    upstream: Option<Upstream>,
}

/// A file name for a digest or tag taken from a request path, or None if it could escape the directory.
fn file_name(reference: &str) -> Option<String> {
    let name = reference.replace(':', "-");
    (!name.is_empty() && !name.contains('/') && !name.contains("..") && !name.ends_with(".type") && !name.ends_with(".part")).then_some(name)
}

/// The file, media type and reference a request path names, if the store holds it.
fn lookup(store: &Store, path: &str) -> Option<(PathBuf, String, String)> {
    if let Some((_, d)) = path.rsplit_once("/blobs/") {
        let n = file_name(d)?;
        let file = store.blobs.join(n);
        return file.exists().then(|| (file, "application/octet-stream".to_owned(), d.to_owned()));
    }
    let (_, r) = path.rsplit_once("/manifests/")?;
    let n = file_name(r)?;
    let media = std::fs::read_to_string(store.manifests.join(format!("{n}.type"))).ok()?;
    Some((store.manifests.join(n), media.trim().to_owned(), r.to_owned()))
}

async fn serve() -> Result<()> {
    let dir = dir();
    let blobs = std::env::var("MIRROR_BLOBS").map(PathBuf::from).unwrap_or_else(|_| dir.join("blobs"));
    let manifests = std::env::var("MIRROR_MANIFESTS").map(PathBuf::from).unwrap_or_else(|_| dir.join("manifests"));
    std::fs::create_dir_all(&blobs)?;
    std::fs::create_dir_all(&manifests)?;
    let challenge = flag("MIRROR_CHALLENGE");
    let upstream = if flag("MIRROR_PROXY") { Some(Upstream::from_env()?) } else { None };
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(dir.join("ca.crt"))? {
        roots.add(c?)?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider)).build()?;
    let chain = CertificateDer::pem_file_iter(dir.join("server.crt"))?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(dir.join("server.key"))?;
    let config = ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions()?.with_client_cert_verifier(verifier).with_single_cert(chain, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let addr = std::env::var("MIRROR_ADDR").unwrap_or_else(|_| "127.0.0.1:7480".into());
    let listener = TcpListener::bind(&addr).await?;
    let proxy = upstream.as_ref().map_or("off".to_owned(), |u| format!("{} corrupt={}", u.base, u.corrupt));
    println!("serving on {addr}, blobs in {}, manifests in {}, challenge {challenge}, proxy {proxy}", blobs.display(), manifests.display());
    let store = Arc::new(Store { blobs, manifests, challenge, upstream });
    loop {
        let (tcp, from) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(tls) => {
                    if let Err(e) = connection(tls, &store).await {
                        println!("connection {from}: {e:#}");
                    }
                }
                Err(e) => println!("handshake {from} failed: {e}"),
            }
        });
    }
}

async fn connection(mut tls: Tls, store: &Store) -> Result<()> {
    let subject = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .and_then(|c| X509Certificate::from_der(c).ok())
        .map(|(_, c)| c.subject().to_string())
        .unwrap_or_default();
    let mut buf = Vec::new();
    loop {
        let head_end = loop {
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p + 4;
            }
            let mut chunk = [0u8; 4096];
            let n = tls.read(&mut chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > 65536 {
                bail!("request head too large");
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        buf.drain(..head_end);
        let mut parts = head.lines().next().unwrap_or_default().split(' ');
        let (method, target) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
        let path = target.split('?').next().unwrap_or_default();
        let header = |name: &str| head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_owned()));
        // Only the scheme is logged, never the credentials.
        let auth = header("authorization").map_or("none".to_owned(), |v| v.split(' ').next().unwrap_or("?").to_owned());
        if store.challenge && auth == "none" {
            println!("{method} {target} subject=[{subject}] auth=none -> 401");
            tls.write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"speculaire\"\r\nContent-Length: 0\r\n\r\n").await?;
            continue;
        }
        // c/image pings `/v2/` before it uses an endpoint; containerd does not.
        if path == "/v2/" || path == "/v2" {
            println!("{method} {target} subject=[{subject}] auth={auth} -> 200");
            tls.write_all(b"HTTP/1.1 200 OK\r\nDocker-Distribution-API-Version: registry/2.0\r\nContent-Length: 0\r\n\r\n").await?;
            continue;
        }
        let found = match method {
            "GET" | "HEAD" => lookup(store, path),
            _ => None,
        };
        let body = match found {
            Some((file, media, reference)) => tokio::fs::read(file).await.ok().map(|b| (b, media, reference)),
            None => None,
        };
        match (body, &store.upstream) {
            (Some((b, media, reference)), _) => {
                println!("{method} {target} subject=[{subject}] auth={auth} -> 200");
                respond(&mut tls, method, &media, &reference, &b).await?;
            }
            (None, Some(upstream)) if matches!(method, "GET" | "HEAD") => {
                let accept = header("accept");
                let status = proxy(&mut tls, store, upstream, method, path, accept.as_deref()).await?;
                println!("{method} {target} subject=[{subject}] auth={auth} -> {status}");
            }
            (None, _) => {
                println!("{method} {target} subject=[{subject}] auth={auth} -> 404");
                tls.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await?;
            }
        }
    }
}

async fn respond(tls: &mut Tls, method: &str, media: &str, reference: &str, body: &[u8]) -> Result<()> {
    let digest = if reference.starts_with("sha256:") { format!("Docker-Content-Digest: {reference}\r\n") } else { String::new() };
    tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {media}\r\n{digest}Content-Length: {}\r\n\r\n", body.len()).as_bytes()).await?;
    if method == "GET" {
        tls.write_all(body).await?;
    }
    Ok(())
}

/// Answers a miss from upstream; returns the status logged. A blob streams to the client and to a
/// `.part` file at once; the last chunk is held back until the digest matches, so a wrong blob never
/// reaches the client whole, and the file is kept only on a match.
async fn proxy(tls: &mut Tls, store: &Store, upstream: &Upstream, method: &str, path: &str, accept: Option<&str>) -> Result<String> {
    let Some((url, repo)) = upstream.locate(path) else {
        tls.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await?;
        return Ok("404 (not a registry path)".into());
    };
    if let Some((_, reference)) = path.rsplit_once("/manifests/") {
        let resp = upstream.get(&url, &repo, Some(accept.unwrap_or(MANIFEST_TYPES))).await?;
        if !resp.status().is_success() {
            tls.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await?;
            return Ok(format!("404 (upstream {})", resp.status()));
        }
        let media = resp.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("application/octet-stream").to_owned();
        let body = resp.bytes().await?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&body)));
        if reference.starts_with("sha256:") && reference != digest {
            tls.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await?;
            return Ok(format!("404 (upstream manifest is {digest})"));
        }
        for name in [reference, digest.as_str()].into_iter().filter_map(file_name) {
            tokio::fs::write(store.manifests.join(&name), &body).await?;
            tokio::fs::write(store.manifests.join(format!("{name}.type")), &media).await?;
        }
        respond(tls, method, &media, &digest, &body).await?;
        return Ok(format!("200 (proxied manifest {})", &digest[..19]));
    }
    let Some(digest) = path.rsplit_once("/blobs/").map(|(_, d)| d.to_owned()) else {
        tls.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await?;
        return Ok("404".into());
    };
    let name = file_name(&digest).context("bad digest")?;
    let resp = upstream.get(&url, &repo, None).await?;
    let Some(len) = resp.content_length().filter(|_| resp.status().is_success()) else {
        tls.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await?;
        return Ok(format!("404 (upstream {})", resp.status()));
    };
    tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nDocker-Content-Digest: {digest}\r\nContent-Length: {len}\r\n\r\n").as_bytes()).await?;
    if method == "HEAD" {
        return Ok("200 (HEAD)".into());
    }
    let part = store.blobs.join(format!("{name}.part"));
    let mut file = tokio::fs::File::create(&part).await?;
    let mut hasher = Sha256::new();
    let mut held: Option<bytes::Bytes> = None;
    let mut stream = resp.bytes_stream();
    let mut corrupt = upstream.corrupt;
    while let Some(chunk) = stream.next().await {
        let mut chunk = chunk?;
        if corrupt && !chunk.is_empty() {
            let mut bad = chunk.to_vec();
            bad[0] ^= 0xff;
            chunk = bytes::Bytes::from(bad);
            corrupt = false;
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
        if let Some(prev) = held.replace(chunk) {
            tls.write_all(&prev).await?;
        }
    }
    file.flush().await?;
    let got = format!("sha256:{}", hex::encode(hasher.finalize()));
    if got != digest {
        tokio::fs::remove_file(&part).await?;
        // Closing without the last chunk: the client sees a short body, never a whole wrong blob.
        bail!("blob {digest}: got {got}; not kept, last chunk withheld, connection closed");
    }
    if let Some(last) = held {
        tls.write_all(&last).await?;
    }
    tokio::fs::rename(&part, store.blobs.join(&name)).await?;
    Ok(format!("200 (proxied {len} bytes, kept)"))
}

#[tokio::main]
async fn main() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("certs") => certs(),
        Some("serve") => serve().await,
        _ => bail!("usage: mirror-spike certs | serve"),
    }
    .context("mirror-spike")
}
