//! Spike 04: a TLS mirror that requires a client certificate and serves blobs from a directory.
//!
//! `mirror-spike certs` writes ca.crt, server.crt, server.key and client.pem (certificate + key).
//! `mirror-spike serve` listens on 127.0.0.1:7480 (MIRROR_ADDR) and serves `blobs/<digest>` files.
//! Env: MIRROR_DIR (default /var/lib/speculaire/mirror), MIRROR_BLOBS (default <dir>/blobs).

use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use x509_parser::prelude::{FromDer, X509Certificate};

fn dir() -> PathBuf {
    PathBuf::from(std::env::var("MIRROR_DIR").unwrap_or_else(|_| "/var/lib/speculaire/mirror".into()))
}

fn write_private(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
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
    server.subject_alt_names = vec![SanType::IpAddress(IpAddr::from([127, 0, 0, 1]))];
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server.signed_by(&server_key, &ca_cert, &ca_key)?;

    let client_key = KeyPair::generate()?;
    let mut client = CertificateParams::new(vec![])?;
    client.distinguished_name.push(DnType::CommonName, "speculaire containerd");
    client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client.signed_by(&client_key, &ca_cert, &ca_key)?;

    std::fs::write(dir.join("ca.crt"), ca_cert.pem())?;
    std::fs::write(dir.join("server.crt"), server_cert.pem())?;
    write_private(&dir.join("server.key"), &server_key.serialize_pem())?;
    write_private(&dir.join("client.pem"), &format!("{}{}", client_cert.pem(), client_key.serialize_pem()))?;
    println!("wrote certificates in {}", dir.display());
    Ok(())
}

async fn serve() -> Result<()> {
    let dir = dir();
    let blobs = std::env::var("MIRROR_BLOBS").map(PathBuf::from).unwrap_or_else(|_| dir.join("blobs"));
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
    println!("serving on {addr}, blobs in {}", blobs.display());
    loop {
        let (tcp, from) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let blobs = blobs.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(tls) => {
                    if let Err(e) = connection(tls, &blobs).await {
                        println!("connection {from}: {e:#}");
                    }
                }
                Err(e) => println!("handshake {from} failed: {e}"),
            }
        });
    }
}

async fn connection(mut tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>, blobs: &Path) -> Result<()> {
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
        let blob = path.rsplit_once("/blobs/").map(|(_, d)| d.replace(':', "-")).filter(|d| !d.contains('/') && !d.contains(".."));
        let body = match (method, blob) {
            ("GET" | "HEAD", Some(name)) => tokio::fs::read(blobs.join(name)).await.ok(),
            _ => None,
        };
        let status = if body.is_some() { 200 } else { 404 };
        println!("{method} {target} subject=[{subject}] -> {status}");
        match body {
            Some(b) => {
                tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", b.len()).as_bytes()).await?;
                if method == "GET" {
                    tls.write_all(&b).await?;
                }
            }
            None => tls.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await?,
        }
    }
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
