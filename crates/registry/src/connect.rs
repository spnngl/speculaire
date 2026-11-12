//! Connections: TCP, then TLS with the trust of one endpoint.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use secrecy::ExposeSecret;
use speculaire_runtime::registries::Tls;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// How long a connection may take to open, TLS included.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Bytes that differ when two `Tls` would build different configs: the key of a client per trust.
pub(crate) fn fingerprint(tls: &Tls) -> Vec<u8> {
    let mut out = vec![u8::from(tls.skip_verify)];
    let mut part = |bytes: &[u8]| {
        out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(bytes);
    };
    for root in &tls.roots {
        part(root);
    }
    part(b"client");
    if let Some(client) = &tls.client {
        part(&client.certificate);
        part(client.key.expose_secret().as_bytes());
    }
    out
}

/// The rustls config of a trust. TLS 1.2 is allowed here, unlike on the mirror: registries that runtimes reach may
/// speak nothing newer (D88).
pub(crate) fn config(tls: &Tls) -> Result<ClientConfig, io::Error> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?;
    let builder = if tls.skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Unverified(provider)))
    } else {
        builder.with_root_certificates(root_store(tls)?)
    };
    let mut config = match &tls.client {
        None => builder.with_no_client_auth(),
        Some(client) => {
            let chain = CertificateDer::pem_slice_iter(&client.certificate)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| io::Error::other(format!("the client certificate: {e}")))?;
            let key = PrivateKeyDer::from_pem_slice(client.key.expose_secret().as_bytes())
                .map_err(|e| io::Error::other(format!("the client key: {e}")))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(io::Error::other)?
        }
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn root_store(tls: &Tls) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    // A node without a system store trusts the endpoint's own CA alone.
    let native = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(native.certs);
    for pem in &tls.roots {
        for certificate in CertificateDer::pem_slice_iter(pem) {
            let certificate =
                certificate.map_err(|e| io::Error::other(format!("a CA certificate: {e}")))?;
            roots.add(certificate).map_err(io::Error::other)?;
        }
    }
    Ok(roots)
}

/// The verifier of `insecure = true`: it accepts every certificate and checks only the signatures' form.
#[derive(Debug)]
struct Unverified(Arc<CryptoProvider>);

impl ServerCertVerifier for Unverified {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Opens a connection to the host of a URI, over TLS when its scheme is `https`.
#[derive(Clone)]
pub(crate) struct Connector {
    tls: TlsConnector,
}

impl Connector {
    pub(crate) fn new(config: ClientConfig) -> Self {
        Self {
            tls: TlsConnector::from(Arc::new(config)),
        }
    }
}

impl tower::Service<Uri> for Connector {
    type Response = Conn;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Conn>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let tls = self.tls.clone();
        Box::pin(async move {
            tokio::time::timeout(CONNECT_TIMEOUT, open(&tls, &uri))
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))
                })
        })
    }
}

async fn open(tls: &TlsConnector, uri: &Uri) -> io::Result<Conn> {
    let host = uri
        .host()
        .ok_or_else(|| io::Error::other("a URL without a host"))?;
    let https = uri.scheme_str() == Some("https");
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    // A URI keeps the brackets of an IPv6 literal; neither the resolver nor a certificate name has them.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let tcp = TcpStream::connect((host, port)).await?;
    tcp.set_nodelay(true)?;
    let stream = if https {
        let name = ServerName::try_from(host.to_owned()).map_err(io::Error::other)?;
        Stream::Tls(Box::new(tls.connect(name, tcp).await?))
    } else {
        Stream::Plain(tcp)
    };
    Ok(Conn(TokioIo::new(stream)))
}

/// A TCP stream, with TLS over it or not.
pub(crate) enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// What hyper's client holds: the stream, and that it is a connection hyper may reuse.
pub(crate) struct Conn(TokioIo<Stream>);

impl hyper::rt::Read for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Connection for Conn {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}
