//! No credential and no token reaches a log, at the most verbose level (D37). This is a binary of its own because
//! `tracing` caches whether a call site is enabled, and only the first subscriber a binary sees decides it.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::convert::Infallible;
use std::io;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use secrecy::SecretString;
use speculaire_registry::{Client, Request};
use speculaire_runtime::registries::{Credentials, Endpoint};
use tokio::net::TcpListener;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Captured {
    type Writer = Self;

    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

#[tokio::test]
async fn a_bearer_flow_logs_neither_the_password_nor_the_token() {
    let captured = Captured::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(captured.clone())
            .finish(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(
                    move |request: http::Request<hyper::body::Incoming>| async move {
                        let mut response = http::Response::new(Full::new(Bytes::new()));
                        let authorization = request
                            .headers()
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default();
                        if request.uri().path() == "/token" {
                            *response.body_mut() = Full::new(Bytes::from_static(
                                br#"{"token":"tok-4f9e1c","expires_in":300}"#,
                            ));
                        } else if authorization != "Bearer tok-4f9e1c" {
                            *response.status_mut() = StatusCode::UNAUTHORIZED;
                            response.headers_mut().insert(
                                "www-authenticate",
                                format!(
                                    r#"Bearer realm="http://{}/token",service="s""#,
                                    request.headers()["host"].to_str().unwrap()
                                )
                                .parse()
                                .unwrap(),
                            );
                        }
                        Ok::<_, Infallible>(response)
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let endpoint = Endpoint::new(false, address.to_string());
    let credentials = Credentials::Login {
        username: "alice".to_owned(),
        password: SecretString::from("pw-7b2d90".to_owned()),
        identity_token: None,
    };
    let request = Request {
        method: Method::GET,
        path: "/a/manifests/1".to_owned(),
        repository: "a".to_owned(),
        headers: Vec::new(),
    };
    let response = Client::new()
        .send(&endpoint, &credentials, &request)
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode::OK);
    let log = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(
        log.contains("upstream request"),
        "the flow logged nothing: {log:?}"
    );
    // The base64 of `alice:pw-7b2d90`.
    for secret in ["pw-7b2d90", "tok-4f9e1c", "YWxpY2U6cHctN2IyZDkw"] {
        assert!(!log.contains(secret), "the log holds {secret}: {log}");
    }
    // The format of Debug for the credentials hides them too.
    let shown = format!("{credentials:?}");
    assert!(!shown.contains("pw-7b2d90"), "{shown}");
}
