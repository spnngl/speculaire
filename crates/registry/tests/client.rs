//! The client against registries that ask for what registries ask for: tokens, passwords, redirects and TLS.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use http::{HeaderName, HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use secrecy::SecretString;
use speculaire_registry::{Client, Error, Request};
use speculaire_runtime::registries::{ClientCert, Credentials, Endpoint, Tls};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// What a fake registry saw of one request.
#[derive(Clone, Debug)]
struct Seen {
    path: String,
    authorization: Option<String>,
    headers: HashMap<String, String>,
    form: String,
}

type Answer = Box<dyn Fn(&Seen) -> http::Response<Full<Bytes>> + Send + Sync>;

/// A server on a free port that answers by a closure and writes down every request.
struct Fake {
    address: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Fake {
    fn authority(&self) -> String {
        self.address.to_string()
    }

    fn paths(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.path.clone())
            .collect()
    }

    fn count(&self, prefix: &str) -> usize {
        self.paths()
            .iter()
            .filter(|p| p.starts_with(prefix))
            .count()
    }

    fn last(&self) -> Seen {
        self.seen.lock().unwrap().last().cloned().unwrap()
    }
}

fn respond(status: u16, headers: &[(&str, &str)], body: &str) -> http::Response<Full<Bytes>> {
    let mut response = http::Response::new(Full::new(Bytes::from(body.to_owned())));
    *response.status_mut() = StatusCode::from_u16(status).unwrap();
    for (name, value) in headers {
        response.headers_mut().insert(
            HeaderName::try_from(*name).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    response
}

async fn serve(tls: Option<Arc<ServerConfig>>, answer: Answer) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let answer = Arc::new(answer);
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (answer, log) = (Arc::clone(&answer), Arc::clone(&log));
            let acceptor = tls.clone().map(TlsAcceptor::from);
            tokio::spawn(async move {
                let service = service_fn(move |request: http::Request<Incoming>| {
                    let (answer, log) = (Arc::clone(&answer), Arc::clone(&log));
                    async move {
                        let (parts, body) = request.into_parts();
                        let form =
                            String::from_utf8_lossy(&body.collect().await.unwrap().to_bytes())
                                .into_owned();
                        let seen = Seen {
                            path: parts.uri.path_and_query().unwrap().to_string(),
                            authorization: parts
                                .headers
                                .get(AUTHORIZATION)
                                .map(|v| v.to_str().unwrap().to_owned()),
                            headers: parts
                                .headers
                                .iter()
                                .map(|(k, v)| {
                                    (k.to_string(), v.to_str().unwrap_or_default().to_owned())
                                })
                                .collect(),
                            form,
                        };
                        log.lock().unwrap().push(seen.clone());
                        Ok::<_, Infallible>(answer(&seen))
                    }
                });
                let mut builder = hyper::server::conn::http1::Builder::new();
                builder.timer(TokioTimer::new());
                match acceptor {
                    Some(acceptor) => {
                        let Ok(tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        let _ = builder.serve_connection(TokioIo::new(tls), service).await;
                    }
                    None => {
                        let _ = builder
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    }
                }
            });
        }
    });
    Fake { address, seen }
}

fn endpoint(fake: &Fake) -> Endpoint {
    Endpoint::new(false, fake.authority())
}

fn get(path: &str, repository: &str) -> Request {
    Request {
        method: Method::GET,
        path: path.to_owned(),
        repository: repository.to_owned(),
        headers: vec![(
            http::header::ACCEPT,
            HeaderValue::from_static("application/vnd.oci.image.index.v1+json"),
        )],
    }
}

fn alice() -> Credentials {
    Credentials::Login {
        username: "alice".to_owned(),
        password: SecretString::from("s3cret".to_owned()),
        identity_token: None,
    }
}

async fn text(response: speculaire_registry::Response) -> String {
    String::from_utf8(response.body.collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

#[tokio::test]
async fn a_plain_request_gets_its_answer_and_sends_its_headers() {
    let fake = serve(
        None,
        Box::new(|_| respond(200, &[("docker-content-digest", "sha256:x")], "hello")),
    )
    .await;
    let response = Client::new()
        .send(
            &endpoint(&fake),
            &Credentials::Anonymous,
            &get("/a/manifests/1", "a"),
        )
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.headers["docker-content-digest"], "sha256:x");
    assert_eq!(text(response).await, "hello");
    let seen = fake.last();
    assert_eq!(seen.path, "/v2/a/manifests/1");
    assert_eq!(
        seen.headers["accept"],
        "application/vnd.oci.image.index.v1+json"
    );
    assert_eq!(seen.authorization, None);
}

/// A registry whose token endpoint is on the same server, and that accepts the token `want`.
fn token_registry(want: &'static str, issued: Arc<Mutex<Vec<&'static str>>>) -> Answer {
    Box::new(move |seen| {
        if seen.path.starts_with("/token") {
            let tokens = issued.lock().unwrap();
            let token = tokens[(tokens.len().saturating_sub(1)).min(tokens.len() - 1)];
            return respond(
                200,
                &[],
                &format!(r#"{{"token":"{token}","expires_in":300}}"#),
            );
        }
        if seen.authorization.as_deref() == Some(&format!("Bearer {want}")) {
            return respond(200, &[], "manifest");
        }
        let host = seen.headers["host"].clone();
        respond(
            401,
            &[(
                WWW_AUTHENTICATE.as_str(),
                &format!(
                    r#"Bearer realm="http://{host}/token",service="registry.test",scope="repository:app/web:pull""#
                ),
            )],
            "",
        )
    })
}

#[tokio::test]
async fn a_bearer_challenge_is_answered_with_a_token_that_later_requests_reuse() {
    let issued = Arc::new(Mutex::new(vec!["tok1"]));
    let fake = serve(None, token_registry("tok1", issued)).await;
    let client = Client::new();
    for _ in 0..3 {
        let response = client
            .send(
                &endpoint(&fake),
                &alice(),
                &get("/app/web/manifests/1", "app/web"),
            )
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::OK);
    }
    // One 401, one token request with the password and the challenge's service and scope, then three authorised requests.
    assert_eq!(fake.count("/token"), 1);
    let paths = fake.paths();
    let token_request = paths.iter().find(|p| p.starts_with("/token")).unwrap();
    assert!(
        token_request.contains("service=registry%2Etest"),
        "{token_request}"
    );
    assert!(
        token_request.contains("scope=repository%3Aapp%2Fweb%3Apull"),
        "{token_request}"
    );
    let seen = fake.seen.lock().unwrap();
    let token_seen = seen.iter().find(|s| s.path.starts_with("/token")).unwrap();
    assert_eq!(
        token_seen.authorization.as_deref(),
        Some("Basic YWxpY2U6czNjcmV0")
    );
    assert_eq!(
        seen.iter()
            .filter(|s| s.authorization.as_deref() == Some("Bearer tok1"))
            .count(),
        3
    );
}

#[tokio::test]
async fn a_token_for_another_repository_is_asked_for_apart() {
    let issued = Arc::new(Mutex::new(vec!["tok1"]));
    let fake = serve(None, token_registry("tok1", issued)).await;
    let client = Client::new();
    for repository in ["app/web", "app/db"] {
        client
            .send(
                &endpoint(&fake),
                &alice(),
                &get("/x/manifests/1", repository),
            )
            .await
            .unwrap();
    }
    assert_eq!(fake.count("/token"), 2);
}

#[tokio::test]
async fn an_anonymous_client_asks_the_token_endpoint_without_a_password() {
    let issued = Arc::new(Mutex::new(vec!["tok1"]));
    let fake = serve(None, token_registry("tok1", issued)).await;
    let response = Client::new()
        .send(
            &endpoint(&fake),
            &Credentials::Anonymous,
            &get("/app/web/manifests/1", "app/web"),
        )
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode::OK);
    let seen = fake.seen.lock().unwrap();
    assert_eq!(
        seen.iter()
            .find(|s| s.path.starts_with("/token"))
            .unwrap()
            .authorization,
        None
    );
}

#[tokio::test]
async fn a_token_endpoint_that_redirects_to_another_host_does_not_pass_it_the_password() {
    let elsewhere = serve(None, Box::new(|_| respond(200, &[], r#"{"token":"tok1"}"#))).await;
    let to = format!("http://{}/token", elsewhere.authority());
    let auth = serve(
        None,
        Box::new(move |_| respond(307, &[("location", &to)], "")),
    )
    .await;
    let realm = format!(r#"Bearer realm="http://{}/token""#, auth.authority());
    let registry = serve(
        None,
        Box::new(move |seen| {
            if seen.authorization.as_deref() == Some("Bearer tok1") {
                respond(200, &[], "manifest")
            } else {
                respond(401, &[(WWW_AUTHENTICATE.as_str(), &realm)], "")
            }
        }),
    )
    .await;
    let response = Client::new()
        .send(
            &endpoint(&registry),
            &alice(),
            &get("/app/web/manifests/1", "app/web"),
        )
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        auth.last().authorization.as_deref(),
        Some("Basic YWxpY2U6czNjcmV0")
    );
    assert_eq!(elsewhere.last().authorization, None);
}

#[tokio::test]
async fn an_identity_token_is_traded_at_the_token_endpoint_by_a_form() {
    let issued = Arc::new(Mutex::new(vec!["tok1"]));
    let fake = serve(None, token_registry("tok1", issued)).await;
    let response = Client::new()
        .send(
            &endpoint(&fake),
            &Credentials::Login {
                username: "alice".to_owned(),
                password: SecretString::from("s3cret".to_owned()),
                identity_token: Some(SecretString::from("refresh me".to_owned())),
            },
            &get("/app/web/manifests/1", "app/web"),
        )
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode::OK);
    let seen = fake.seen.lock().unwrap();
    let token = seen.iter().find(|s| s.path.starts_with("/token")).unwrap();
    assert_eq!(token.path, "/token");
    assert_eq!(
        token.form,
        "grant_type=refresh_token&service=registry%2Etest&scope=repository%3Aapp%2Fweb%3Apull&client_id=speculaire&refresh_token=refresh%20me"
    );
}

#[tokio::test]
async fn a_token_the_registry_stops_accepting_is_replaced_once() {
    let issued = Arc::new(Mutex::new(vec!["old"]));
    let fake = serve(None, token_registry("new", Arc::clone(&issued))).await;
    let client = Client::new();
    let request = get("/app/web/manifests/1", "app/web");
    // The registry refuses the first token, and the 401 is the answer.
    let first = client
        .send(&endpoint(&fake), &alice(), &request)
        .await
        .unwrap();
    assert_eq!(first.status, StatusCode::UNAUTHORIZED);
    issued.lock().unwrap().push("new");
    // The held token is refused: it is forgotten, a new one is fetched, and the request goes through.
    let second = client
        .send(&endpoint(&fake), &alice(), &request)
        .await
        .unwrap();
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(fake.count("/token"), 2);
}

#[tokio::test]
async fn basic_credentials_answer_a_basic_challenge_and_an_anonymous_client_gets_the_401() {
    let fake = serve(
        None,
        Box::new(|seen| {
            if seen.authorization.as_deref() == Some("Basic YWxpY2U6czNjcmV0") {
                respond(200, &[], "ok")
            } else {
                respond(
                    401,
                    &[("www-authenticate", r#"Basic realm="registry""#)],
                    "",
                )
            }
        }),
    )
    .await;
    let client = Client::new();
    let request = get("/a/manifests/1", "a");
    assert_eq!(
        client
            .send(&endpoint(&fake), &alice(), &request)
            .await
            .unwrap()
            .status,
        StatusCode::OK
    );
    assert_eq!(
        client
            .send(&endpoint(&fake), &Credentials::Anonymous, &request)
            .await
            .unwrap()
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_challenge_nothing_answers_is_the_answer() {
    let fake = serve(
        None,
        Box::new(|_| respond(401, &[("www-authenticate", "Negotiate")], "")),
    )
    .await;
    let response = Client::new()
        .send(&endpoint(&fake), &alice(), &get("/a/manifests/1", "a"))
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(fake.paths().len(), 1);
    // A 404 is no challenge at all.
    let fake = serve(None, Box::new(|_| respond(404, &[], ""))).await;
    let response = Client::new()
        .send(&endpoint(&fake), &alice(), &get("/a/manifests/1", "a"))
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_token_endpoint_that_fails_or_a_realm_that_is_no_url_is_an_error() {
    let fake = serve(
        None,
        Box::new(|seen| {
            if seen.path.starts_with("/token") {
                respond(500, &[], "")
            } else {
                let host = seen.headers["host"].clone();
                respond(
                    401,
                    &[(
                        "www-authenticate",
                        &format!(r#"Bearer realm="http://{host}/token""#),
                    )],
                    "",
                )
            }
        }),
    )
    .await;
    let err = Client::new()
        .send(&endpoint(&fake), &alice(), &get("/a/manifests/1", "a"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Token { .. }), "{err}");
    assert!(err.to_string().contains("500"), "{err}");
    for header in [
        r#"Bearer service="x""#,
        r#"Bearer realm="/relative""#,
        r#"Bearer realm="ftp://host/token""#,
        r#"Bearer realm="not a url""#,
    ] {
        let fake = serve(
            None,
            Box::new(move |_| respond(401, &[("www-authenticate", header)], "")),
        )
        .await;
        let err = Client::new()
            .send(&endpoint(&fake), &alice(), &get("/a/manifests/1", "a"))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Token { .. }), "{header}: {err}");
    }
    // A token endpoint that answers 200 with no token.
    let fake = serve(
        None,
        Box::new(|seen| {
            if seen.path.starts_with("/token") {
                respond(200, &[], "{}")
            } else {
                let host = seen.headers["host"].clone();
                respond(
                    401,
                    &[(
                        "www-authenticate",
                        &format!(r#"Bearer realm="http://{host}/token""#),
                    )],
                    "",
                )
            }
        }),
    )
    .await;
    let err = Client::new()
        .send(&endpoint(&fake), &alice(), &get("/a/manifests/1", "a"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("holds no token"), "{err}");
}

#[tokio::test]
async fn redirects_are_followed_and_the_password_stays_with_the_registry() {
    // The CDN a blob redirects to, on another port: it must not see the registry's token.
    let cdn = serve(None, Box::new(|_| respond(200, &[], "from the cdn"))).await;
    let cdn_url = format!("http://{}/blob?sig=1", cdn.authority());
    let issued = Arc::new(Mutex::new(vec!["tok1"]));
    let registry_answer = token_registry("tok1", issued);
    let fake = serve(
        None,
        Box::new(move |seen| {
            if seen.path.starts_with("/v2/app/web/blobs/") {
                if seen.authorization.is_none() {
                    return registry_answer(seen);
                }
                return respond(307, &[("location", &cdn_url)], "");
            }
            if seen.path == "/v2/app/web/moved" {
                return respond(301, &[("location", "/v2/app/web/manifests/1")], "");
            }
            registry_answer(seen)
        }),
    )
    .await;
    let client = Client::new();
    let response = client
        .send(
            &endpoint(&fake),
            &alice(),
            &get("/app/web/blobs/sha256:x", "app/web"),
        )
        .await
        .unwrap();
    assert_eq!(text(response).await, "from the cdn");
    let cdn_seen = cdn.last();
    assert_eq!(cdn_seen.path, "/blob?sig=1");
    assert_eq!(
        cdn_seen.authorization, None,
        "the token went to another host"
    );
    assert_eq!(
        cdn_seen.headers["accept"],
        "application/vnd.oci.image.index.v1+json"
    );
    // A redirect to a path on the same host keeps the token.
    let response = client
        .send(
            &endpoint(&fake),
            &alice(),
            &get("/app/web/moved", "app/web"),
        )
        .await
        .unwrap();
    assert_eq!(text(response).await, "manifest");
}

#[tokio::test]
async fn a_loop_of_redirects_is_an_error() {
    let fake = serve(
        None,
        Box::new(|_| respond(302, &[("location", "/v2/loop")], "")),
    )
    .await;
    let err = Client::new()
        .send(
            &endpoint(&fake),
            &Credentials::Anonymous,
            &get("/loop", "a"),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("more than 5 redirects"), "{err}");
    assert_eq!(fake.paths().len(), 6);
}

#[tokio::test]
async fn an_endpoint_that_is_down_is_an_error_naming_it() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let endpoint = Endpoint::new(false, address.to_string());
    let err = Client::new()
        .send(&endpoint, &Credentials::Anonymous, &get("/", "a"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Request { .. }), "{err}");
    assert!(err.to_string().contains(&address.to_string()), "{err}");
}

// ---- TLS ----

struct Pki {
    ca_pem: String,
    server: Arc<ServerConfig>,
    client: ClientCert,
}

/// A CA, a server certificate for 127.0.0.1 and a client certificate, and a server config that asks for a client
/// certificate when `require_client` is set.
fn pki(require_client: bool, versions: &[&'static rustls::SupportedProtocolVersion]) -> Pki {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let leaf = |names: Vec<String>, usage: rcgen::ExtendedKeyUsagePurpose| {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(names).unwrap();
        params.extended_key_usages = vec![usage];
        let cert = params.signed_by(&key, &issuer).unwrap();
        (cert, key)
    };
    let (server_cert, server_key) = leaf(
        vec!["127.0.0.1".to_owned()],
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    );
    let (client_cert, client_key) = leaf(
        vec!["client".to_owned()],
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    );
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)
        .unwrap();
    let builder = if require_client {
        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        builder.with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .unwrap(),
        )
    } else {
        builder.with_no_client_auth()
    };
    let server = builder
        .with_single_cert(
            vec![server_cert.der().clone()],
            PrivateKeyDer::from_pem_slice(server_key.serialize_pem().as_bytes()).unwrap(),
        )
        .unwrap();
    // The client's chain is its certificate, as a PEM file of `certs.d` holds it.
    let _ = CertificateDer::pem_slice_iter(client_cert.pem().as_bytes()).count();
    Pki {
        ca_pem: ca.pem(),
        server: Arc::new(server),
        client: ClientCert {
            certificate: client_cert.pem().into_bytes(),
            key: SecretString::from(client_key.serialize_pem()),
        },
    }
}

#[tokio::test]
async fn the_root_the_namespace_and_the_headers_of_an_endpoint_shape_the_request() {
    let cdn = serve(None, Box::new(|_| respond(200, &[], "from the cdn"))).await;
    let cdn_url = format!("http://{}/blob", cdn.authority());
    let fake = serve(
        None,
        Box::new(move |seen| {
            if seen.path.starts_with("/hub/v2/a/blobs/") {
                return respond(307, &[("location", &cdn_url)], "");
            }
            respond(200, &[], "manifest")
        }),
    )
    .await;
    let endpoint = Endpoint {
        root: "/hub/v2".to_owned(),
        namespace: Some("localhost:5000".to_owned()),
        headers: vec![("X-Team".to_owned(), SecretString::from("infra".to_owned()))],
        ..Endpoint::new(false, fake.authority())
    };
    let client = Client::new();
    let response = client
        .send(
            &endpoint,
            &Credentials::Anonymous,
            &get("/a/manifests/1", "a"),
        )
        .await
        .unwrap();
    assert_eq!(text(response).await, "manifest");
    let seen = fake.last();
    assert_eq!(seen.path, "/hub/v2/a/manifests/1?ns=localhost%3A5000");
    assert_eq!(seen.headers["x-team"], "infra");
    // A query already there is extended, and a host named by a redirect gets none of the endpoint's headers.
    let response = client
        .send(
            &endpoint,
            &Credentials::Anonymous,
            &get("/a/blobs/sha256:x?from=1", "a"),
        )
        .await
        .unwrap();
    assert_eq!(text(response).await, "from the cdn");
    assert_eq!(
        fake.last().path,
        "/hub/v2/a/blobs/sha256:x?from=1&ns=localhost%3A5000"
    );
    let seen = cdn.last();
    assert!(!seen.headers.contains_key("x-team"), "{seen:?}");
    // A header name that is none is an error, not a panic.
    let bad = Endpoint {
        headers: vec![("not a name".to_owned(), SecretString::from("v".to_owned()))],
        ..Endpoint::new(false, fake.authority())
    };
    let err = client
        .send(&bad, &Credentials::Anonymous, &get("/a/manifests/1", "a"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Request { .. }), "{err}");
}

fn tls_endpoint(fake: &Fake, tls: Tls) -> Endpoint {
    Endpoint {
        tls,
        ..Endpoint::new(true, fake.authority())
    }
}

#[tokio::test]
async fn an_endpoint_is_trusted_by_its_ca_or_not_at_all_unless_it_is_insecure() {
    let pki = pki(false, &[&rustls::version::TLS13]);
    let fake = serve(
        Some(Arc::clone(&pki.server)),
        Box::new(|_| respond(200, &[], "secure")),
    )
    .await;
    let client = Client::new();
    let request = get("/", "a");
    let none = tls_endpoint(&fake, Tls::default());
    let err = client
        .send(&none, &Credentials::Anonymous, &request)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Request { .. }), "{err}");
    let trusted = tls_endpoint(
        &fake,
        Tls {
            roots: vec![pki.ca_pem.clone().into_bytes()],
            ..Tls::default()
        },
    );
    assert_eq!(
        text(
            client
                .send(&trusted, &Credentials::Anonymous, &request)
                .await
                .unwrap()
        )
        .await,
        "secure"
    );
    let insecure = tls_endpoint(
        &fake,
        Tls {
            skip_verify: true,
            ..Tls::default()
        },
    );
    assert_eq!(
        text(
            client
                .send(&insecure, &Credentials::Anonymous, &request)
                .await
                .unwrap()
        )
        .await,
        "secure"
    );
    // A CA that is no PEM is an error of the endpoint's setup, not a silent distrust.
    let broken = tls_endpoint(
        &fake,
        Tls {
            roots: vec![
                b"-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n".to_vec(),
            ],
            ..Tls::default()
        },
    );
    let err = client
        .send(&broken, &Credentials::Anonymous, &request)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Tls { .. }), "{err}");
}

#[tokio::test]
async fn a_registry_that_wants_a_client_certificate_gets_the_one_of_the_endpoint() {
    let pki = pki(true, &[&rustls::version::TLS13]);
    let fake = serve(
        Some(Arc::clone(&pki.server)),
        Box::new(|_| respond(200, &[], "mutual")),
    )
    .await;
    let client = Client::new();
    let request = get("/", "a");
    let without = tls_endpoint(
        &fake,
        Tls {
            roots: vec![pki.ca_pem.clone().into_bytes()],
            ..Tls::default()
        },
    );
    assert!(
        client
            .send(&without, &Credentials::Anonymous, &request)
            .await
            .is_err()
    );
    let with = tls_endpoint(
        &fake,
        Tls {
            roots: vec![pki.ca_pem.clone().into_bytes()],
            client: Some(pki.client.clone()),
            skip_verify: false,
        },
    );
    assert_eq!(
        text(
            client
                .send(&with, &Credentials::Anonymous, &request)
                .await
                .unwrap()
        )
        .await,
        "mutual"
    );
    // A key that is no key is an error of the endpoint's setup.
    let broken = tls_endpoint(
        &fake,
        Tls {
            roots: vec![pki.ca_pem.into_bytes()],
            client: Some(ClientCert {
                certificate: pki.client.certificate,
                key: SecretString::from("no key".to_owned()),
            }),
            skip_verify: false,
        },
    );
    let err = client
        .send(&broken, &Credentials::Anonymous, &request)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Tls { .. }), "{err}");
}

#[tokio::test]
async fn a_registry_that_speaks_tls_1_2_only_is_reached() {
    let pki = pki(false, &[&rustls::version::TLS12]);
    let fake = serve(
        Some(Arc::clone(&pki.server)),
        Box::new(|_| respond(200, &[], "old")),
    )
    .await;
    let endpoint = tls_endpoint(
        &fake,
        Tls {
            roots: vec![pki.ca_pem.into_bytes()],
            ..Tls::default()
        },
    );
    let response = Client::new()
        .send(&endpoint, &Credentials::Anonymous, &get("/", "a"))
        .await
        .unwrap();
    assert_eq!(text(response).await, "old");
}

#[tokio::test]
async fn a_plain_http_endpoint_is_reached_again_and_again() {
    let fake = serve(None, Box::new(|_| respond(200, &[], "plain"))).await;
    let client = Client::new();
    for _ in 0..3 {
        let response = client
            .send(&endpoint(&fake), &Credentials::Anonymous, &get("/", "a"))
            .await
            .unwrap();
        assert_eq!(text(response).await, "plain");
    }
    assert_eq!(fake.paths().len(), 3);
}
