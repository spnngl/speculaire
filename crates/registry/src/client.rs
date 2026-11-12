//! Sending a request to an endpoint, with the authentication a registry asks for.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE, LOCATION, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Incoming;
use hyper_util::client::legacy::Client as Hyper;
use hyper_util::rt::TokioExecutor;
use secrecy::{ExposeSecret, SecretString};
use speculaire_runtime::registries::{Credentials, Endpoint};
use tracing::debug;

use crate::challenge::{self, Challenge};
use crate::connect::{self, Connector};
use crate::token::{self, Key, Tokens};

/// How many redirects a request follows.
const MAX_REDIRECTS: usize = 5;

/// How long a registry may take to answer a request with its headers.
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest answer of a token endpoint that is read.
const MAX_TOKEN_ANSWER: usize = 1 << 20;

/// `client_id` of the token requests that carry an identity token.
const CLIENT_ID: &str = "speculaire";

/// What a query value keeps unescaped: Go's `url.QueryEscape` leaves these (and alphanumerics) alone.
const QUERY_VALUE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

type HyperClient = Hyper<Connector, Full<Bytes>>;

/// What to ask: `GET` or `HEAD` of a path of the registry's API.
#[derive(Clone, Debug)]
pub struct Request {
    /// `GET` or `HEAD`.
    pub method: Method,
    /// The path and query below the endpoint's API root, such as `/library/busybox/manifests/1.37`.
    pub path: String,
    /// The repository the request is about, for the scope of a token: `library/busybox`.
    pub repository: String,
    /// Headers to send, such as `Accept` and `Range`.
    pub headers: Vec<(HeaderName, HeaderValue)>,
}

/// What a registry answered: the status and headers, and the body still to be read.
#[derive(Debug)]
pub struct Response {
    /// The status.
    pub status: StatusCode,
    /// The headers.
    pub headers: HeaderMap,
    /// The body.
    pub body: Incoming,
}

/// Why a request could not be answered.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The trust of the endpoint cannot be built.
    #[error("cannot set up TLS for {authority}: {source}")]
    Tls {
        /// The endpoint.
        authority: String,
        /// Why.
        source: std::io::Error,
    },
    /// The request could not be made or answered.
    #[error("{authority}: {message}")]
    Request {
        /// The endpoint.
        authority: String,
        /// Why.
        message: String,
    },
    /// The registry asked for a token and the token endpoint did not give one.
    #[error("{authority}: no token: {message}")]
    Token {
        /// The endpoint.
        authority: String,
        /// Why.
        message: String,
    },
}

/// The client: connections kept by trust, and the tokens in use.
#[derive(Default)]
pub struct Client {
    clients: Mutex<HashMap<Vec<u8>, HyperClient>>,
    tokens: Tokens,
}

impl Client {
    /// A client with no connection and no token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks the endpoint. A 401 with a Bearer challenge is answered with a token, a 401 with a Basic challenge with
    /// the credentials, and the request is repeated once; other statuses, 401 included when nothing can answer it,
    /// are the answer. Redirects are followed, and the credentials go only to the endpoint's own host.
    ///
    /// # Errors
    ///
    /// When the endpoint cannot be reached or trusted, does not answer in time, or refuses to give a token.
    pub async fn send(
        &self,
        endpoint: &Endpoint,
        credentials: &Credentials,
        request: &Request,
    ) -> Result<Response, Error> {
        let client = self.hyper(endpoint)?;
        let key = Key {
            authority: endpoint.authority.clone(),
            scope: format!("repository:{}:pull", request.repository),
        };
        let mut authorization = self
            .tokens
            .get(&key, Instant::now())
            .map(|token| bearer(&token));
        let mut retried = false;
        loop {
            let response = follow(&client, endpoint, request, authorization.as_ref()).await?;
            if response.status != StatusCode::UNAUTHORIZED || retried {
                return Ok(response);
            }
            retried = true;
            if authorization.is_some() {
                // The registry stopped accepting a token we thought good: ask for another.
                self.tokens.forget(&key);
            }
            let challenges = challenges_of(&response.headers);
            let Some(answer) = self
                .answer(&client, endpoint, credentials, &challenges, &key)
                .await?
            else {
                // Nothing to answer with: the 401 is the answer.
                return Ok(response);
            };
            authorization = Some(answer);
        }
    }

    /// The `Authorization` that answers the challenges, if the credentials or a token endpoint can.
    async fn answer(
        &self,
        client: &HyperClient,
        endpoint: &Endpoint,
        credentials: &Credentials,
        challenges: &[Challenge],
        key: &Key,
    ) -> Result<Option<HeaderValue>, Error> {
        if let Some(challenge) = challenges.iter().find(|c| c.scheme == "bearer") {
            return self
                .fetch_token(client, endpoint, credentials, challenge, key)
                .await
                .map(Some);
        }
        if challenges.iter().any(|c| c.scheme == "basic")
            && let Credentials::Login {
                username, password, ..
            } = credentials
        {
            return Ok(Some(basic(username, password)));
        }
        Ok(None)
    }

    async fn fetch_token(
        &self,
        client: &HyperClient,
        endpoint: &Endpoint,
        credentials: &Credentials,
        challenge: &Challenge,
        key: &Key,
    ) -> Result<HeaderValue, Error> {
        let failed = |message: String| Error::Token {
            authority: endpoint.authority.clone(),
            message,
        };
        let realm = challenge
            .param("realm")
            .ok_or_else(|| failed("the challenge names no realm".to_owned()))?;
        let realm: Uri = realm
            .parse()
            .map_err(|_| failed("the realm is no URL".to_owned()))?;
        let (Some(scheme), Some(realm_authority)) = (realm.scheme_str(), realm.authority()) else {
            return Err(failed("the realm is no absolute URL".to_owned()));
        };
        if scheme != "https" && scheme != "http" {
            return Err(failed(format!("the realm has the scheme {scheme}")));
        }
        let service = challenge.param("service").unwrap_or_default();
        let scope = challenge.param("scope").unwrap_or(&key.scope);
        let query = token::query(service, scope);
        // The password goes as the authorization, which a redirect to another host does not get.
        let (method, body, headers, authorization) = match credentials {
            Credentials::Login {
                identity_token: Some(identity),
                ..
            } => {
                let form = |text: &str| {
                    percent_encoding::utf8_percent_encode(text, percent_encoding::NON_ALPHANUMERIC)
                        .to_string()
                };
                let body = format!(
                    "grant_type=refresh_token&service={}&scope={}&client_id={CLIENT_ID}&refresh_token={}",
                    form(service),
                    form(scope),
                    form(identity.expose_secret())
                );
                (
                    Method::POST,
                    Bytes::from(body),
                    vec![(
                        CONTENT_TYPE,
                        HeaderValue::from_static("application/x-www-form-urlencoded"),
                    )],
                    None,
                )
            }
            Credentials::Login {
                username, password, ..
            } => (
                Method::GET,
                Bytes::new(),
                Vec::new(),
                Some(basic(username, password)),
            ),
            Credentials::Anonymous => (Method::GET, Bytes::new(), Vec::new(), None),
        };
        // A form carries the query's fields in its body.
        let ours = if method == Method::GET {
            query.as_str()
        } else {
            ""
        };
        let uri =
            with_query(&realm, ours).ok_or_else(|| failed("the realm is no URL".to_owned()))?;
        let realm_endpoint = Endpoint {
            tls: endpoint.tls.clone(),
            ..Endpoint::new(scheme == "https", realm_authority.to_string())
        };
        let response = follow_uri(
            client,
            &realm_endpoint,
            &method,
            uri,
            &headers,
            body,
            authorization.as_ref(),
        )
        .await?;
        let status = response.status;
        let body = Limited::new(response.body, MAX_TOKEN_ANSWER)
            .collect()
            .await
            .map_err(|e| failed(format!("reading the token: {e}")))?
            .to_bytes();
        if status != StatusCode::OK {
            return Err(failed(format!("the token endpoint answered {status}")));
        }
        let (token, lifetime) = token::parse_answer(&body)
            .ok_or_else(|| failed("the token endpoint's answer holds no token".to_owned()))?;
        let authorization = bearer(&token);
        self.tokens
            .put(key.clone(), token, lifetime, Instant::now());
        Ok(authorization)
    }

    /// The hyper client for the trust of `endpoint`, made on first use.
    fn hyper(&self, endpoint: &Endpoint) -> Result<HyperClient, Error> {
        let fingerprint = connect::fingerprint(&endpoint.tls);
        let mut clients = self
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(client) = clients.get(&fingerprint) {
            return Ok(client.clone());
        }
        let config = connect::config(&endpoint.tls).map_err(|source| Error::Tls {
            authority: endpoint.authority.clone(),
            source,
        })?;
        let client = Hyper::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .build(Connector::new(config));
        clients.insert(fingerprint, client.clone());
        Ok(client)
    }
}

/// `uri` with `query` appended to the query it has.
fn with_query(uri: &Uri, query: &str) -> Option<Uri> {
    let joined = [uri.query().unwrap_or_default(), query]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("&");
    let path = uri.path();
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(if joined.is_empty() {
        path.parse().ok()?
    } else {
        format!("{path}?{joined}").parse().ok()?
    });
    Uri::from_parts(parts).ok()
}

fn challenges_of(headers: &HeaderMap) -> Vec<Challenge> {
    let joined = headers
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ");
    challenge::parse(&joined)
}

/// An `Authorization: Bearer` value, marked sensitive so that no debug output of it prints.
fn bearer(token: &SecretString) -> HeaderValue {
    sensitive(&format!("Bearer {}", token.expose_secret()))
}

fn basic(username: &str, password: &SecretString) -> HeaderValue {
    sensitive(&format!(
        "Basic {}",
        base64(format!("{username}:{}", password.expose_secret()).as_bytes())
    ))
}

fn sensitive(text: &str) -> HeaderValue {
    // A token or password with a byte a header cannot hold gives a value that the registry refuses, and a 401.
    let mut value = HeaderValue::from_str(text).unwrap_or_else(|_| HeaderValue::from_static(""));
    value.set_sensitive(true);
    value
}

/// Standard Base64 with padding (RFC 4648 § 4).
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |n, (i, byte)| n | (u32::from(*byte) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

async fn follow(
    client: &HyperClient,
    endpoint: &Endpoint,
    request: &Request,
    authorization: Option<&HeaderValue>,
) -> Result<Response, Error> {
    let scheme = if endpoint.https { "https" } else { "http" };
    let mut path = format!("{}{}", endpoint.root, request.path);
    if let Some(namespace) = &endpoint.namespace {
        let separator = if path.contains('?') { '&' } else { '?' };
        path = format!(
            "{path}{separator}ns={}",
            percent_encoding::utf8_percent_encode(namespace, QUERY_VALUE)
        );
    }
    let uri: Uri = format!("{scheme}://{}{path}", endpoint.authority)
        .parse()
        .map_err(|_| Error::Request {
            authority: endpoint.authority.clone(),
            message: format!("{:?} is no path", request.path),
        })?;
    follow_uri(
        client,
        endpoint,
        &request.method,
        uri,
        &request.headers,
        Bytes::new(),
        authorization,
    )
    .await
}

/// One request, and the redirects it gets. The `Authorization` goes to the endpoint's own authority only.
async fn follow_uri(
    client: &HyperClient,
    endpoint: &Endpoint,
    method: &Method,
    mut uri: Uri,
    headers: &[(HeaderName, HeaderValue)],
    body: Bytes,
    authorization: Option<&HeaderValue>,
) -> Result<Response, Error> {
    let failed = |message: String| Error::Request {
        authority: endpoint.authority.clone(),
        message,
    };
    for _ in 0..=MAX_REDIRECTS {
        let mut builder = http::Request::builder()
            .method(method.clone())
            .uri(uri.clone());
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let own =
            uri.authority().map(http::uri::Authority::as_str) == Some(endpoint.authority.as_str());
        if own {
            if let Some(authorization) = authorization {
                builder = builder.header(AUTHORIZATION, authorization);
            }
            // The registry config's own headers go to its host and no other, redirects included.
            for (name, value) in &endpoint.headers {
                let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                    failed("a header of the registry config has no valid name".to_owned())
                })?;
                builder = builder.header(name, sensitive(value.expose_secret()));
            }
        }
        let request = builder
            .body(Full::new(body.clone()))
            .map_err(|e| failed(e.to_string()))?;
        debug!(method = %method, host = uri.authority().map(http::uri::Authority::as_str), path = uri.path(), "upstream request");
        let response = tokio::time::timeout(HEADER_TIMEOUT, client.request(request))
            .await
            .map_err(|_| failed(format!("no answer within {} s", HEADER_TIMEOUT.as_secs())))?
            .map_err(|e| failed(chain(&e)))?;
        let (parts, incoming) = response.into_parts();
        debug!(status = %parts.status, "upstream answer");
        let redirect = matches!(
            parts.status,
            StatusCode::MOVED_PERMANENTLY
                | StatusCode::FOUND
                | StatusCode::SEE_OTHER
                | StatusCode::TEMPORARY_REDIRECT
                | StatusCode::PERMANENT_REDIRECT
        );
        let location = parts.headers.get(LOCATION).and_then(|v| v.to_str().ok());
        if let (true, Some(location)) = (redirect, location) {
            uri =
                resolve(&uri, location).ok_or_else(|| failed("a redirect to no URL".to_owned()))?;
            continue;
        }
        return Ok(Response {
            status: parts.status,
            headers: parts.headers,
            body: incoming,
        });
    }
    Err(failed(format!("more than {MAX_REDIRECTS} redirects")))
}

/// An error and its sources on one line: hyper's client error names only the stage that failed.
fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        text.push_str(": ");
        text.push_str(&next.to_string());
        source = next.source();
    }
    text
}

/// The URL a `Location` names, from the URL that was asked: absolute, or a path on the same host.
fn resolve(base: &Uri, location: &str) -> Option<Uri> {
    let target: Uri = location.parse().ok()?;
    if target.scheme().is_some() && target.authority().is_some() {
        return Some(target);
    }
    let path_and_query = target.path_and_query()?.as_str();
    if !path_and_query.starts_with('/') {
        return None;
    }
    Uri::builder()
        .scheme(base.scheme()?.clone())
        .authority(base.authority()?.clone())
        .path_and_query(path_and_query)
        .build()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_is_the_standard_alphabet_with_padding() {
        for (input, want) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
            ("user:pass", "dXNlcjpwYXNz"),
        ] {
            assert_eq!(base64(input.as_bytes()), want, "{input:?}");
        }
        assert_eq!(base64(&[0xfb, 0xff, 0xfe]), "+//+");
    }

    #[test]
    fn a_location_is_absolute_or_a_path_on_the_same_host() {
        let base: Uri = "https://registry.example:5000/v2/a/blobs/x"
            .parse()
            .unwrap();
        assert_eq!(
            resolve(&base, "https://cdn.example/blob?sig=1").unwrap(),
            "https://cdn.example/blob?sig=1".parse::<Uri>().unwrap()
        );
        assert_eq!(
            resolve(&base, "/v2/other?x=1").unwrap(),
            "https://registry.example:5000/v2/other?x=1"
                .parse::<Uri>()
                .unwrap()
        );
        assert!(resolve(&base, "relative/path").is_none());
        assert!(resolve(&base, "http://[bad").is_none());
    }

    #[test]
    fn credentials_are_marked_sensitive() {
        let password = SecretString::from("hunter2".to_owned());
        let value = basic("alice", &password);
        assert!(value.is_sensitive());
        assert_eq!(format!("{value:?}"), "Sensitive");
        assert!(bearer(&password).is_sensitive());
    }
}
