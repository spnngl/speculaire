//! The trust root the agent verifies against (D26, D143): a pinned file read at start, or the root Sigstore's TUF
//! repository serves, refreshed in the background.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use http::{Method, StatusCode};
use http_body_util::{BodyExt as _, Limited};
use jiff::Timestamp;
use sigstore_tuf::Repository;
use sigstore_tuf::transport::FetchFuture;
use speculaire_registry::{Client, Request};
use speculaire_runtime::registries::{Credentials, Endpoint};
use speculaire_verify::{Absent, TrustRoot};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::{TrustedRoot, Verify};
use crate::followed::Followed;
use crate::telemetry;

/// How soon a failed TUF refresh is tried again, when it is sooner than `verify.tuf_refresh`.
const RETRY: Duration = Duration::from_secs(60);

pub use speculaire_verify::Held;

/// Where the trust root comes from, read from `[verify]` and the pinned file.
#[derive(Debug)]
pub struct Source(Kind);

#[derive(Debug)]
enum Kind {
    /// A pinned `trusted_root.json`, read, and read again as it changes (D30).
    Pinned { path: PathBuf, file: Followed<Held> },
    /// A TUF repository.
    Tuf {
        /// The repository.
        repository: Endpoint,
        /// `verify.tuf_cache`.
        cache: PathBuf,
        /// `verify.tuf_refresh`.
        refresh: Duration,
    },
}

impl Source {
    /// Reads `[verify]`, and the pinned file if there is one.
    ///
    /// # Errors
    ///
    /// When the pinned file cannot be read or is not a trusted root (D30): the agent and `check-config` refuse it.
    pub fn read(verify: &Verify) -> anyhow::Result<Self> {
        let kind = match verify.trusted_root.get() {
            TrustedRoot::Pinned(path) => Kind::Pinned {
                path: path.get().to_owned(),
                file: Followed::read("the pinned trust root", path.get(), pinned)?,
            },
            TrustedRoot::PublicGood => {
                let url = verify.tuf_url.get();
                let mut repository = Endpoint::new(true, url.authority());
                url.root().clone_into(&mut repository.root);
                Kind::Tuf {
                    repository,
                    cache: verify.tuf_cache.get().get().to_owned(),
                    refresh: verify.tuf_refresh.get().get(),
                }
            }
        };
        Ok(Self(kind))
    }

    /// Holds the trust root: a pinned one at once, and again as the file changes; a TUF one after each refresh, which
    /// runs now and then every `refresh`, or every minute while it fails. A failed refresh keeps the root held, and a
    /// root with the hash held is no change (D154).
    #[must_use]
    pub fn hold(self) -> Holding {
        match self.0 {
            Kind::Pinned { path, file } => {
                let held = file.subscribe();
                report(&held.borrow(), "pinned");
                Holding {
                    held,
                    pinned: Some((path, file)),
                }
            }
            Kind::Tuf {
                repository,
                cache,
                refresh,
            } => {
                let absent = Err(Absent::new("not fetched from TUF yet"));
                report(&absent, "TUF");
                let (holder, held) = watch::channel(absent);
                let cdn = Cdn::new(repository);
                tokio::spawn(async move {
                    loop {
                        let fetched = TrustRoot::fetch(cdn.clone(), &cache, Timestamp::now())
                            .await
                            .map(Arc::new);
                        let wait = if fetched.is_ok() {
                            refresh
                        } else {
                            refresh.min(RETRY)
                        };
                        holder.send_if_modified(|held| refreshed(held, fetched));
                        tokio::time::sleep(wait).await;
                    }
                });
                Holding { held, pinned: None }
            }
        }
    }

    /// The trust root once, as `speculaire verify` needs it (D156): the pinned one, or the one a TUF refresh into
    /// `verify.tuf_cache` gives, the cache answering when the refresh fails. The cache's writes are atomic, so the
    /// agent may refresh it at the same time.
    ///
    /// # Errors
    ///
    /// When no trust root is valid now: verification is unverifiable then, not refused.
    pub async fn once(self) -> Held {
        match self.0 {
            Kind::Pinned { file, .. } => file.subscribe().borrow().clone(),
            Kind::Tuf {
                repository, cache, ..
            } => TrustRoot::fetch(Cdn::new(repository), &cache, Timestamp::now())
                .await
                .map(Arc::new),
        }
    }
}

/// The trust root held, with the pinned file it is read from, if one is.
#[derive(Debug)]
pub struct Holding {
    held: watch::Receiver<Held>,
    pinned: Option<(PathBuf, Followed<Held>)>,
}

impl Holding {
    /// The trust root, as it changes.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<Held> {
        self.held.clone()
    }

    /// Reads the pinned file again, as SIGHUP does.
    pub fn reload(&mut self) {
        if let Some((path, file)) = &mut self.pinned {
            file.reload(path);
            self.read();
        }
    }

    /// Reads the pinned file again when it changed (D93).
    pub fn poll(&mut self) {
        if let Some((path, file)) = &mut self.pinned {
            file.poll(path);
            self.read();
        }
    }

    /// Reports a pinned root read again.
    fn read(&mut self) {
        if self.held.has_changed().unwrap_or(false) {
            report(&self.held.borrow_and_update(), "pinned");
        }
    }
}

/// Reads the pinned trust root at `path`.
fn pinned(path: &Path) -> anyhow::Result<Held> {
    Ok(Ok(Arc::new(TrustRoot::load(path)?)))
}

/// Swaps `fetched` in for `held` unless it failed while a root is held; whether the root's hash changed.
fn refreshed(held: &mut Held, fetched: Held) -> bool {
    match fetched {
        Err(reason) if held.is_ok() => {
            warn!(%reason, "the TUF refresh failed; the trust root held stays in use");
            false
        }
        fetched => {
            report(&fetched, "TUF");
            let changed = match (&*held, &fetched) {
                (Ok(before), Ok(now)) => before.hash() != now.hash(),
                _ => true,
            };
            *held = fetched;
            changed
        }
    }
}

/// Logs the trust root and sets its expiry metric: `0` when there is none.
fn report(held: &Held, source: &str) {
    match held {
        Ok(root) => {
            let expiry = root.expiry();
            info!(source, hash = %root.hash(), expiry = ?expiry, "trust root read");
            if let Some(expiry) = expiry {
                metrics::gauge!(telemetry::TRUST_ROOT_EXPIRY)
                    .set(expiry.as_duration().as_secs_f64());
            }
        }
        Err(reason) => {
            warn!(source, %reason, "no trust root");
            metrics::gauge!(telemetry::TRUST_ROOT_EXPIRY).set(0.0);
        }
    }
}

/// A TUF repository over HTTPS, on the registry client's connections and trust (D143).
#[derive(Clone)]
struct Cdn {
    client: Arc<Client>,
    endpoint: Arc<Endpoint>,
}

impl Cdn {
    fn new(endpoint: Endpoint) -> Self {
        Self {
            client: Arc::new(Client::new()),
            endpoint: Arc::new(endpoint),
        }
    }

    /// The file at `path` below the repository, or `None` when it has none: a 404, or the 403 that object stores such
    /// as the public-good CDN's answer for a missing object.
    async fn get(&self, path: String, max_length: u64) -> sigstore_tuf::Result<Option<Vec<u8>>> {
        let request = Request {
            method: Method::GET,
            path,
            repository: String::new(),
            headers: Vec::new(),
        };
        let response = self
            .client
            .send(&self.endpoint, &Credentials::Anonymous, &request)
            .await
            .map_err(|e| sigstore_tuf::Error::transport_with_source(request.path.clone(), e))?;
        match response.status {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND | StatusCode::FORBIDDEN => return Ok(None),
            status => {
                return Err(sigstore_tuf::Error::transport(format!(
                    "{}: {status}",
                    request.path
                )));
            }
        }
        let limit = usize::try_from(max_length).unwrap_or(usize::MAX);
        let body = Limited::new(response.body, limit)
            .collect()
            .await
            .map_err(|e| sigstore_tuf::Error::transport_with_source(request.path.clone(), e))?;
        Ok(Some(body.to_bytes().to_vec()))
    }
}

impl Repository for Cdn {
    fn fetch_metadata<'a>(&'a self, name: &'a str, max_length: u64) -> FetchFuture<'a> {
        Box::pin(self.get(format!("/{name}"), max_length))
    }

    fn fetch_target<'a>(&'a self, path: &'a str, max_length: u64) -> FetchFuture<'a> {
        Box::pin(self.get(format!("/targets/{path}"), max_length))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use axum::Router;
    use axum::http::Uri;
    use speculaire_artifacts::testing::{FIXTURES, tuf_expiry};

    use super::*;

    /// Serves the recorded TUF repository of step 01 (D141) over plain HTTP on loopback, with `/broken.json` failing
    /// and `/forbidden.json` refused.
    async fn recorded() -> Endpoint {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds loopback");
        let address = listener.local_addr().expect("has an address");
        let app = Router::new().fallback(|uri: Uri| async move {
            match uri.path() {
                "/broken.json" => Err(StatusCode::INTERNAL_SERVER_ERROR),
                "/forbidden.json" => Err(StatusCode::FORBIDDEN),
                path => std::fs::read(
                    Path::new(FIXTURES)
                        .join("tuf")
                        .join(path.trim_start_matches('/')),
                )
                .map_err(|_| StatusCode::NOT_FOUND),
            }
        });
        tokio::spawn(async move { axum::serve(listener, app).await });
        let mut endpoint = Endpoint::new(false, address.to_string());
        endpoint.root.clear();
        endpoint
    }

    #[test]
    fn a_failed_refresh_keeps_the_root_held_and_the_same_root_is_no_change() {
        let root = || {
            TrustRoot::load(&Path::new(FIXTURES).join("trusted_root.json"))
                .map(Arc::new)
                .expect("the recorded root")
        };
        let mut held = Err(Absent::new("not fetched from TUF yet"));

        assert!(refreshed(&mut held, Err(Absent::new("unreachable"))));
        assert!(refreshed(&mut held, Ok(root())));
        assert!(!refreshed(&mut held, Ok(root())), "the same hash");
        assert!(!refreshed(&mut held, Err(Absent::new("unreachable"))));
        assert!(held.is_ok(), "the root held stays");
    }

    #[test]
    fn a_pinned_root_reloads_on_sighup_or_a_poll_and_a_refused_file_keeps_it() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("trusted_root.json");
        let recorded = std::fs::read(Path::new(FIXTURES).join("trusted_root.json"))
            .expect("the recorded root");
        std::fs::write(&path, &recorded).expect("writes the root");
        let file = Followed::read("the pinned trust root", &path, pinned).expect("reads the root");
        let mut holding = Source(Kind::Pinned {
            path: path.clone(),
            file,
        })
        .hold();
        let mut held = holding.subscribe();
        let hash = |held: &mut watch::Receiver<Held>| {
            held.borrow_and_update()
                .as_ref()
                .map(|root| root.hash())
                .expect("a root is held")
        };
        let first = hash(&mut held);

        // Another byte is another hash (D143).
        std::fs::write(&path, [recorded.as_slice(), b"\n"].concat()).expect("writes the root");
        holding.poll();
        assert!(
            held.has_changed().expect("the holder lives"),
            "a poll reads the changed file"
        );
        assert_ne!(hash(&mut held), first);

        std::fs::write(&path, b"{").expect("writes a broken root");
        holding.reload();
        assert!(
            !held.has_changed().expect("the holder lives"),
            "a refused file keeps the root"
        );

        std::fs::write(&path, &recorded).expect("writes the root");
        holding.reload();
        assert_eq!(hash(&mut held), first, "SIGHUP reads the file");
    }

    #[tokio::test]
    async fn the_cdn_serves_the_recorded_trust_root() {
        let cdn = Cdn::new(recorded().await);
        let cache = tempfile::tempdir().expect("a temporary directory");
        let expiry: Timestamp = tuf_expiry().parse().expect("RFC 3339");
        let valid = expiry
            .checked_sub(jiff::SignedDuration::from_hours(24))
            .expect("in range");

        let root = TrustRoot::fetch(cdn, cache.path(), valid)
            .await
            .expect("the recorded repository serves a root");

        let pinned = TrustRoot::load(&Path::new(FIXTURES).join("trusted_root.json"))
            .expect("the recorded root");
        assert_eq!(root.hash(), pinned.hash());
    }

    #[tokio::test]
    async fn the_cdn_tells_missing_files_from_failures() {
        let cdn = Cdn::new(recorded().await);

        assert_eq!(
            cdn.fetch_metadata("missing.json", 1 << 20)
                .await
                .expect("a 404 is no error"),
            None
        );
        assert_eq!(
            cdn.fetch_metadata("forbidden.json", 1 << 20)
                .await
                .expect("a 403 is no error"),
            None
        );
        let broken = cdn
            .fetch_metadata("broken.json", 1 << 20)
            .await
            .expect_err("a 500 fails");
        assert!(broken.to_string().contains("/broken.json: 500"), "{broken}");
        let long = cdn
            .fetch_metadata("timestamp.json", 16)
            .await
            .expect_err("past max_length fails");
        assert!(long.to_string().contains("/timestamp.json"), "{long}");
        assert!(
            cdn.fetch_target("missing.json", 1 << 20)
                .await
                .expect("a 404 is no error")
                .is_none()
        );
    }
}
