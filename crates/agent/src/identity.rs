//! The node identity of peer links: kubelet's certificate and the cluster CA, read again as kubelet rotates them (D16,
//! D95).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use speculaire_pki::node::{Credentials, Error};
use speculaire_runtime::watch::Watch;
use tracing::{debug, error, info};

use crate::{config, telemetry};

/// The credentials of peer links, and the two files they come from.
pub(crate) struct Identity {
    credentials: Arc<Credentials>,
    certificate: Source,
    ca: Source,
}

impl Identity {
    /// Reads both files; an absent or bad one leaves P2P off until a later read succeeds.
    pub(crate) fn load(config: &config::Identity) -> Self {
        let mut identity = Self {
            credentials: Arc::new(Credentials::default()),
            certificate: Source::new(config.certificate.get().get(), "the kubelet certificate"),
            ca: Source::new(config.ca.get().get(), "the cluster CA"),
        };
        identity.reload();
        identity
    }

    /// Reads both files again, as SIGHUP does.
    pub(crate) fn reload(&mut self) {
        let credentials = &self.credentials;
        self.certificate
            .read(|path| credentials.load_identity(path).map(drop));
        self.ca.read(|path| credentials.load_authority(path));
        self.show();
    }

    /// Reads again each file whose stamp differs from the one taken before its last read (D93).
    pub(crate) fn poll(&mut self) {
        let credentials = &self.credentials;
        if self.certificate.watch.changed() {
            self.certificate
                .read(|path| credentials.load_identity(path).map(drop));
        }
        if self.ca.watch.changed() {
            self.ca.read(|path| credentials.load_authority(path));
        }
        // Every poll: an identity kubelet stopped renewing expires without a file changing.
        self.show();
    }

    /// The credentials of peer links, which follow the files.
    pub(crate) const fn credentials(&self) -> &Arc<Credentials> {
        &self.credentials
    }

    /// Sets the metrics of the identity in use: its expiry, and whether peer links can be made.
    fn show(&self) {
        if let Some(identity) = self.credentials.identity() {
            let expiry = identity
                .expiry()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            metrics::gauge!(telemetry::IDENTITY_EXPIRY).set(expiry.as_secs_f64());
        }
        let enabled = self.enabled(SystemTime::now());
        metrics::gauge!(telemetry::P2P_ENABLED).set(f64::from(u8::from(enabled)));
    }

    /// Whether peer links can be made at `now`: the identity and the CA are loaded, and the identity has not expired.
    pub(crate) fn enabled(&self, now: SystemTime) -> bool {
        self.credentials.is_ready()
            && self
                .credentials
                .identity()
                .is_some_and(|identity| now < identity.expiry())
    }
}

/// A file of the identity, with the stamp taken before its last read.
struct Source {
    path: PathBuf,
    what: &'static str,
    watch: Watch,
    absent: bool,
}

impl Source {
    fn new(path: &Path, what: &'static str) -> Self {
        Self {
            path: path.to_owned(),
            what,
            watch: Watch::new(vec![path.to_owned()]),
            absent: false,
        }
    }

    /// Stamps the file, then reads it with `load`. An absent file is said once, at `info`: a joining node has none yet
    /// (D16). Any other failure is logged and counted, and what was loaded before stays (D30).
    fn read(&mut self, load: impl FnOnce(&Path) -> Result<(), Error>) {
        self.watch = self.watch.again();
        let what = self.what;
        match load(&self.path) {
            Ok(()) => {
                self.absent = false;
                debug!(path = %self.path.display(), "{what} loaded");
            }
            Err(Error::Absent { path }) => {
                if !self.absent {
                    info!(path = %path.display(), "{what} does not exist; P2P waits for it");
                }
                self.absent = true;
            }
            Err(err) => {
                self.absent = false;
                metrics::counter!(telemetry::CONFIG_RELOAD_FAILURES).increment(1);
                error!(error = %err, "{what} cannot be loaded; the one loaded before, if any, stays in use");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use speculaire_pki::node::node_subject;
    use speculaire_pki::testing::{Cluster, handshake};

    use super::*;

    /// A node's files as kubelet lays them out: dated pairs, and a link to the current one.
    struct Files {
        dir: tempfile::TempDir,
        cluster: Cluster,
        pairs: usize,
    }

    impl Files {
        fn new() -> Self {
            let files = Self {
                dir: tempfile::tempdir().unwrap(),
                cluster: Cluster::new("kubernetes"),
                pairs: 0,
            };
            fs::write(files.ca(), files.cluster.ca()).unwrap();
            files
        }

        fn current(&self) -> PathBuf {
            self.dir.path().join("kubelet-client-current.pem")
        }

        fn ca(&self) -> PathBuf {
            self.dir.path().join("ca.crt")
        }

        /// Writes a new dated pair and repoints the link to it, as kubelet's certificate store does (client-go
        /// `util/certificate/certificate_store.go:204-312`, kubernetes v1.38.0-alpha.3-218-ge3e26fc7ab7); returns it.
        fn rotate(&mut self, pem: &str) -> String {
            self.pairs += 1;
            let pair = self
                .dir
                .path()
                .join(format!("kubelet-client-{}.pem", self.pairs));
            fs::write(&pair, pem).unwrap();
            let link = self.dir.path().join("kubelet-client-updated.pem");
            symlink(&pair, &link).unwrap();
            fs::rename(&link, self.current()).unwrap();
            pem.to_owned()
        }

        fn identity(&self) -> Identity {
            let mut identity = Identity {
                credentials: Arc::new(Credentials::default()),
                certificate: Source::new(&self.current(), "the kubelet certificate"),
                ca: Source::new(&self.ca(), "the cluster CA"),
            };
            identity.reload();
            identity
        }

        /// The certificate `identity` presents to a peer of the same cluster.
        fn presented(&self, identity: &Identity) -> Vec<u8> {
            let peer = Arc::new(Credentials::default());
            let pem = self.dir.path().join("peer.pem");
            fs::write(&pem, self.cluster.kubelet("b")).unwrap();
            peer.load_identity(&pem).unwrap();
            peer.load_authority(&self.ca()).unwrap();
            let seen = handshake(identity.credentials.server(), peer.client("a")).unwrap();
            seen.server.to_vec()
        }
    }

    fn der(pem: &str) -> Vec<u8> {
        speculaire_pki::testing::der(pem).to_vec()
    }

    #[test]
    fn a_repointed_link_is_what_the_next_poll_loads() {
        let mut files = Files::new();
        let first = files.rotate(&files.cluster.kubelet("a"));
        let mut identity = files.identity();
        assert_eq!(files.presented(&identity), der(&first));
        let second = files.rotate(&files.cluster.kubelet("a"));
        // kubelet deletes the older files.
        fs::remove_file(files.dir.path().join("kubelet-client-1.pem")).unwrap();
        assert!(identity.certificate.watch.changed());
        identity.poll();
        assert_eq!(files.presented(&identity), der(&second));
        assert_eq!(node_subject(&der(&second)), Ok("a".to_owned()));
        assert!(!identity.certificate.watch.changed(), "read once");
    }

    #[test]
    fn identity_and_ca_are_read_once_they_exist() {
        let mut files = Files::new();
        fs::remove_file(files.ca()).unwrap();
        let mut identity = files.identity();
        assert!(identity.certificate.absent && identity.ca.absent);
        assert!(identity.credentials.identity().is_none());
        files.rotate(&files.cluster.kubelet("a"));
        identity.poll();
        assert!(!identity.certificate.absent && identity.ca.absent);
        assert!(!identity.enabled(SystemTime::now()), "no CA yet");
        fs::write(files.ca(), files.cluster.ca()).unwrap();
        identity.poll();
        assert!(!identity.ca.absent);
        let expiry = identity.credentials.identity().unwrap().expiry();
        assert!(identity.enabled(expiry - std::time::Duration::from_secs(1)));
        assert!(!identity.enabled(expiry), "expired");
    }

    #[test]
    fn a_bad_pair_leaves_the_one_in_use_and_is_read_again_only_once_it_changes() {
        let mut files = Files::new();
        let first = files.rotate(&files.cluster.kubelet("a"));
        let mut identity = files.identity();
        files.rotate("not a pair");
        identity.poll();
        assert!(!identity.certificate.absent);
        assert!(
            !identity.certificate.watch.changed(),
            "the same bad file is no change"
        );
        assert_eq!(files.presented(&identity), der(&first));
        // SIGHUP reads it all the same.
        identity.reload();
        assert_eq!(files.presented(&identity), der(&first));
    }
}
