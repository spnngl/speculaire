//! The mirror's TLS: its server certificate, and the clients it accepts (D14).
//!
//! Only TLS 1.3 (the `tls12` feature of rustls is off), and only a client with a certificate that the local CA
//! signed. The files are read again when one of them changes, so `configure` can replace them under a running agent
//! (D14, Measured: the next pull used the regenerated certificates).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime};

use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use speculaire_pki::mirror::Part;
use tracing::{error, info};

/// How often the files are looked at: at most once in this time, when a connection comes.
const RECHECK: Duration = Duration::from_secs(1);

/// The certificates could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file is missing or unreadable.
    #[error("{}: {source}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// Why.
        source: std::io::Error,
    },
    /// A file is not what it should be.
    #[error("{}: {reason}", path.display())]
    Invalid {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        reason: String,
    },
    /// The files do not make a TLS configuration.
    #[error("the mirror's certificates do not make a TLS configuration: {0}")]
    Config(#[from] rustls::Error),
}

/// What a load read, to tell whether the files changed.
type Stamp = Vec<Option<SystemTime>>;

struct Loaded {
    config: Arc<ServerConfig>,
    stamp: Stamp,
}

/// The TLS configuration of the mirror, reloaded when its files change.
pub struct Tls {
    directory: PathBuf,
    loaded: RwLock<Arc<Loaded>>,
    checked: Mutex<Instant>,
}

impl Tls {
    /// Loads the CA, the server certificate and its key from `directory` (the files of `Part`).
    ///
    /// # Errors
    ///
    /// When a file is missing or is not a certificate or key, or the certificate and key do not match.
    pub fn load(directory: &Path) -> Result<Self, Error> {
        Ok(Self {
            directory: directory.to_owned(),
            loaded: RwLock::new(Arc::new(read(directory)?)),
            checked: Mutex::new(Instant::now()),
        })
    }

    /// The configuration to accept the next connection with: the files' latest, when they are readable, else the last
    /// one that was.
    pub fn config(&self) -> Arc<ServerConfig> {
        let due = {
            let mut checked = self.checked.lock().unwrap_or_else(PoisonError::into_inner);
            if checked.elapsed() >= RECHECK {
                *checked = Instant::now();
                true
            } else {
                false
            }
        };
        if due {
            self.reload();
        }
        Arc::clone(
            &self
                .loaded
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .config,
        )
    }

    fn reload(&self) {
        let current = stamp(&self.directory);
        let held = Arc::clone(&self.loaded.read().unwrap_or_else(PoisonError::into_inner));
        if held.stamp == current {
            return;
        }
        match read(&self.directory) {
            Ok(loaded) => {
                *self.loaded.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(loaded);
                info!(directory = %self.directory.display(), "the mirror's certificates were reloaded");
            }
            Err(err) => {
                // The old files' stamp is kept, so the next connection looks again: a replacement in progress ends.
                error!(error = %err, "the mirror's certificates changed and cannot be loaded; the previous ones stay in use");
            }
        }
    }
}

fn files(directory: &Path) -> [PathBuf; 3] {
    [Part::Ca, Part::ServerCertificate, Part::ServerKey]
        .map(|part| directory.join(part.file_name()))
}

fn stamp(directory: &Path) -> Stamp {
    files(directory)
        .iter()
        .map(|path| std::fs::metadata(path).and_then(|m| m.modified()).ok())
        .collect()
}

fn read(directory: &Path) -> Result<Loaded, Error> {
    // The stamp first: a file replaced while it is read is read again at the next look.
    let stamp = stamp(directory);
    let [ca, certificate, key] = files(directory);
    let bytes = |path: &Path| {
        std::fs::read(path).map_err(|source| Error::Read {
            path: path.to_owned(),
            source,
        })
    };
    let invalid = |path: &Path, e: rustls::pki_types::pem::Error| Error::Invalid {
        path: path.to_owned(),
        reason: e.to_string(),
    };
    let mut roots = RootCertStore::empty();
    for der in CertificateDer::pem_slice_iter(&bytes(&ca)?) {
        let der = der.map_err(|e| invalid(&ca, e))?;
        roots.add(der).map_err(|e| Error::Invalid {
            path: ca.clone(),
            reason: e.to_string(),
        })?;
    }
    if roots.is_empty() {
        return Err(Error::Invalid {
            path: ca,
            reason: "holds no certificate".to_owned(),
        });
    }
    let chain = CertificateDer::pem_slice_iter(&bytes(&certificate)?)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| invalid(&certificate, e))?;
    let key = PrivateKeyDer::from_pem_slice(&bytes(&key)?).map_err(|e| invalid(&key, e))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()
            .map_err(|e| Error::Invalid {
                path: directory.join(Part::Ca.file_name()),
                reason: e.to_string(),
            })?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Loaded {
        config: Arc::new(config),
        stamp,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use secrecy::ExposeSecret as _;
    use speculaire_pki::mirror::Mirror;

    use super::*;

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    fn write(dir: &Path, mirror: &Mirror) {
        for part in [Part::Ca, Part::ServerCertificate, Part::ServerKey] {
            std::fs::write(
                dir.join(part.file_name()),
                mirror.contents(part).expose_secret(),
            )
            .unwrap();
        }
    }

    #[test]
    fn the_files_of_configure_make_a_tls_1_3_configuration_for_http_1() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            &Mirror::generate(IP, SystemTime::now()).unwrap(),
        );
        let tls = Tls::load(dir.path()).unwrap();
        let config = tls.config();
        assert_eq!(config.alpn_protocols, [b"http/1.1".to_vec()]);
    }

    #[test]
    fn a_missing_or_wrong_file_is_named() {
        let dir = tempfile::tempdir().unwrap();
        let err = Tls::load(dir.path()).err().unwrap();
        assert!(err.to_string().contains("ca.crt"), "{err}");
        let mirror = Mirror::generate(IP, SystemTime::now()).unwrap();
        write(dir.path(), &mirror);
        std::fs::write(dir.path().join("server.key"), "not a key").unwrap();
        let err = Tls::load(dir.path()).err().unwrap();
        assert!(err.to_string().contains("server.key"), "{err}");
        write(dir.path(), &mirror);
        std::fs::write(dir.path().join("ca.crt"), "").unwrap();
        let err = Tls::load(dir.path()).err().unwrap();
        assert!(
            matches!(err, Error::Invalid { .. }) && err.to_string().contains("ca.crt"),
            "{err}"
        );
        write(dir.path(), &mirror);
        let other = Mirror::generate(IP, SystemTime::now()).unwrap();
        std::fs::write(
            dir.path().join("server.key"),
            other.server_key().expose_secret(),
        )
        .unwrap();
        assert!(matches!(Tls::load(dir.path()), Err(Error::Config(_))));
    }

    #[test]
    fn a_changed_file_is_loaded_at_the_next_look_and_a_broken_one_keeps_the_old() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            &Mirror::generate(IP, SystemTime::now()).unwrap(),
        );
        let tls = Tls::load(dir.path()).unwrap();
        let first = tls.config();
        // Within the recheck time nothing is looked at.
        write(
            dir.path(),
            &Mirror::generate(IP, SystemTime::now()).unwrap(),
        );
        assert!(Arc::ptr_eq(&first, &tls.config()));
        *tls.checked.lock().unwrap() = Instant::now().checked_sub(RECHECK).unwrap();
        let second = tls.config();
        assert!(!Arc::ptr_eq(&first, &second), "the new files were loaded");
        // A file that cannot be loaded leaves the last good one in use, and is looked at again.
        std::fs::write(dir.path().join("server.crt"), "garbage").unwrap();
        *tls.checked.lock().unwrap() = Instant::now().checked_sub(RECHECK).unwrap();
        assert!(Arc::ptr_eq(&second, &tls.config()));
        write(
            dir.path(),
            &Mirror::generate(IP, SystemTime::now()).unwrap(),
        );
        *tls.checked.lock().unwrap() = Instant::now().checked_sub(RECHECK).unwrap();
        assert!(!Arc::ptr_eq(&second, &tls.config()));
    }
}
