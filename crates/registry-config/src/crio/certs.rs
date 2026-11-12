//! The TLS files of a registry host: CA certificates and client certificates in a per-host directory (D66).
//!
//! Ported from go.podman.io/image v5.40.0 `docker/docker_client.go` (`dockerCertDir`) and
//! `pkg/tlsclientconfig/tlsclientconfig.go` (`SetupCertificates`), as vendored by CRI-O v1.37.2. (D25)
//!
//! The files are found and paired as the library does, and must be readable; whether they hold PEM, and a key that
//! matches its certificate, is for the TLS configuration built from them to say.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::Context;
use super::configfile::{self, Wanted};

/// A client certificate and its key, files of one directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientCert {
    /// The `*.cert` file.
    pub cert: PathBuf,
    /// The `*.key` file of the same name.
    pub key: PathBuf,
}

/// What a certificate directory holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Certs {
    /// The `*.crt` files: CA certificates to trust besides the system's.
    pub ca: Vec<PathBuf>,
    /// The `*.cert` files with their keys: certificates to present.
    pub client: Vec<ClientCert>,
}

/// A certificate directory that cannot be used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A file or directory cannot be read.
    #[error("cannot read {}", path.display())]
    Read {
        /// The file or directory.
        path: PathBuf,
        /// What failed.
        #[source]
        source: std::io::Error,
    },
    /// A client certificate has no key, or a key no certificate.
    #[error("{message}")]
    Unpaired {
        /// What is missing.
        message: String,
    },
}

/// `dockerCertDir`: the directory of `host_port` (`registry.example:5000`) in the first of the certificate
/// directories that has one: the user's, the administrator's and the system's of `containers`, then Docker's.
///
/// # Errors
///
/// When looking for a directory fails other than by its absence or a permission.
pub fn cert_dir(ctx: &Context, host_port: &str) -> Result<Option<PathBuf>, Error> {
    let paths = configfile::search_paths(
        ctx,
        &Wanted {
            name: "certs",
            extension: "d",
            bare: true,
            custom_file: None,
            env_file: None,
            custom_dir: None,
            env_override: None,
        },
    );
    let docker = ctx.under_root("/etc/docker/certs.d");
    for base in paths.drop_in_dirs.iter().chain([&docker]) {
        let dir = base.join(host_port.trim_start_matches('/'));
        match std::fs::metadata(&dir) {
            Ok(_) => return Ok(Some(dir)),
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::PermissionDenied) => {}
            Err(source) => return Err(Error::Read { path: dir, source }),
        }
    }
    Ok(None)
}

/// `SetupCertificates`: the files of `dir`. A missing or forbidden directory has none.
///
/// # Errors
///
/// When a file cannot be read, or a certificate and its key are not both there.
pub fn setup(dir: &Path) -> Result<Certs, Error> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::PermissionDenied) => {
            return Ok(Certs::default());
        }
        Err(source) => {
            return Err(Error::Read {
                path: dir.to_owned(),
                source,
            });
        }
    };
    let read_error = |source| Error::Read {
        path: dir.to_owned(),
        source,
    };
    let mut names = entries
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(read_error)?;
    names.sort();
    let has = |name: &str| names.iter().any(|candidate| candidate == name);
    // A file removed since the listing is skipped; any other failure is an error.
    let readable = |path: &Path| match std::fs::read(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(source) => Err(Error::Read {
            path: path.to_owned(),
            source,
        }),
    };
    let mut certs = Certs::default();
    #[expect(
        clippy::case_sensitive_file_extension_comparisons,
        reason = "the library compares the suffix as bytes: `CA.CRT` is not a CA certificate"
    )]
    for name in &names {
        if name.ends_with(".crt") && readable(&dir.join(name))? {
            certs.ca.push(dir.join(name));
        }
        if let Some(base) = name.strip_suffix(".cert") {
            let key = format!("{base}.key");
            if !has(&key) {
                return Err(Error::Unpaired {
                    message: format!(
                        "missing key {key} for client certificate {name}. Note that CA certificates should use the extension .crt"
                    ),
                });
            }
            let (cert, key) = (dir.join(name), dir.join(&key));
            // `tls.LoadX509KeyPair` reads both, and fails on a file that is gone.
            for path in [&cert, &key] {
                std::fs::read(path).map_err(|source| Error::Read {
                    path: path.clone(),
                    source,
                })?;
            }
            certs.client.push(ClientCert { cert, key });
        }
        if let Some(base) = name.strip_suffix(".key") {
            let cert = format!("{base}.cert");
            if !has(&cert) {
                return Err(Error::Unpaired {
                    message: format!("missing client certificate {cert} for key {name}"),
                });
            }
        }
    }
    Ok(certs)
}

/// The certificates of `host_port` for `ctx`: those of its directory, none when it has no directory.
///
/// # Errors
///
/// As [`cert_dir`] and [`setup`].
pub fn load(ctx: &Context, host_port: &str) -> Result<Certs, Error> {
    match cert_dir(ctx, host_port)? {
        Some(dir) => setup(&dir),
        None => Ok(Certs::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_with(files: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("a temporary directory");
        for file in files {
            std::fs::write(dir.path().join(file), "pem").expect("a file");
        }
        dir
    }

    #[test]
    fn certificates_are_the_crt_files_and_the_cert_and_key_pairs() {
        let dir = dir_with(&["ca.crt", "other.txt", "a.cert", "a.key", "b.cert", "b.key"]);
        let found = setup(dir.path()).expect("certificates");
        assert_eq!(found.ca, [dir.path().join("ca.crt")]);
        assert_eq!(
            found.client,
            [
                ClientCert {
                    cert: dir.path().join("a.cert"),
                    key: dir.path().join("a.key")
                },
                ClientCert {
                    cert: dir.path().join("b.cert"),
                    key: dir.path().join("b.key")
                }
            ]
        );
    }

    #[test]
    fn a_certificate_without_its_key_and_a_key_without_its_certificate_are_errors() {
        let error = setup(dir_with(&["a.cert"]).path()).expect_err("a refusal");
        assert!(
            error
                .to_string()
                .contains("missing key a.key for client certificate a.cert"),
            "{error}"
        );
        let error = setup(dir_with(&["a.key"]).path()).expect_err("a refusal");
        assert!(
            error
                .to_string()
                .contains("missing client certificate a.cert for key a.key"),
            "{error}"
        );
        let upper = setup(dir_with(&["A.CERT", "b.KEY", "C.CRT"]).path()).expect("none");
        assert_eq!(upper, Certs::default());
    }

    #[test]
    fn a_certificate_that_vanished_since_the_listing_is_skipped() {
        let dir = dir_with(&["a.cert", "a.key"]);
        std::os::unix::fs::symlink(dir.path().join("gone"), dir.path().join("ca.crt"))
            .expect("a link");
        let found = setup(dir.path()).expect("certificates");
        assert_eq!(found.ca, Vec::<PathBuf>::new());
        assert_eq!(found.client.len(), 1);
    }

    #[test]
    fn the_certificates_of_a_host_are_those_of_its_directory() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let host = dir.path().join("etc/containers/certs.d/reg.test");
        std::fs::create_dir_all(&host).expect("a directory");
        std::fs::write(host.join("ca.crt"), "pem").expect("a file");
        let ctx = Context {
            root: dir.path().to_owned(),
            home: dir.path().join("home"),
            ..Context::root()
        };
        assert_eq!(
            load(&ctx, "reg.test").expect("certificates").ca,
            [host.join("ca.crt")]
        );
    }

    #[test]
    fn a_missing_directory_has_no_certificates_and_a_file_is_not_a_directory() {
        let dir = dir_with(&["file"]);
        assert_eq!(
            setup(&dir.path().join("none")).expect("none"),
            Certs::default()
        );
        assert!(matches!(
            setup(&dir.path().join("file")),
            Err(Error::Read { .. })
        ));
    }

    #[test]
    fn a_key_that_cannot_be_read_is_an_error() {
        let dir = dir_with(&["a.cert"]);
        // A directory named `a.key` is there, and cannot be read as a file.
        std::fs::create_dir(dir.path().join("a.key")).expect("a directory");
        assert!(matches!(setup(dir.path()), Err(Error::Read { .. })));
        let dir = dir_with(&["a.key"]);
        std::fs::create_dir(dir.path().join("a.cert")).expect("a directory");
        assert!(matches!(setup(dir.path()), Err(Error::Read { .. })));
        let dir = tempfile::tempdir().expect("a temporary directory");
        std::fs::create_dir(dir.path().join("ca.crt")).expect("a directory");
        assert!(matches!(setup(dir.path()), Err(Error::Read { .. })));
    }

    #[test]
    fn the_first_directory_of_the_host_wins() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let ctx = Context {
            root: dir.path().to_owned(),
            home: dir.path().join("home"),
            ..Context::root()
        };
        assert_eq!(cert_dir(&ctx, "reg.test:5000").expect("none"), None);
        for path in [
            "etc/docker/certs.d/reg.test:5000",
            "usr/share/containers/certs.d/reg.test:5000",
        ] {
            std::fs::create_dir_all(dir.path().join(path)).expect("a directory");
        }
        assert_eq!(
            cert_dir(&ctx, "reg.test:5000").expect("a directory"),
            Some(
                dir.path()
                    .join("usr/share/containers/certs.d/reg.test:5000")
            )
        );
        std::fs::create_dir_all(dir.path().join("etc/containers/certs.d/reg.test:5000"))
            .expect("a directory");
        assert_eq!(
            cert_dir(&ctx, "reg.test:5000").expect("a directory"),
            Some(dir.path().join("etc/containers/certs.d/reg.test:5000"))
        );
        assert_eq!(load(&ctx, "reg.test:5000").expect("none"), Certs::default());
        let file = dir.path().join("etc/containers/certs.d/file");
        std::fs::write(&file, "").expect("a file");
        let beyond = Context { root: file, ..ctx };
        assert!(matches!(cert_dir(&beyond, "x"), Err(Error::Read { .. })));
    }
}
