//! The mirror's certificates in the mirror's directory (D14, D32): the part of wiring that no runtime differs in.

use std::net::SocketAddr;
use std::path::Path;
use std::time::SystemTime;

use secrecy::{ExposeSecret, SecretString};
use speculaire_pki::mirror::{Mirror, Part};

use crate::files::{self, Change};
use crate::wiring::{Error, Problem, Target, io_at};

/// The mirror's certificates as the directory has them, if it has them all and they are readable.
pub(crate) fn read(dir: &Path) -> Result<Option<Mirror>, Error> {
    let read = |part: Part| {
        let path = dir.join(part.file_name());
        files::read(&path).map_err(io_at(&path))
    };
    let (Some(ca), Some(server), Some(key), Some(client)) = (
        read(Part::Ca)?,
        read(Part::ServerCertificate)?,
        read(Part::ServerKey)?,
        read(Part::Client)?,
    ) else {
        return Ok(None);
    };
    Ok(Mirror::from_files(
        ca,
        server,
        SecretString::from(key),
        &SecretString::from(client),
    )
    .ok())
}

/// The certificates that are in `dir` when they are good for `address`, else new ones, written.
pub(crate) fn ensure(
    dir: &Path,
    address: SocketAddr,
    now: SystemTime,
    changes: &mut Vec<Change>,
) -> Result<Mirror, Error> {
    let kept = read(dir)?.filter(|m| m.check(address.ip(), now).is_ok());
    let mirror = match kept {
        Some(mirror) => mirror,
        None => Mirror::generate(address.ip(), now)?,
    };
    for part in Part::ALL {
        let path = dir.join(part.file_name());
        let mode = if part.is_secret() { 0o600 } else { 0o644 };
        let contents = mirror.contents(part);
        changes.extend(
            files::write(&path, contents.expose_secret().as_bytes(), mode).map_err(io_at(&path))?,
        );
    }
    Ok(mirror)
}

pub(crate) fn remove(dir: &Path, changes: &mut Vec<Change>) -> Result<(), Error> {
    for part in Part::ALL {
        let path = dir.join(part.file_name());
        changes.extend(files::remove(&path).map_err(io_at(&path))?);
    }
    files::remove_dir_if_empty(dir).map_err(io_at(dir))
}

/// What is wrong with the certificates of the mirror's directory: nothing when they are all there, and good for the
/// target's address.
#[must_use]
pub fn check(target: &Target, now: SystemTime) -> Vec<Problem> {
    let dir = target.directory.clone();
    let problem = |part: Part, message: String| Problem {
        path: dir.join(part.file_name()),
        message,
    };
    for part in Part::ALL {
        if !dir.join(part.file_name()).is_file() {
            return vec![problem(
                part,
                "is missing: run `speculaire configure`".to_owned(),
            )];
        }
    }
    match read(&dir) {
        Ok(Some(mirror)) => match mirror.check(target.address.ip(), now) {
            Ok(()) => Vec::new(),
            Err(p) => vec![problem(
                p.part,
                format!("{}: run `speculaire configure`", p.reason),
            )],
        },
        Ok(None) => vec![problem(
            Part::Client,
            "is not a certificate followed by a key: run `speculaire configure`".to_owned(),
        )],
        Err(Error::Io { path, source }) => vec![Problem {
            path,
            message: source.to_string(),
        }],
        Err(other) => vec![Problem {
            path: dir,
            message: other.to_string(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_part_that_cannot_be_read_is_an_error_naming_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join(Part::ServerKey.file_name());
        std::fs::create_dir(&key).unwrap();
        let err = read(dir.path()).unwrap_err();
        assert!(
            matches!(&err, Error::Io { path, .. } if *path == key),
            "{err}"
        );
    }
}
