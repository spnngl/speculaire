//! Wiring CRI-O: a drop-in of `registries.conf.d` that puts the mirror first, and the certificates in `certs.d` (D66,
//! D82, D83).

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use secrecy::ExposeSecret;
use speculaire_registry_config::crio::registries::{self, Registry};

use super::{CriO, dropin};
use crate::certificates;
use crate::files::{self, Change};
use crate::wiring::{Error, Problem, Report, Target, Wiring, io_at};

const CERTS: [(&str, u32); 3] = [
    ("ca.crt", 0o644),
    ("client.cert", 0o644),
    ("client.key", 0o600),
];

impl CriO {
    /// The drop-in's entries and its text, from the admin's own files.
    fn render(&self, target: &Target) -> Result<(Vec<Registry>, Vec<dropin::Left>, String), Error> {
        let admin = registries::load_except(&self.context(), Some(&self.dropin()))
            .map_err(|e| Error::Registries(Box::new(e)))?;
        let (entries, left) = dropin::entries(&target.registries, &admin, target.address);
        let text = dropin::render(&entries);
        Ok((entries, left, text))
    }

    /// Makes CRI-O read its registry config again (`systemctl reload crio`).
    fn reload(&self) -> io::Result<()> {
        let status = Command::new(&self.systemctl)
            .args(["reload", "crio"])
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!("systemctl reload crio: {status}")))
        }
    }
}

/// The directories of `certs.d` holding the mirror's CA, other than the one of the current address.
fn own_cert_dirs(certs: &Path, ca: &str) -> Result<Vec<PathBuf>, Error> {
    let entries = match std::fs::read_dir(certs) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_at(certs)(e)),
    };
    let mut dirs = Vec::new();
    for entry in entries {
        let path = entry.map_err(io_at(certs))?.path();
        if files::read(&path.join("ca.crt")).ok().flatten().as_deref() == Some(ca) {
            dirs.push(path);
        }
    }
    dirs.sort();
    Ok(dirs)
}

fn remove_cert_dir(dir: &Path, changes: &mut Vec<Change>) -> Result<(), Error> {
    for (name, _) in CERTS {
        let path = dir.join(name);
        changes.extend(files::remove(&path).map_err(io_at(&path))?);
    }
    files::remove_dir_if_empty(dir).map_err(io_at(dir))
}

impl Wiring for CriO {
    fn configure(&self, target: &Target, now: SystemTime) -> Result<Report, Error> {
        let (_, left, text) = self.render(target)?;
        let mirror_dir = target.directory.clone();
        let old_ca = certificates::read(&mirror_dir)?.map(|m| m.ca().to_owned());
        let mut report = Report {
            notes: left
                .iter()
                .map(|l| format!("registry {}: not mirrored: {}", l.prefix, l.reason))
                .collect(),
            ..Report::default()
        };
        let mirror = certificates::ensure(&mirror_dir, target.address, now, &mut report.changes)?;
        let certs = self.certs();
        let dir = certs.join(target.address.to_string());
        for (name, mode) in CERTS {
            let contents = match name {
                "ca.crt" => mirror.ca().to_owned(),
                "client.cert" => mirror.client_certificate().to_owned(),
                _ => mirror.client_key().expose_secret().to_owned(),
            };
            let path = dir.join(name);
            report
                .changes
                .extend(files::write(&path, contents.as_bytes(), mode).map_err(io_at(&path))?);
        }
        // The directory of an address the mirror had before is the mirror's own, by its CA.
        if let Some(old_ca) = old_ca {
            for stale in own_cert_dirs(&certs, &old_ca)?
                .into_iter()
                .filter(|d| *d != dir)
            {
                remove_cert_dir(&stale, &mut report.changes)?;
            }
        }
        let dropin_path = self.dropin();
        report.changes.extend(
            files::write(&dropin_path, text.as_bytes(), 0o644).map_err(io_at(&dropin_path))?,
        );
        // What `configure` cannot fix: a file after the drop-in that replaces one of its entries.
        report
            .notes
            .extend(self.check(target)?.iter().map(Problem::to_string));
        // Always: a reload that failed after the files were written must run again, and finds nothing to change.
        self.reload().map_err(Error::Reload)?;
        Ok(report)
    }

    fn unconfigure(&self, target: &Target) -> Result<Report, Error> {
        let mut report = Report::default();
        let dropin_path = self.dropin();
        report
            .changes
            .extend(files::remove(&dropin_path).map_err(io_at(&dropin_path))?);
        // Always, for the reason `configure` does: the certificates go only once CRI-O has stopped using them.
        self.reload().map_err(Error::Reload)?;
        let mirror_dir = target.directory.clone();
        let certs = self.certs();
        let mut dirs = vec![certs.join(target.address.to_string())];
        if let Some(mirror) = certificates::read(&mirror_dir)? {
            dirs.extend(own_cert_dirs(&certs, mirror.ca())?);
        }
        dirs.sort();
        dirs.dedup();
        for dir in dirs {
            remove_cert_dir(&dir, &mut report.changes)?;
        }
        certificates::remove(&mirror_dir, &mut report.changes)?;
        Ok(report)
    }

    fn check(&self, target: &Target) -> Result<Vec<Problem>, Error> {
        let dropin_path = self.dropin();
        let (entries, _, wanted) = self.render(target)?;
        let mut problems = Vec::new();
        let problem = |message: String| Problem {
            path: dropin_path.clone(),
            message,
        };
        match files::read(&dropin_path).map_err(io_at(&dropin_path))? {
            None => return Ok(self.dropin_missing().into_iter().collect()),
            Some(text) if text != wanted => problems.push(problem(
                "differs from what `speculaire configure` writes for the registries now (the admin's entry changed, or the file was edited): run `speculaire configure`"
                    .to_owned(),
            )),
            Some(_) => {}
        }
        // What CRI-O reads after every drop-in: a later one replaces an entry whole.
        let effective =
            registries::load(&self.context()).map_err(|e| Error::Registries(Box::new(e)))?;
        for want in &entries {
            match effective.registries.iter().find(|r| r.prefix == want.prefix) {
                Some(got) if got == want => {}
                Some(got) if got.mirrors.first() != want.mirrors.first() => {
                    problems.push(problem(format!(
                        "the effective entry of {} does not have the mirror first: a later file replaces it; run `speculaire configure` after removing it",
                        want.prefix
                    )));
                }
                Some(_) => problems.push(problem(format!(
                    "the effective entry of {} differs from the admin's, with the mirror first: run `speculaire configure`",
                    want.prefix
                ))),
                None => problems.push(problem(format!(
                    "{} has no effective entry: run `speculaire configure`",
                    want.prefix
                ))),
            }
        }
        Ok(problems)
    }
}

#[cfg(test)]
mod tests;
