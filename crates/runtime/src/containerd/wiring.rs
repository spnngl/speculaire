//! Wiring containerd: the mirror first in every `hosts.toml` of its `config_path` (D32, D55, D56).

use std::io;
use std::path::PathBuf;
use std::time::SystemTime;

use speculaire_pki::mirror::Part;
use speculaire_registry_config::containerd::config as containerd_config;
use speculaire_registry_config::containerd::config::Hosts;

use super::{Containerd, hosts};
use crate::wiring::{Error, Problem, Report, Target, Wiring, io_at};
use crate::{certificates, files};

impl Containerd {
    /// The entry `configure` writes into every `hosts.toml`.
    fn entry(target: &Target) -> hosts::Entry {
        let dir = target.directory.clone();
        hosts::Entry {
            url: format!("https://{}", target.address),
            ca: dir.join(Part::Ca.file_name()),
            client: dir.join(Part::Client.file_name()),
        }
    }

    /// The directories of containerd's `config_path`.
    fn roots(&self) -> Result<Vec<PathBuf>, Error> {
        let config = self.config();
        match containerd_config::load(&config) {
            Ok(registry) => match registry.hosts {
                Hosts::ConfigPath(roots) => Ok(roots),
                Hosts::Mirrors(_) => Err(Error::LegacyMirrors(config)),
            },
            // containerd without a config file runs on its defaults.
            Err(containerd_config::LoadError::Read { path, source })
                if path == config && source.kind() == io::ErrorKind::NotFound =>
            {
                Ok(vec![
                    self.paths.at("/etc/containerd/certs.d"),
                    self.paths.at("/etc/docker/certs.d"),
                ])
            }
            Err(source) => Err(Error::Containerd {
                path: config,
                source: Box::new(source),
            }),
        }
    }
}

impl Wiring for Containerd {
    fn configure(&self, target: &Target, now: SystemTime) -> Result<Report, Error> {
        let roots = self.roots()?;
        let (targets, skipped) = hosts::targets(&roots).map_err(io_at(&roots[0]))?;
        let entry = Self::entry(target);
        let mirror_dir = target.directory.clone();
        let mut edits = Vec::new();
        for file in targets {
            let old = files::read(&file.path)
                .map_err(io_at(&file.path))?
                .unwrap_or_default();
            let new = hosts::add(&old, &entry, &mirror_dir).map_err(|source| Error::Edit {
                path: file.path.clone(),
                source,
            })?;
            edits.push((file.path, old, new));
        }
        let mut report = Report {
            notes: skipped
                .iter()
                .map(|s| format!("{}: left alone: {}", s.dir.display(), s.reason))
                .collect(),
            ..Report::default()
        };
        // The certificates first: containerd fails every pull for a registry whose hosts.toml names a missing file
        // (D32).
        certificates::ensure(&mirror_dir, target.address, now, &mut report.changes)?;
        for (path, old, new) in edits {
            if old != new {
                report.changes.extend(
                    files::write_keeping_mode(&path, new.as_bytes(), 0o644)
                        .map_err(io_at(&path))?,
                );
            }
        }
        Ok(report)
    }

    fn unconfigure(&self, target: &Target) -> Result<Report, Error> {
        let roots = self.roots()?;
        let (targets, _) = hosts::targets(&roots).map_err(io_at(&roots[0]))?;
        let mirror_dir = target.directory.clone();
        let mut report = Report::default();
        let mut edits = Vec::new();
        for file in targets.iter().filter(|t| t.exists) {
            let old = files::read(&file.path).map_err(io_at(&file.path))?;
            let Some(old) = old else { continue };
            let new = hosts::remove(&old, &mirror_dir).map_err(|source| Error::Edit {
                path: file.path.clone(),
                source,
            })?;
            edits.push((file.path.clone(), old, new));
        }
        for (path, old, new) in edits {
            if old == new {
                continue;
            }
            if hosts::is_blank(&new) {
                // The file `configure` made, or one the admin had emptied of everything but the mirror.
                report
                    .changes
                    .extend(files::remove(&path).map_err(io_at(&path))?);
                if let Some(dir) = path
                    .parent()
                    .filter(|dir| dir.file_name().is_some_and(|n| n == hosts::DEFAULT_DIR))
                {
                    files::remove_dir_if_empty(dir).map_err(io_at(dir))?;
                }
            } else {
                report.changes.extend(
                    files::write_keeping_mode(&path, new.as_bytes(), 0o644)
                        .map_err(io_at(&path))?,
                );
            }
        }
        // The certificates last (D32).
        certificates::remove(&mirror_dir, &mut report.changes)?;
        Ok(report)
    }

    fn check(&self, target: &Target) -> Result<Vec<Problem>, Error> {
        let roots = self.roots()?;
        let (targets, _) = hosts::targets(&roots).map_err(io_at(&roots[0]))?;
        let entry = Self::entry(target);
        let mirror_dir = target.directory.clone();
        let mut problems = Vec::new();
        for file in targets {
            let problem = |message: String| Problem {
                path: file.path.clone(),
                message,
            };
            let Some(text) = files::read(&file.path).map_err(io_at(&file.path))? else {
                problems.push(problem(
                    "is missing, and has no mirror entry: run `speculaire configure`".to_owned(),
                ));
                continue;
            };
            match hosts::add(&text, &entry, &mirror_dir) {
                Ok(wanted) if wanted == text => {}
                Ok(_) => problems.push(problem(format!(
                    "lacks the mirror entry [host.\"{}\"], or it differs: run `speculaire configure`",
                    entry.url
                ))),
                Err(e) => problems.push(problem(e.to_string())),
            }
        }
        Ok(problems)
    }
}

#[cfg(test)]
mod tests;
