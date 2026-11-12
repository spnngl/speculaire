//! Points the container runtime at the mirror, and back (D14, D32, D55, D56, D66, D82, D83, D90).
//!
//! [`configure`] and [`unconfigure`] act on a node's files; [`check`] only reads them. What differs between runtimes
//! is behind the [`Wiring`] and [`Settings`] of `speculaire-runtime`; what is left here is what they have in common:
//! the refusal to unconfigure while the runtime requires the plugin, the certificates, and the order in which
//! problems are reported.

use std::time::SystemTime;

use speculaire_runtime::certificates;
use speculaire_runtime::settings::Settings;
use speculaire_runtime::wiring::{Error, Problem, Report, Target, Wiring};

/// The plugin name the agent registers with NRI (D9).
const PLUGIN: &str = "speculaire";

/// Points the runtime at the mirror: makes the certificates, and puts the mirror first in the runtime's registry
/// config.
///
/// It reads and decides everything first, then writes: a config it cannot read changes nothing. Running it again,
/// with the same target, changes no file.
///
/// # Errors
///
/// When a config cannot be read or edited, or a file cannot be written, or the runtime does not reload.
pub fn configure(wiring: &dyn Wiring, target: &Target, now: SystemTime) -> Result<Report, Error> {
    wiring.configure(target, now)
}

/// Takes the mirror back out of the runtime's config, then deletes the certificates (D32).
///
/// # Errors
///
/// When the runtime requires the plugin and `force` is not set, or a config cannot be read or edited, or a file
/// cannot be removed, or the runtime does not reload.
pub fn unconfigure(
    wiring: &dyn Wiring,
    settings: &dyn Settings,
    target: &Target,
    force: bool,
) -> Result<Report, Error> {
    if !force {
        let required = settings.required_plugins()?;
        if required.plugins.iter().any(|name| name == PLUGIN) {
            return Err(Error::Required {
                runtime: required.runtime,
                key: required.key,
            });
        }
    }
    wiring.unconfigure(target)
}

/// What a node's config lacks of what `configure` makes: nothing when it is as `configure` would leave it.
///
/// # Errors
///
/// When a config cannot be read.
pub fn check(wiring: &dyn Wiring, target: &Target, now: SystemTime) -> Result<Vec<Problem>, Error> {
    let mut problems = wiring.check(target)?;
    problems.extend(certificates::check(target, now));
    Ok(problems)
}

/// What is wrong on the node that would make the agent mirror or gate wrongly, so that it must not start: nothing
/// when it may.
#[must_use]
pub fn preflight(settings: &dyn Settings, target: &Target, now: SystemTime) -> Vec<Problem> {
    let mut problems = settings.preflight();
    problems.extend(certificates::check(target, now));
    problems
}

/// What the agent's preflight and [`check`] find wrong, each once: what `check-config` reports.
///
/// # Errors
///
/// When a config cannot be read.
pub fn check_all(
    wiring: &dyn Wiring,
    settings: &dyn Settings,
    target: &Target,
    now: SystemTime,
) -> Result<Vec<Problem>, Error> {
    // The certificates are in preflight's problems already: they are read once.
    let mut problems = preflight(settings, target, now);
    for problem in wiring.check(target)? {
        if !problems.contains(&problem) {
            problems.push(problem);
        }
    }
    Ok(problems)
}

#[cfg(test)]
mod tests;
