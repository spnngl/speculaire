//! CRI-O's settings as the agent depends on them, from its inspect API (D54, D64, D86).

use super::{CriO, Nri, config};
use crate::detect::Runtime;
use crate::settings::{Required, Settings, check_version};
use crate::version::Release;
use crate::wiring::{Error, Problem};

/// The oldest CRI-O the agent supports: the oldest Kubernetes minor kind ships (D63, D86).
pub const MINIMUM: Release = Release::new(1, 35, 0);

/// The key of CRI-O's NRI config that `unconfigure` checks.
const REQUIRED: &str = "`nri_validator_required_plugins` of [crio.nri.default_validator]";

impl CriO {
    /// CRI-O's NRI settings, from its inspect API.
    fn nri(&self) -> Result<Nri, super::Error> {
        Nri::parse(&config(&self.socket)?)
    }

    /// The problem of CRI-O's drop-in not being there, if it is not (D66).
    pub(super) fn dropin_missing(&self) -> Option<Problem> {
        let path = self.dropin();
        (!path.exists()).then(|| Problem {
            path,
            message:
                "is missing: CRI-O does not pull through the mirror; run `speculaire configure`"
                    .to_owned(),
        })
    }
}

impl Settings for CriO {
    fn required_plugins(&self) -> Result<Required, Error> {
        Ok(Required {
            runtime: Runtime::CriO.name(),
            key: REQUIRED,
            plugins: self.nri()?.required_plugins,
        })
    }

    fn preflight(&self) -> Vec<Problem> {
        let (mut problems, _) = check_version(Runtime::CriO, &self.socket, "crio_socket", MINIMUM);
        match self.nri() {
            Ok(nri) => {
                let mut report = |message: &str| {
                    problems.push(Problem {
                        path: self.socket.clone(),
                        message: format!(
                            "{message}: the gate cannot run, and it cannot be turned off (D54, D64); restart CRI-O after the change"
                        ),
                    });
                };
                if !nri.enabled {
                    report("`enable_nri = false` in [crio.nri]: set it to true");
                }
                if nri.disable_connections {
                    report(
                        "`nri_disable_connections = true` in [crio.nri] closes NRI to plugins that start on their own: set it to false",
                    );
                }
            }
            Err(e) => problems.push(Problem {
                path: self.socket.clone(),
                message: e.to_string(),
            }),
        }
        problems.extend(self.dropin_missing());
        problems
    }
}

#[cfg(test)]
mod tests;
