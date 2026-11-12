//! What a runtime's own settings say about the agent: preflight, and the plugins the runtime requires (D15, D54, D55,
//! D56, D64, D66, D86).
//!
//! The agent refuses to start on a node where it would mirror or gate wrongly, and `check-config` says why without
//! starting it. Every problem names the file or socket it comes from, the key to change, and what to set.

use std::path::Path;

use crate::cri;
use crate::detect::Runtime;
use crate::version::Release;
use crate::wiring::{Error, Problem};

/// What a runtime's config says about the plugins it refuses containers without.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Required {
    /// The runtime's name.
    pub runtime: &'static str,
    /// The config key the plugins are under, for the message that tells the admin where to look.
    pub key: &'static str,
    /// The plugins the runtime requires.
    pub plugins: Vec<String>,
}

/// A runtime's settings as the agent depends on them.
pub trait Settings: Send + Sync {
    /// The plugins the runtime's NRI validator requires: `unconfigure` must not leave the runtime refusing every
    /// container for want of the agent (D54).
    ///
    /// # Errors
    ///
    /// When the runtime's settings cannot be read.
    fn required_plugins(&self) -> Result<Required, Error>;

    /// What is wrong on the node that would make the agent mirror or gate wrongly, so that it must not start: nothing
    /// when it may.
    fn preflight(&self) -> Vec<Problem>;
}

/// What the runtime says over the CRI about its version: its release when it is one the agent supports, and the
/// problems found on the way.
///
/// `socket_key` is the key of `[runtime]` that names the socket, for the message about a runtime that does not answer.
pub(crate) fn check_version(
    runtime: Runtime,
    socket: &Path,
    socket_key: &str,
    minimum: Release,
) -> (Vec<Problem>, Option<Release>) {
    let problem = |message: String| Problem {
        path: socket.to_owned(),
        message,
    };
    let version = match cri::version(socket) {
        Ok(version) => version,
        Err(e) => {
            return (
                vec![problem(format!(
                    "{e}: the agent needs {runtime} running, and the socket is `runtime.{socket_key}`"
                ))],
                None,
            );
        }
    };
    if version.name != runtime.name() {
        return (
            vec![problem(format!(
                "answers as {:?}, not {runtime}: the sockets of `[runtime]` name the wrong runtime",
                version.name
            ))],
            None,
        );
    }
    let Some(release) = version.release() else {
        return (
            vec![problem(format!(
                "{runtime} reports the version {:?}, which is no release: the agent cannot tell whether it supports it",
                version.version
            ))],
            None,
        );
    };
    let mut problems = Vec::new();
    if release < minimum {
        problems.push(problem(format!(
            "{runtime} {release} is older than {minimum}, the oldest the agent supports: upgrade it"
        )));
    }
    (problems, Some(release))
}

/// An error and its sources, as one line.
pub(crate) fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        text.push_str(": ");
        text.push_str(&next.to_string());
        source = next.source();
    }
    text
}
