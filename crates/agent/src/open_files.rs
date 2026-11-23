//! The open-file limit (D204): the agent raises its soft `RLIMIT_NOFILE` to the hard limit at start, so that it gets
//! what the node allows whether a unit's `LimitNOFILE` or a container runtime set the limits.

use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
use tracing::{info, warn};

/// Raises the soft open-file limit to the hard one, and logs both as they were; a failure warns. An unlimited value
/// records no field.
pub(crate) fn raise() {
    let Rlimit {
        current: soft,
        maximum: hard,
    } = getrlimit(Resource::Nofile);
    if soft == hard {
        info!(soft, hard, "open-file limit");
        return;
    }
    let raised = Rlimit {
        current: hard,
        maximum: hard,
    };
    match setrlimit(Resource::Nofile, raised) {
        Ok(()) => info!(soft, hard, "open-file soft limit raised to the hard limit"),
        Err(error) => warn!(soft, hard, %error, "the open-file soft limit cannot be raised"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_soft_limit_below_the_hard_one_ends_equal_to_it() {
        // Finite, as a macOS host's unlimited hard limit cannot be a soft one; lowering a limit needs no privilege.
        let hard = getrlimit(Resource::Nofile)
            .maximum
            .map_or(4096, |h| h.min(4096));
        let lowered = Rlimit {
            current: Some(hard / 4),
            maximum: Some(hard),
        };
        setrlimit(Resource::Nofile, lowered).expect("lowering the open-file limit");
        raise();
        let raised = Rlimit {
            current: Some(hard),
            maximum: Some(hard),
        };
        assert_eq!(getrlimit(Resource::Nofile), raised);
    }
}
