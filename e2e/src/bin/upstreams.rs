//! Starts the upstreams of the cluster that `SPECULAIRE_E2E_CLUSTER` names, for `just e2e-up` (D94, D112).

use std::process::ExitCode;

fn main() -> ExitCode {
    match e2e::upstream::start(&e2e::Cluster::from_env()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("e2e: {failure}");
            ExitCode::FAILURE
        }
    }
}
