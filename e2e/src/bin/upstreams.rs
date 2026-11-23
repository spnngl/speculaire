//! Starts the upstreams of the cluster that `SPECULAIRE_E2E_CLUSTER` names, for `just e2e-up` (D94, D112), and pushes
//! to the plain one the agent's image that `SPECULAIRE_E2E_IMAGE` names, when it names one (D208).

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cluster = e2e::Cluster::from_env();
    let image = std::env::var("SPECULAIRE_E2E_IMAGE").ok();
    let started = e2e::upstream::start(&cluster).and_then(|()| {
        image.map_or(Ok(()), |image| {
            e2e::upstream::push_agent(&cluster, Path::new(&image))
        })
    });
    match started {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("e2e: {failure}");
            ExitCode::FAILURE
        }
    }
}
