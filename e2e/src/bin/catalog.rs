//! The reverse half of D34's catalog check, which `just e2e` runs after the IPv4 pass (D182).
//!
//! `catalog <runtime> <dir>` reads every scrape in `dir`, a file each of an agent's `/metrics` in the protobuf
//! exposition, and fails naming each row of `docs/metrics.md` that the suites on `runtime` must emit and no scrape
//! holds.

use std::collections::BTreeSet;
use std::process::ExitCode;

use e2e::node::families;
use e2e::{Runtime, catalog};

fn main() -> ExitCode {
    match run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(None) => ExitCode::SUCCESS,
        Ok(Some(missing)) => {
            for name in missing {
                eprintln!(
                    "catalog: {name} is listed in docs/metrics.md for this runtime, and no agent emitted it (D182)"
                );
            }
            ExitCode::FAILURE
        }
        Err(failure) => {
            eprintln!("catalog: {failure}");
            ExitCode::FAILURE
        }
    }
}

/// The rows no scrape holds, or `None` when every row was emitted.
fn run(args: &[String]) -> Result<Option<Vec<&'static str>>, String> {
    let [runtime, dir] = args else {
        return Err("usage: catalog <containerd|crio> <dir>".to_owned());
    };
    let runtime: Runtime = runtime.parse()?;
    let mut emitted = BTreeSet::new();
    let mut scrapes = 0_usize;
    for entry in std::fs::read_dir(dir).map_err(|err| format!("{dir}: {err}"))? {
        let path = entry.map_err(|err| format!("{dir}: {err}"))?.path();
        let exposition =
            std::fs::read(&path).map_err(|err| format!("{}: {err}", path.display()))?;
        emitted.extend(families(&exposition).map_err(|err| format!("{}: {err}", path.display()))?);
        scrapes += 1;
    }
    let required: Vec<_> = catalog::rows()?
        .into_iter()
        .filter(|row| row.required(runtime))
        .map(|row| row.name)
        .collect();
    let missing: Vec<_> = required
        .iter()
        .copied()
        .filter(|name| !emitted.contains(*name))
        .collect();
    println!(
        "catalog: {} of {} rows emitted in {scrapes} scrapes",
        required.len() - missing.len(),
        required.len()
    );
    Ok((!missing.is_empty()).then_some(missing))
}
