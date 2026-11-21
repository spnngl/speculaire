//! A percentile of a native histogram over a bench set, for `bench/bench.sh` (D35, D178).
//!
//! `histogram <name> <percent> <before> <after> [<before> <after>]...` reads each pair of files, two readings of one
//! agent's `/metrics` in the protobuf exposition taken around the set, and prints `<samples> <seconds>`: the samples of
//! the histogram `name` recorded between the two readings, summed over the pairs and every series, and the upper bound
//! of the bucket of their `percent`th percentile.

use std::process::ExitCode;

use e2e::node::Native;

fn main() -> ExitCode {
    match run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok((samples, seconds)) => {
            println!("{samples} {seconds}");
            ExitCode::SUCCESS
        }
        Err(failure) => {
            eprintln!("histogram: {failure}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(u64, f64), String> {
    let [name, percent, readings @ ..] = args else {
        return Err(
            "usage: histogram <name> <percent> <before> <after> [<before> <after>]...".to_owned(),
        );
    };
    let percent = percent
        .parse()
        .map_err(|err| format!("percent {percent}: {err}"))?;
    let (pairs, []) = readings.as_chunks::<2>() else {
        return Err("readings come in pairs, a before and an after".to_owned());
    };
    if pairs.is_empty() {
        return Err("no readings".to_owned());
    }
    let read = |path: &String| {
        let bytes = std::fs::read(path).map_err(|err| format!("{path}: {err}"))?;
        Native::decode(&bytes, name, None).map_err(|err| format!("{path}: {err}"))
    };
    let mut set = Native::default();
    for [before, after] in pairs {
        let since = read(after)?.since(&read(before)?).ok_or_else(|| {
            format!("{after} holds fewer samples than {before}: the agent restarted in between")
        })?;
        set.merge(&since)?;
    }
    Ok((set.count, set.percentile(percent)))
}
