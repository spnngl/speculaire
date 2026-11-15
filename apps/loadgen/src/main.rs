//! `speculaire-loadgen`: D33's load scenario against one reflector, through `speculaire-load` (D62, D104).

// D46: on musl, mimalloc in its secure mode replaces musl's allocator.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::ffi::OsString;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use speculaire_load::{Scenario, Settings, Targets};

/// Run D33's load against one reflector, print the report as Markdown, and exit 1 when a target is missed. Every
/// option defaults to D33's value; Linux only.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Simulated agents.
    #[arg(long)]
    agents: Option<usize>,
    /// Digests each agent announces.
    #[arg(long)]
    blobs: Option<usize>,
    /// Digests the agents draw theirs from.
    #[arg(long)]
    pool: Option<usize>,
    /// Lookups a second.
    #[arg(long)]
    lookups: Option<u32>,
    /// Deltas a second, each a digest added or removed.
    #[arg(long)]
    deltas: Option<u32>,
    /// Time over which the agents connect.
    #[arg(long, value_parser = humantime::parse_duration)]
    join: Option<Duration>,
    /// Load before the measures.
    #[arg(long, value_parser = humantime::parse_duration)]
    warmup: Option<Duration>,
    /// Load over which the measures are taken.
    #[arg(long, value_parser = humantime::parse_duration)]
    steady: Option<Duration>,
    /// Seed of every random choice.
    #[arg(long)]
    seed: Option<u64>,
    /// Target of the reflector's peak RSS, in MiB.
    #[arg(long)]
    rss_mib: Option<u64>,
    /// Target of the server-side lookup p99.
    #[arg(long, value_parser = humantime::parse_duration)]
    lookup_p99: Option<Duration>,
    /// Target of the resync after a reflector restart.
    #[arg(long, value_parser = humantime::parse_duration)]
    resync: Option<Duration>,
    /// Report the measures, and exit 0 even when a target is missed: for runs under Valgrind.
    #[arg(long)]
    measure_only: bool,
    /// The reflector's command, `agent --config <file>` appended: the `speculaire` binary, or a wrapper and it.
    #[arg(last = true, required = true)]
    reflector: Vec<OsString>,
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,speculaire_load=info".into()),
        )
        .init();
    let cli = Cli::parse();
    let (d33, targets) = (Scenario::D33, Targets::D33);
    let settings = Settings {
        scenario: Scenario {
            agents: cli.agents.unwrap_or(d33.agents),
            blobs: cli.blobs.unwrap_or(d33.blobs),
            pool: cli.pool.unwrap_or(d33.pool),
            lookups: cli.lookups.unwrap_or(d33.lookups),
            deltas: cli.deltas.unwrap_or(d33.deltas),
            join: cli.join.unwrap_or(d33.join),
            warmup: cli.warmup.unwrap_or(d33.warmup),
            steady: cli.steady.unwrap_or(d33.steady),
            seed: cli.seed.unwrap_or(d33.seed),
        },
        targets: Targets {
            rss: cli.rss_mib.map_or(targets.rss, |mib| mib << 20),
            lookup_p99: cli.lookup_p99.unwrap_or(targets.lookup_p99),
            resync: cli.resync.unwrap_or(targets.resync),
            ..targets
        },
        reflector: cli.reflector,
    };
    let report = speculaire_load::run(&settings).await?;
    print!("{}", report.markdown());
    Ok(if report.passed() || cli.measure_only {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
