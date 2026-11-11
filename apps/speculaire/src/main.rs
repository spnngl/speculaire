//! `speculaire`: the agent and its admin commands (ARCHITECTURE.md § Layout).

// D46: on musl, mimalloc in its secure mode replaces musl's allocator.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use speculaire_agent::config;

/// P2P image mirror and supply-chain gate for containerd and CRI-O.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the agent until SIGTERM; SIGHUP reloads the config.
    Agent {
        /// The config file.
        #[arg(long, default_value = config::DEFAULT_PATH)]
        config: PathBuf,
    },
    /// Print the version and the platform this binary was built for.
    Version,
    /// Check a config file without starting the agent: exit 0 when it is valid, 1 otherwise.
    ///
    /// This release checks the file itself; checks of the policy and trust root it names arrive with verification.
    CheckConfig {
        /// The config file.
        #[arg(default_value = config::DEFAULT_PATH)]
        path: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Agent { config } => speculaire_agent::run(&config)?,
        Command::Version => writeln!(std::io::stdout().lock(), "{}", version())?,
        Command::CheckConfig { path } => {
            config::load(&path)?;
        }
    }
    Ok(())
}

/// The line `speculaire version` prints: name, version, architecture and OS, then `-musl` for a static build.
fn version() -> String {
    let musl = if cfg!(target_env = "musl") {
        "-musl"
    } else {
        ""
    };
    format!(
        "speculaire {} {}-{}{musl}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH,
        std::env::consts::OS,
    )
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::{Cli, version};

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn version_names_the_package_and_the_platform() {
        let line = version();
        let prefix = format!(
            "speculaire {} {}-{}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::ARCH,
            std::env::consts::OS,
        );
        assert!(line.starts_with(&prefix), "{line}");
        assert_eq!(line.ends_with("-musl"), cfg!(target_env = "musl"), "{line}");
    }
}
