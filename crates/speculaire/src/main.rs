//! `speculaire`: the agent and its admin commands (ARCHITECTURE.md § Layout).

// D46: on musl, mimalloc in its secure mode replaces musl's allocator.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use clap::{Parser, Subcommand};

/// P2P image mirror and supply-chain gate for containerd.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the version and the platform this binary was built for.
    Version,
}

fn main() {
    match Cli::parse().command {
        Command::Version => println!("{}", version()),
    }
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

    use super::Cli;

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }
}
