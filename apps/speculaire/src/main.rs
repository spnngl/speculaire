//! `speculaire`: the agent and its admin commands (ARCHITECTURE.md § Layout).

// D46: on musl, mimalloc in its secure mode replaces musl's allocator.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::SystemTime;

use anyhow::Context as _;
use clap::{Parser, Subcommand, ValueEnum};
use speculaire_agent::config;
use speculaire_configure::{Paths, Report, Settings, System};
use speculaire_runtime::detect::{self, Runtime, Sockets};

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
    /// Check a config file and this node's runtime config, without starting the agent: exit 0 when all is as
    /// `configure` leaves it, 1 otherwise, naming each file.
    ///
    /// It checks the file itself, and that the runtime goes through the mirror: containerd's `hosts.toml` files, or
    /// CRI-O's drop-in. Checks of the policy and trust root arrive with verification.
    CheckConfig {
        /// The config file.
        #[arg(default_value = config::DEFAULT_PATH)]
        path: PathBuf,
        #[command(flatten)]
        runtime: RuntimeArg,
    },
    /// Make the runtime pull through the mirror: create the mirror's certificates and edit the runtime's registry
    /// config. Running it again changes nothing.
    Configure {
        /// The config file.
        #[arg(long, default_value = config::DEFAULT_PATH)]
        config: PathBuf,
        #[command(flatten)]
        runtime: RuntimeArg,
    },
    /// Take the mirror out of the runtime's registry config, then delete the certificates.
    ///
    /// It stops while the runtime's NRI config requires the speculaire plugin, which would block every container
    /// once the agent is gone.
    Unconfigure {
        /// The config file.
        #[arg(long, default_value = config::DEFAULT_PATH)]
        config: PathBuf,
        #[command(flatten)]
        runtime: RuntimeArg,
        /// Go on although the runtime requires the plugin.
        #[arg(long)]
        force: bool,
    },
}

/// Which runtime the node runs, when the command may not ask its sockets.
#[derive(clap::Args)]
struct RuntimeArg {
    /// The runtime, instead of the one whose socket accepts a connection (for image builds).
    #[arg(long, value_enum)]
    runtime: Option<RuntimeName>,
}

#[derive(Clone, Copy, ValueEnum)]
enum RuntimeName {
    Containerd,
    #[value(name = "cri-o")]
    CriO,
}

impl RuntimeArg {
    /// The runtime named, or the one that answers (D64).
    fn resolve(&self) -> anyhow::Result<Runtime> {
        match self.runtime {
            Some(RuntimeName::Containerd) => Ok(Runtime::Containerd),
            Some(RuntimeName::CriO) => Ok(Runtime::CriO),
            None => Ok(detect::detect(&Sockets::system())?),
        }
    }
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
        Command::CheckConfig { path, runtime } => check_config(&path, &runtime)?,
        Command::Configure { config, runtime } => {
            let settings = settings(&config)?;
            let runtime = runtime.resolve()?;
            let report = speculaire_configure::configure(
                runtime,
                &Paths::system(),
                &settings,
                SystemTime::now(),
                &system(),
            )?;
            print_report(&report)?;
        }
        Command::Unconfigure {
            config,
            runtime,
            force,
        } => {
            let settings = settings(&config)?;
            let runtime = runtime.resolve()?;
            let report = speculaire_configure::unconfigure(
                runtime,
                &Paths::system(),
                &settings,
                force,
                &system(),
            )?;
            print_report(&report)?;
        }
    }
    Ok(())
}

fn system() -> System {
    System {
        crio_socket: Sockets::system().crio,
    }
}

/// The settings `configure` needs, from the agent's config file.
fn settings(path: &std::path::Path) -> anyhow::Result<Settings> {
    let config = config::load(path)?;
    Ok(Settings {
        address: config.mirror.address.get().get(),
        registries: config
            .mirror
            .registries
            .get()
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect(),
    })
}

fn print_report(report: &Report) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    for change in &report.changes {
        writeln!(out, "{change}")?;
    }
    drop(out);
    for note in &report.notes {
        eprintln!("note: {note}");
    }
    Ok(())
}

/// Exits non-zero, naming each file, when the config or the node's runtime config is not as `configure` leaves it.
fn check_config(path: &std::path::Path, runtime: &RuntimeArg) -> anyhow::Result<()> {
    let settings = settings(path)?;
    let runtime = runtime.resolve()?;
    let problems =
        speculaire_configure::check(runtime, &Paths::system(), &settings, SystemTime::now())
            .context("cannot check the runtime's config")?;
    for problem in &problems {
        eprintln!("{problem}");
    }
    match problems.len() {
        0 => Ok(()),
        1 => anyhow::bail!("1 file is not as `speculaire configure` leaves it"),
        n => anyhow::bail!("{n} files are not as `speculaire configure` leaves them"),
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
    use clap::{CommandFactory, Parser as _};
    use speculaire_runtime::detect::Runtime;

    use super::{Cli, Command, RuntimeArg, settings, version};

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn the_runtime_flag_names_the_runtime_without_asking_the_sockets() {
        for (flag, want) in [
            ("containerd", Runtime::Containerd),
            ("cri-o", Runtime::CriO),
        ] {
            let cli = Cli::try_parse_from(["speculaire", "configure", "--runtime", flag]).unwrap();
            let Command::Configure { runtime, .. } = cli.command else {
                panic!("not configure");
            };
            assert_eq!(runtime.resolve().unwrap(), want);
        }
        let cli = Cli::try_parse_from(["speculaire", "unconfigure", "--force"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Unconfigure { force: true, .. }
        ));
        assert!(Cli::try_parse_from(["speculaire", "configure", "--runtime", "docker"]).is_err());
        let none = RuntimeArg { runtime: None };
        // The sockets of the machine running the tests answer nothing, or one runtime.
        let _ = none.resolve();
    }

    #[test]
    fn the_settings_are_the_mirror_address_and_registries_of_the_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[mirror]\naddress = \"127.0.0.2:7490\"\nregistries = [\"docker.io\", \"localhost:5000\"]\n").unwrap();
        let settings = settings(&path).unwrap();
        assert_eq!(settings.address, "127.0.0.2:7490".parse().unwrap());
        assert_eq!(settings.registries, ["docker.io", "localhost:5000"]);
        std::fs::write(&path, "").unwrap();
        let defaults = super::settings(&path).unwrap();
        assert_eq!(defaults.address, "127.0.0.1:7480".parse().unwrap());
        assert_eq!(
            defaults.registries,
            ["docker.io", "registry.k8s.io", "quay.io", "ghcr.io"]
        );
        std::fs::write(&path, "[mirror]\naddress = \"10.0.0.1:7480\"\n").unwrap();
        assert!(super::settings(&path).is_err());
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
