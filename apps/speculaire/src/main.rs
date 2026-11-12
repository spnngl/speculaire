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
use speculaire_agent::node::Node;
use speculaire_configure::{Problem, Report};
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
    /// The runtime named, or the one whose socket answers (D64).
    fn resolve(&self, sockets: &Sockets) -> anyhow::Result<Runtime> {
        match self.runtime {
            Some(RuntimeName::Containerd) => Ok(Runtime::Containerd),
            Some(RuntimeName::CriO) => Ok(Runtime::CriO),
            None => Ok(detect::detect(sockets)?),
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
            let node = node(&config)?;
            let runtime = runtime.resolve(&node.sockets)?;
            let report = speculaire_configure::configure(
                runtime,
                &node.paths,
                &node.settings,
                SystemTime::now(),
                &node.system,
            )?;
            print_report(
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
                &report,
            )?;
        }
        Command::Unconfigure {
            config,
            runtime,
            force,
        } => {
            let node = node(&config)?;
            let runtime = runtime.resolve(&node.sockets)?;
            let report = speculaire_configure::unconfigure(
                runtime,
                &node.paths,
                &node.settings,
                force,
                &node.system,
            )?;
            print_report(
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
                &report,
            )?;
        }
    }
    Ok(())
}

/// The node the agent's config file names.
fn node(path: &std::path::Path) -> anyhow::Result<Node> {
    Ok(Node::new(&config::load(path)?))
}

/// What a run changed on `out`, one file per line, and what it left alone on `err`.
fn print_report(
    out: &mut impl Write,
    err: &mut impl Write,
    report: &Report,
) -> std::io::Result<()> {
    for change in &report.changes {
        writeln!(out, "{change}")?;
    }
    for note in &report.notes {
        writeln!(err, "note: {note}")?;
    }
    Ok(())
}

/// Each problem on `err`, and an error that counts them when there are any.
fn verdict(err: &mut impl Write, problems: &[Problem]) -> anyhow::Result<()> {
    for problem in problems {
        writeln!(err, "{problem}")?;
    }
    match problems.len() {
        0 => Ok(()),
        1 => anyhow::bail!("1 problem with the runtime, its config or the mirror's certificates"),
        n => {
            anyhow::bail!("{n} problems with the runtime, its config or the mirror's certificates")
        }
    }
}

/// Exits non-zero, naming each file or socket, when the config is invalid, the agent would refuse to start on this
/// node (D86), or the runtime's config is not as `configure` leaves it.
fn check_config(path: &std::path::Path, runtime: &RuntimeArg) -> anyhow::Result<()> {
    let node = node(path)?;
    let runtime = runtime.resolve(&node.sockets)?;
    let problems = speculaire_configure::check_all(
        runtime,
        &node.paths,
        &node.settings,
        &node.system,
        SystemTime::now(),
    )
    .context("cannot check the runtime's config")?;
    verdict(&mut std::io::stderr().lock(), &problems)
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
    use speculaire_runtime::detect::{Runtime, Sockets};

    use super::{Cli, Command, RuntimeArg, node, version};

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
            assert_eq!(runtime.resolve(&Sockets::system()).unwrap(), want);
        }
        let cli = Cli::try_parse_from(["speculaire", "unconfigure", "--force"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Unconfigure { force: true, .. }
        ));
        assert!(Cli::try_parse_from(["speculaire", "configure", "--runtime", "docker"]).is_err());
        let none = RuntimeArg { runtime: None };
        // The sockets of the machine running the tests answer nothing, or one runtime.
        let _ = none.resolve(&Sockets::system());
    }

    #[test]
    fn the_node_is_the_one_the_config_file_names_and_a_bad_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[mirror]\naddress = \"127.0.0.2:7490\"\n").unwrap();
        assert_eq!(
            node(&path).unwrap().settings.address,
            "127.0.0.2:7490".parse().unwrap()
        );
        std::fs::write(&path, "[mirror]\naddress = \"10.0.0.1:7480\"\n").unwrap();
        assert!(node(&path).is_err());
        assert!(node(&dir.path().join("missing.toml")).is_err());
    }

    #[test]
    fn a_report_prints_changes_on_stdout_and_notes_on_stderr() {
        use speculaire_configure::{Change, Report};
        let report = Report {
            changes: vec![Change::Created("/a".into()), Change::Removed("/b".into())],
            notes: vec!["left /c alone".to_owned()],
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        super::print_report(&mut out, &mut err, &report).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "created /a\nremoved /b\n");
        assert_eq!(String::from_utf8(err).unwrap(), "note: left /c alone\n");
    }

    #[test]
    fn problems_are_printed_and_counted() {
        use speculaire_configure::Problem;
        let problem = |path: &str| Problem {
            path: path.into(),
            message: "is wrong".to_owned(),
        };
        let mut err = Vec::new();
        super::verdict(&mut err, &[]).unwrap();
        assert_eq!(err, b"");
        let one = super::verdict(&mut err, &[problem("/x")]).unwrap_err();
        assert!(one.to_string().starts_with("1 problem "), "{one}");
        let two = super::verdict(&mut err, &[problem("/y"), problem("/z")]).unwrap_err();
        assert!(two.to_string().starts_with("2 problems "), "{two}");
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "/x: is wrong\n/y: is wrong\n/z: is wrong\n"
        );
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
