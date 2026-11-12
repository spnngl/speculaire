//! Points containerd and CRI-O at the mirror, and back (D14, D32, D55, D56, D66, D82, D83).
//!
//! [`configure`] and [`unconfigure`] act on a node's files; [`check`] only reads them. Every path goes through
//! [`Paths`], so that tests run them on a temporary directory, and every call into the system (a reload of CRI-O,
//! its inspect API) through [`Host`], so that tests run them on a fake.

pub mod containerd;
pub mod crio;
pub mod files;
mod preflight;

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

pub use files::Change;
pub use preflight::{CONTAINERD_MINIMUM, CRIO_MINIMUM, preflight};
use secrecy::ExposeSecret;
use speculaire_pki::mirror::{self, Mirror, Part};
use speculaire_registry_config::containerd::config as containerd_config;
use speculaire_registry_config::containerd::config::Hosts;
use speculaire_registry_config::crio::Context;
use speculaire_registry_config::crio::registries::{self, Registry};
use speculaire_runtime::containerd::ImageExports;
use speculaire_runtime::cri::{self, RuntimeVersion};
use speculaire_runtime::detect::Runtime;

/// Where the files of a node are: the real root, or a directory standing in for it.
#[derive(Clone, Debug)]
pub struct Paths {
    root: PathBuf,
    containerd_config: Option<PathBuf>,
}

impl Paths {
    /// The node itself.
    #[must_use]
    pub fn system() -> Self {
        Self {
            root: PathBuf::new(),
            containerd_config: None,
        }
    }

    /// A directory standing for `/`.
    #[must_use]
    pub fn under(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            containerd_config: None,
        }
    }

    /// The same node with containerd's `config.toml` somewhere else (`runtime.containerd_config`, D87).
    #[must_use]
    pub fn with_containerd_config(mut self, path: impl Into<PathBuf>) -> Self {
        self.containerd_config = Some(path.into());
        self
    }

    fn at(&self, path: &str) -> PathBuf {
        self.root_path(path)
    }

    fn root_path(&self, path: &str) -> PathBuf {
        if self.root.as_os_str().is_empty() {
            PathBuf::from(path)
        } else {
            self.root.join(path.trim_start_matches('/'))
        }
    }

    /// The context CRI-O's files are read in.
    #[must_use]
    pub fn context(&self) -> Context {
        Context {
            root: self.root.clone(),
            // root's home, below the stand-in root too: the user's own files are read.
            home: self.root_path("/root"),
            ..Context::root()
        }
    }

    /// containerd's `config.toml`.
    #[must_use]
    pub fn containerd_config(&self) -> PathBuf {
        self.containerd_config
            .clone()
            .unwrap_or_else(|| self.at(containerd_config::DEFAULT_PATH))
    }

    /// The drop-in `configure` writes for CRI-O (D66).
    #[must_use]
    pub fn crio_dropin(&self) -> PathBuf {
        self.at("/etc/containers/registries.conf.d/99-speculaire.conf")
    }

    /// CRI-O's per-registry certificate directories.
    #[must_use]
    pub fn crio_certs(&self) -> PathBuf {
        self.at("/etc/containers/certs.d")
    }
}

/// The settings `configure` reads from the agent's config (D30).
#[derive(Clone, Debug)]
pub struct Settings {
    /// `mirror.address`.
    pub address: SocketAddr,
    /// `mirror.registries`.
    pub registries: Vec<String>,
    /// `mirror.directory`: where the mirror's CA and certificates live (D14).
    pub directory: PathBuf,
}

/// What `configure` and `unconfigure` call out to.
pub trait Host {
    /// Makes CRI-O read its registry config again (`systemctl reload crio`).
    ///
    /// # Errors
    ///
    /// When the reload fails.
    fn reload_crio(&self) -> io::Result<()>;

    /// CRI-O's NRI settings, from its inspect API.
    ///
    /// # Errors
    ///
    /// When CRI-O cannot be asked, or does not answer a config.
    fn crio_nri(&self) -> Result<speculaire_runtime::crio::Nri, speculaire_runtime::crio::Error>;

    /// The socket of `runtime`.
    fn socket(&self, runtime: Runtime) -> PathBuf;

    /// What the runtime reports about itself over the CRI (D86).
    ///
    /// # Errors
    ///
    /// When the runtime cannot be asked.
    fn runtime_version(&self, runtime: Runtime) -> Result<RuntimeVersion, cri::Error>;

    /// The settings containerd's CRI image service exports, `None` when it lists none (D15, D86).
    ///
    /// # Errors
    ///
    /// When containerd cannot be asked.
    fn containerd_image_exports(&self) -> Result<Option<ImageExports>, cri::Error>;
}

/// The node's own `systemctl` and runtime sockets.
#[derive(Clone, Debug)]
pub struct System {
    /// containerd's socket.
    pub containerd_socket: PathBuf,
    /// CRI-O's socket.
    pub crio_socket: PathBuf,
    /// The `systemctl` to run.
    pub systemctl: PathBuf,
}

impl Host for System {
    fn reload_crio(&self) -> io::Result<()> {
        let status = Command::new(&self.systemctl)
            .args(["reload", "crio"])
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!("systemctl reload crio: {status}")))
        }
    }

    fn crio_nri(&self) -> Result<speculaire_runtime::crio::Nri, speculaire_runtime::crio::Error> {
        speculaire_runtime::crio::Nri::parse(&speculaire_runtime::crio::config(&self.crio_socket)?)
    }

    fn socket(&self, runtime: Runtime) -> PathBuf {
        match runtime {
            Runtime::Containerd => self.containerd_socket.clone(),
            Runtime::CriO => self.crio_socket.clone(),
        }
    }

    fn runtime_version(&self, runtime: Runtime) -> Result<RuntimeVersion, cri::Error> {
        cri::version(&self.socket(runtime))
    }

    fn containerd_image_exports(&self) -> Result<Option<ImageExports>, cri::Error> {
        speculaire_runtime::containerd::image_exports(&self.containerd_socket)
    }
}

/// What a run did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The files it created, changed or removed.
    pub changes: Vec<Change>,
    /// What it left alone, and why.
    pub notes: Vec<String>,
}

/// A file or socket of the node that is not as the agent needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// The file or socket.
    pub path: PathBuf,
    /// What is wrong.
    pub message: String,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.message)
    }
}

/// Why a run stopped.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file or directory could not be read or written.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// What failed.
        source: io::Error,
    },
    /// containerd's config cannot be read.
    #[error("{}: {source}", path.display())]
    Containerd {
        /// The `config.toml`.
        path: PathBuf,
        /// What is wrong.
        source: Box<containerd_config::LoadError>,
    },
    /// containerd's config uses `mirrors`, which `hosts.toml` cannot be added beside.
    #[error(
        "{}: the registry section uses `mirrors`, which containerd 2.x refuses beside `config_path` and this agent does not edit: move them to `hosts.toml` files and set `config_path`",
        .0.display()
    )]
    LegacyMirrors(PathBuf),
    /// A `hosts.toml` cannot be edited.
    #[error("{}: {source}", path.display())]
    Edit {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        source: containerd::EditError,
    },
    /// CRI-O's registry config cannot be read.
    #[error(transparent)]
    Registries(Box<registries::Error>),
    /// The mirror's certificates cannot be made.
    #[error(transparent)]
    Generate(#[from] mirror::GenerateError),
    /// A runtime config names `speculaire` among the plugins it requires.
    #[error(
        "{key} names speculaire: the runtime refuses every container while the agent is not running. Remove it, restart {runtime}, and run unconfigure again (--force skips this check)"
    )]
    Required {
        /// The runtime.
        runtime: Runtime,
        /// The key.
        key: &'static str,
    },
    /// CRI-O's inspect API could not be read.
    #[error("cannot read CRI-O's config: {0}")]
    Inspect(#[from] speculaire_runtime::crio::Error),
    /// CRI-O did not reload.
    #[error("cannot reload CRI-O: {0}")]
    Reload(io::Error),
}

fn io_at(path: &Path) -> impl FnOnce(io::Error) -> Error {
    let path = path.to_owned();
    move |source| Error::Io { path, source }
}

/// The key of containerd's NRI config that `unconfigure` checks.
const CONTAINERD_REQUIRED: &str =
    "`required_plugins` of [plugins.'io.containerd.nri.v1.nri'.default_validator]";
/// The key of CRI-O's NRI config that `unconfigure` checks.
const CRIO_REQUIRED: &str = "`nri_validator_required_plugins` of [crio.nri.default_validator]";

/// The plugin name the agent registers with NRI (D9).
const PLUGIN: &str = "speculaire";

/// Points the runtime at the mirror: makes the certificates, and adds the mirror to containerd's `hosts.toml` files, or
/// writes CRI-O's drop-in and certificates and reloads it.
///
/// It reads and decides everything first, then writes: a config it cannot read changes nothing. Running it again,
/// with the same settings, changes no file.
///
/// # Errors
///
/// When a config cannot be read or edited, or a file cannot be written, or CRI-O does not reload.
pub fn configure(
    runtime: Runtime,
    paths: &Paths,
    settings: &Settings,
    now: SystemTime,
    host: &dyn Host,
) -> Result<Report, Error> {
    match runtime {
        Runtime::Containerd => configure_containerd(paths, settings, now),
        Runtime::CriO => configure_crio(paths, settings, now, host),
    }
}

/// Takes the mirror back out of the runtime's config, then deletes the certificates (D32).
///
/// # Errors
///
/// When the runtime requires the plugin and `force` is not set, or a config cannot be read or edited, or a file
/// cannot be removed, or CRI-O does not reload.
pub fn unconfigure(
    runtime: Runtime,
    paths: &Paths,
    settings: &Settings,
    force: bool,
    host: &dyn Host,
) -> Result<Report, Error> {
    if !force {
        refuse_while_required(runtime, paths, host)?;
    }
    match runtime {
        Runtime::Containerd => unconfigure_containerd(paths, settings),
        Runtime::CriO => unconfigure_crio(paths, settings, host),
    }
}

/// What a node's config lacks of what `configure` makes: nothing when it is as `configure` would leave it.
///
/// # Errors
///
/// When a config cannot be read.
pub fn check(
    runtime: Runtime,
    paths: &Paths,
    settings: &Settings,
    now: SystemTime,
) -> Result<Vec<Problem>, Error> {
    match runtime {
        Runtime::Containerd => check_containerd(paths, settings),
        Runtime::CriO => check_crio(paths, settings),
    }
    .map(|mut problems| {
        problems.extend(check_certificates(settings, now));
        problems
    })
}

/// What the agent's preflight and [`check`] find wrong, each once: what `check-config` reports.
///
/// # Errors
///
/// When a config cannot be read.
pub fn check_all(
    runtime: Runtime,
    paths: &Paths,
    settings: &Settings,
    host: &dyn Host,
    now: SystemTime,
) -> Result<Vec<Problem>, Error> {
    let mut problems = preflight(runtime, paths, settings, host, now);
    for problem in check(runtime, paths, settings, now)? {
        if !problems.contains(&problem) {
            problems.push(problem);
        }
    }
    Ok(problems)
}

fn refuse_while_required(runtime: Runtime, paths: &Paths, host: &dyn Host) -> Result<(), Error> {
    let (key, required) = match runtime {
        Runtime::Containerd => {
            let config = paths.containerd_config();
            // containerd without a config file has no NRI validator either.
            let required =
                match containerd_config::load_plugins(&config).map(|p| p.nri.required_plugins) {
                    Err(containerd_config::LoadError::Read { source, .. })
                        if source.kind() == io::ErrorKind::NotFound =>
                    {
                        Vec::new()
                    }
                    other => other.map_err(|source| Error::Containerd {
                        path: config,
                        source: Box::new(source),
                    })?,
                };
            (CONTAINERD_REQUIRED, required)
        }
        Runtime::CriO => (CRIO_REQUIRED, host.crio_nri()?.required_plugins),
    };
    if required.iter().any(|name| name == PLUGIN) {
        return Err(Error::Required { runtime, key });
    }
    Ok(())
}

// ---- certificates ----

/// The mirror's certificates as the directory has them, if it has them all and they are readable.
fn read_certificates(dir: &Path) -> Result<Option<Mirror>, Error> {
    let read = |part: Part| files::read(&dir.join(part.file_name())).map_err(io_at(dir));
    let (Some(ca), Some(server), Some(key), Some(client)) = (
        read(Part::Ca)?,
        read(Part::ServerCertificate)?,
        read(Part::ServerKey)?,
        read(Part::Client)?,
    ) else {
        return Ok(None);
    };
    Ok(Mirror::from_files(
        ca,
        server,
        secrecy::SecretString::from(key),
        &secrecy::SecretString::from(client),
    )
    .ok())
}

/// The certificates that are in `dir` when they are good for `address`, else new ones, written.
fn ensure_certificates(
    dir: &Path,
    address: SocketAddr,
    now: SystemTime,
    changes: &mut Vec<Change>,
) -> Result<Mirror, Error> {
    let kept = read_certificates(dir)?.filter(|m| m.check(address.ip(), now).is_ok());
    let mirror = match kept {
        Some(mirror) => mirror,
        None => Mirror::generate(address.ip(), now)?,
    };
    for part in Part::ALL {
        let path = dir.join(part.file_name());
        let mode = if part.is_secret() { 0o600 } else { 0o644 };
        let contents = mirror.contents(part);
        changes.extend(
            files::write(&path, contents.expose_secret().as_bytes(), mode).map_err(io_at(&path))?,
        );
    }
    Ok(mirror)
}

fn remove_certificates(dir: &Path, changes: &mut Vec<Change>) -> Result<(), Error> {
    for part in Part::ALL {
        let path = dir.join(part.file_name());
        changes.extend(files::remove(&path).map_err(io_at(&path))?);
    }
    files::remove_dir_if_empty(dir).map_err(io_at(dir))
}

fn check_certificates(settings: &Settings, now: SystemTime) -> Vec<Problem> {
    let dir = settings.directory.clone();
    let problem = |part: Part, message: String| Problem {
        path: dir.join(part.file_name()),
        message,
    };
    for part in Part::ALL {
        if !dir.join(part.file_name()).is_file() {
            return vec![problem(
                part,
                "is missing: run `speculaire configure`".to_owned(),
            )];
        }
    }
    match read_certificates(&dir) {
        Ok(Some(mirror)) => match mirror.check(settings.address.ip(), now) {
            Ok(()) => Vec::new(),
            Err(p) => vec![problem(
                p.part,
                format!("{}: run `speculaire configure`", p.reason),
            )],
        },
        Ok(None) => vec![problem(
            Part::Client,
            "is not a certificate followed by a key: run `speculaire configure`".to_owned(),
        )],
        Err(Error::Io { path, source }) => vec![Problem {
            path,
            message: source.to_string(),
        }],
        Err(other) => vec![Problem {
            path: dir,
            message: other.to_string(),
        }],
    }
}

// ---- containerd ----

/// The entry `configure` writes into every `hosts.toml`.
fn containerd_entry(settings: &Settings) -> containerd::Entry {
    let dir = settings.directory.clone();
    containerd::Entry {
        url: format!("https://{}", settings.address),
        ca: dir.join(Part::Ca.file_name()),
        client: dir.join(Part::Client.file_name()),
    }
}

/// The directories of containerd's `config_path`.
fn containerd_roots(paths: &Paths) -> Result<Vec<PathBuf>, Error> {
    let config = paths.containerd_config();
    match containerd_config::load(&config) {
        Ok(registry) => match registry.hosts {
            Hosts::ConfigPath(roots) => Ok(roots),
            Hosts::Mirrors(_) => Err(Error::LegacyMirrors(config)),
        },
        // containerd without a config file runs on its defaults.
        Err(containerd_config::LoadError::Read { path, source })
            if path == config && source.kind() == io::ErrorKind::NotFound =>
        {
            Ok(vec![
                paths.at("/etc/containerd/certs.d"),
                paths.at("/etc/docker/certs.d"),
            ])
        }
        Err(source) => Err(Error::Containerd {
            path: config,
            source: Box::new(source),
        }),
    }
}

fn configure_containerd(
    paths: &Paths,
    settings: &Settings,
    now: SystemTime,
) -> Result<Report, Error> {
    let roots = containerd_roots(paths)?;
    let (targets, skipped) = containerd::targets(&roots).map_err(io_at(&roots[0]))?;
    let entry = containerd_entry(settings);
    let mirror_dir = settings.directory.clone();
    let mut edits = Vec::new();
    for target in targets {
        let old = files::read(&target.path)
            .map_err(io_at(&target.path))?
            .unwrap_or_default();
        let new = containerd::add(&old, &entry, &mirror_dir).map_err(|source| Error::Edit {
            path: target.path.clone(),
            source,
        })?;
        edits.push((target.path, old, new));
    }
    let mut report = Report {
        notes: skipped
            .iter()
            .map(|s| format!("{}: left alone: {}", s.dir.display(), s.reason))
            .collect(),
        ..Report::default()
    };
    // The certificates first: containerd fails every pull for a registry whose hosts.toml names a missing file (D32).
    ensure_certificates(&mirror_dir, settings.address, now, &mut report.changes)?;
    for (path, old, new) in edits {
        if old != new {
            report.changes.extend(
                files::write_keeping_mode(&path, new.as_bytes(), 0o644).map_err(io_at(&path))?,
            );
        }
    }
    Ok(report)
}

fn unconfigure_containerd(paths: &Paths, settings: &Settings) -> Result<Report, Error> {
    let roots = containerd_roots(paths)?;
    let (targets, _) = containerd::targets(&roots).map_err(io_at(&roots[0]))?;
    let mirror_dir = settings.directory.clone();
    let mut report = Report::default();
    let mut edits = Vec::new();
    for target in targets.iter().filter(|t| t.exists) {
        let old = files::read(&target.path).map_err(io_at(&target.path))?;
        let Some(old) = old else { continue };
        let new = containerd::remove(&old, &mirror_dir).map_err(|source| Error::Edit {
            path: target.path.clone(),
            source,
        })?;
        edits.push((target.path.clone(), old, new));
    }
    for (path, old, new) in edits {
        if old == new {
            continue;
        }
        if containerd::is_blank(&new) {
            // The file `configure` made, or one the admin had emptied of everything but the mirror.
            report
                .changes
                .extend(files::remove(&path).map_err(io_at(&path))?);
            if let Some(dir) = path.parent().filter(|dir| {
                dir.file_name()
                    .is_some_and(|n| n == containerd::DEFAULT_DIR)
            }) {
                files::remove_dir_if_empty(dir).map_err(io_at(dir))?;
            }
        } else {
            report.changes.extend(
                files::write_keeping_mode(&path, new.as_bytes(), 0o644).map_err(io_at(&path))?,
            );
        }
    }
    // The certificates last (D32).
    remove_certificates(&mirror_dir, &mut report.changes)?;
    Ok(report)
}

fn check_containerd(paths: &Paths, settings: &Settings) -> Result<Vec<Problem>, Error> {
    let roots = containerd_roots(paths)?;
    let (targets, _) = containerd::targets(&roots).map_err(io_at(&roots[0]))?;
    let entry = containerd_entry(settings);
    let mirror_dir = settings.directory.clone();
    let mut problems = Vec::new();
    for target in targets {
        let problem = |message: String| Problem {
            path: target.path.clone(),
            message,
        };
        let Some(text) = files::read(&target.path).map_err(io_at(&target.path))? else {
            problems.push(problem(
                "is missing, and has no mirror entry: run `speculaire configure`".to_owned(),
            ));
            continue;
        };
        match containerd::add(&text, &entry, &mirror_dir) {
            Ok(wanted) if wanted == text => {}
            Ok(_) => problems.push(problem(format!(
                "lacks the mirror entry [host.\"{}\"], or it differs: run `speculaire configure`",
                entry.url
            ))),
            Err(e) => problems.push(problem(e.to_string())),
        }
    }
    Ok(problems)
}

// ---- CRI-O ----

/// The drop-in's entries and its text, from the admin's own files.
fn crio_dropin(
    paths: &Paths,
    settings: &Settings,
) -> Result<(Vec<Registry>, Vec<crio::Left>, String), Error> {
    let admin = registries::load_except(&paths.context(), Some(&paths.crio_dropin()))
        .map_err(|e| Error::Registries(Box::new(e)))?;
    let (entries, left) = crio::entries(&settings.registries, &admin, settings.address);
    let text = crio::render(&entries);
    Ok((entries, left, text))
}

/// The directories of `certs.d` holding the mirror's CA, other than the one of the current address.
fn own_cert_dirs(certs: &Path, ca: &str) -> Result<Vec<PathBuf>, Error> {
    let entries = match std::fs::read_dir(certs) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_at(certs)(e)),
    };
    let mut dirs = Vec::new();
    for entry in entries {
        let path = entry.map_err(io_at(certs))?.path();
        if files::read(&path.join("ca.crt")).ok().flatten().as_deref() == Some(ca) {
            dirs.push(path);
        }
    }
    dirs.sort();
    Ok(dirs)
}

const CRIO_CERTS: [(&str, u32); 3] = [
    ("ca.crt", 0o644),
    ("client.cert", 0o644),
    ("client.key", 0o600),
];

fn configure_crio(
    paths: &Paths,
    settings: &Settings,
    now: SystemTime,
    host: &dyn Host,
) -> Result<Report, Error> {
    let (_, left, dropin) = crio_dropin(paths, settings)?;
    let mirror_dir = settings.directory.clone();
    let old_ca = read_certificates(&mirror_dir)?.map(|m| m.ca().to_owned());
    let mut report = Report {
        notes: left
            .iter()
            .map(|l| format!("registry {}: not mirrored: {}", l.prefix, l.reason))
            .collect(),
        ..Report::default()
    };
    let mirror = ensure_certificates(&mirror_dir, settings.address, now, &mut report.changes)?;
    let certs = paths.crio_certs();
    let dir = certs.join(settings.address.to_string());
    for (name, mode) in CRIO_CERTS {
        let contents = match name {
            "ca.crt" => mirror.ca().to_owned(),
            "client.cert" => mirror.client_certificate().to_owned(),
            _ => mirror.client_key().expose_secret().to_owned(),
        };
        let path = dir.join(name);
        report
            .changes
            .extend(files::write(&path, contents.as_bytes(), mode).map_err(io_at(&path))?);
    }
    // The directory of an address the mirror had before is the mirror's own, by its CA.
    if let Some(old_ca) = old_ca {
        for stale in own_cert_dirs(&certs, &old_ca)?
            .into_iter()
            .filter(|d| *d != dir)
        {
            remove_cert_dir(&stale, &mut report.changes)?;
        }
    }
    let dropin_path = paths.crio_dropin();
    report
        .changes
        .extend(files::write(&dropin_path, dropin.as_bytes(), 0o644).map_err(io_at(&dropin_path))?);
    // What `configure` cannot fix: a file after the drop-in that replaces one of its entries.
    report
        .notes
        .extend(check_crio(paths, settings)?.iter().map(Problem::to_string));
    // Always: a reload that failed after the files were written must run again, and finds nothing to change.
    host.reload_crio().map_err(Error::Reload)?;
    Ok(report)
}

fn remove_cert_dir(dir: &Path, changes: &mut Vec<Change>) -> Result<(), Error> {
    for (name, _) in CRIO_CERTS {
        let path = dir.join(name);
        changes.extend(files::remove(&path).map_err(io_at(&path))?);
    }
    files::remove_dir_if_empty(dir).map_err(io_at(dir))
}

fn unconfigure_crio(paths: &Paths, settings: &Settings, host: &dyn Host) -> Result<Report, Error> {
    let mut report = Report::default();
    let dropin_path = paths.crio_dropin();
    report
        .changes
        .extend(files::remove(&dropin_path).map_err(io_at(&dropin_path))?);
    // Always, for the reason `configure` does: the certificates go only once CRI-O has stopped using them.
    host.reload_crio().map_err(Error::Reload)?;
    let mirror_dir = settings.directory.clone();
    let certs = paths.crio_certs();
    let mut dirs = vec![certs.join(settings.address.to_string())];
    if let Some(mirror) = read_certificates(&mirror_dir)? {
        dirs.extend(own_cert_dirs(&certs, mirror.ca())?);
    }
    dirs.sort();
    dirs.dedup();
    for dir in dirs {
        remove_cert_dir(&dir, &mut report.changes)?;
    }
    remove_certificates(&mirror_dir, &mut report.changes)?;
    Ok(report)
}

/// The problem of CRI-O's drop-in not being there, if it is not (D66).
fn crio_dropin_missing(paths: &Paths) -> Option<Problem> {
    let path = paths.crio_dropin();
    (!path.exists()).then(|| Problem {
        path,
        message: "is missing: CRI-O does not pull through the mirror; run `speculaire configure`"
            .to_owned(),
    })
}

fn check_crio(paths: &Paths, settings: &Settings) -> Result<Vec<Problem>, Error> {
    let dropin_path = paths.crio_dropin();
    let (entries, _, wanted) = crio_dropin(paths, settings)?;
    let mut problems = Vec::new();
    let problem = |message: String| Problem {
        path: dropin_path.clone(),
        message,
    };
    match files::read(&dropin_path).map_err(io_at(&dropin_path))? {
        None => return Ok(crio_dropin_missing(paths).into_iter().collect()),
        Some(text) if text != wanted => problems.push(problem(
            "differs from what `speculaire configure` writes for the registries now (the admin's entry changed, or the file was edited): run `speculaire configure`"
                .to_owned(),
        )),
        Some(_) => {}
    }
    // What CRI-O reads after every drop-in: a later one replaces an entry whole.
    let effective =
        registries::load(&paths.context()).map_err(|e| Error::Registries(Box::new(e)))?;
    for want in &entries {
        match effective.registries.iter().find(|r| r.prefix == want.prefix) {
            Some(got) if got == want => {}
            Some(got) if got.mirrors.first() != want.mirrors.first() => {
                problems.push(problem(format!(
                    "the effective entry of {} does not have the mirror first: a later file replaces it; run `speculaire configure` after removing it",
                    want.prefix
                )));
            }
            Some(_) => problems.push(problem(format!(
                "the effective entry of {} differs from the admin's, with the mirror first: run `speculaire configure`",
                want.prefix
            ))),
            None => problems.push(problem(format!(
                "{} has no effective entry: run `speculaire configure`",
                want.prefix
            ))),
        }
    }
    Ok(problems)
}

#[cfg(test)]
mod tests;
