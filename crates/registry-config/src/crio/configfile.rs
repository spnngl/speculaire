//! Where go.podman.io/image looks for a config file and its drop-ins.
//!
//! Ported from go.podman.io/storage v1.63.0 `pkg/configfile/parse.go` (`getSearchPaths`, `Read`, `getDropInPaths`,
//! `readDropInsFromPaths`, `getDropInPathsUnderMain`), as vendored by CRI-O v1.37.2, for Linux. (D25)

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::Context;

/// The system directory of the files a distribution ships.
const SYSTEM_DIR: &str = "/usr/share/containers";
/// The system directory of the administrator's overrides.
const ADMIN_DIR: &str = "/etc/containers";

/// A config file to look for: `registries.conf` or the `certs.d` directories.
pub(crate) struct Wanted<'a> {
    /// `Name` and `Extension`, joined by a dot unless `bare` is set.
    pub(crate) name: &'a str,
    pub(crate) extension: &'a str,
    /// `DoNotUseExtensionForConfigName`: the extension names the drop-in directories only.
    pub(crate) bare: bool,
    /// `CustomConfigFilePath` or, when empty, the file `EnvironmentName` names.
    pub(crate) custom_file: Option<&'a Path>,
    pub(crate) env_file: Option<&'a Path>,
    /// `CustomConfigFileDropInDirectory`.
    pub(crate) custom_dir: Option<&'a Path>,
    /// The file `EnvironmentName + "_OVERRIDE"` names.
    pub(crate) env_override: Option<&'a Path>,
}

/// A file or directory that cannot be read.
#[derive(Debug, thiserror::Error)]
#[error("cannot read {}", path.display())]
pub(crate) struct ReadError {
    pub(crate) path: PathBuf,
    pub(crate) source: std::io::Error,
}

/// The places to look, from the highest priority to the lowest (`SearchPaths`).
pub(crate) struct SearchPaths {
    /// The main files; the first one that exists is read.
    pub(crate) main_files: Vec<PathBuf>,
    /// Whether a main file may be missing: not when a path was named.
    ignore_main_missing: bool,
    /// The drop-in directories.
    pub(crate) drop_in_dirs: Vec<PathBuf>,
    /// The file read after everything else.
    pub(crate) extra_override: Option<PathBuf>,
}

/// `getSearchPaths`.
pub(crate) fn search_paths(ctx: &Context, wanted: &Wanted<'_>) -> SearchPaths {
    let file_name = if wanted.bare {
        wanted.name.to_owned()
    } else {
        format!("{}.{}", wanted.name, wanted.extension)
    };
    let default_config = ctx.under_root(&format!("{SYSTEM_DIR}/{file_name}"));
    let override_config = ctx.under_root(&format!("{ADMIN_DIR}/{file_name}"));
    let config_home = ctx
        .xdg_config_home
        .clone()
        .unwrap_or_else(|| ctx.home.join(".config"));
    let user_config = config_home.join("containers").join(&file_name);

    let mut ignore_main_missing = true;
    let mut load_drop_ins = true;
    let main_files = if let Some(path) = wanted.custom_file {
        ignore_main_missing = false;
        vec![path.to_owned()]
    } else if let Some(path) = wanted.env_file.filter(|path| !path.as_os_str().is_empty()) {
        // The variable names the file and no drop-in directory is read.
        ignore_main_missing = false;
        load_drop_ins = false;
        vec![path.to_owned()]
    } else {
        vec![
            user_config.clone(),
            override_config.clone(),
            default_config.clone(),
        ]
    };

    let mut drop_in_dirs = Vec::new();
    if load_drop_ins {
        if let Some(dir) = wanted.custom_dir {
            drop_in_dirs.push(dir.to_owned());
        } else {
            let suffix = format!(".{}", wanted.extension);
            drop_in_dirs.push(with_suffix(&user_config, ".d"));
            drop_in_dirs.extend(under_main(&override_config, &suffix, ctx.uid));
            drop_in_dirs.extend(under_main(&default_config, &suffix, ctx.uid));
        }
    }
    let extra_override = match (wanted.custom_dir, wanted.env_override) {
        (None, Some(path)) if !path.as_os_str().is_empty() => Some(path.to_owned()),
        _ => None,
    };
    SearchPaths {
        main_files,
        ignore_main_missing,
        drop_in_dirs,
        extra_override,
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut text = path.as_os_str().to_owned();
    text.push(suffix);
    PathBuf::from(text)
}

/// `getDropInPathsUnderMain`: `rootful` or `rootless` variants of the directory, then the plain one.
fn under_main(main: &Path, suffix: &str, uid: u32) -> Vec<PathBuf> {
    let main = main.to_string_lossy();
    let rootless = uid > 0;
    let special = if rootless { "rootless" } else { "rootful" };
    let (prefix, cut) = match main.strip_suffix(suffix) {
        Some(prefix) => (prefix, true),
        None => (&*main, false),
    };
    let mut special_path = format!("{prefix}.{special}");
    if cut {
        special_path.push_str(suffix);
    }
    special_path.push_str(".d");
    let mut paths = Vec::new();
    if rootless {
        paths.push(PathBuf::from(&special_path).join(uid.to_string()));
    }
    paths.push(PathBuf::from(special_path));
    paths.push(PathBuf::from(format!("{main}.d")));
    paths
}

/// The files to read, in order (`Read`): the first main file that opens, the drop-ins by file name, the override.
/// A drop-in of the same name in several directories is read from the one of the highest priority.
///
/// # Errors
///
/// When a named file is missing, or a file or directory fails other than by its absence.
pub(crate) fn files(paths: &SearchPaths, extension: &str) -> Result<Vec<PathBuf>, ReadError> {
    let mut files = Vec::new();
    for path in paths
        .main_files
        .iter()
        .filter(|path| !path.as_os_str().is_empty())
    {
        if opens(path, paths.ignore_main_missing)? {
            files.push(path.clone());
            break;
        }
    }
    // A drop-in that is not found when opened, such as a dangling link, is skipped.
    for path in drop_ins(&paths.drop_in_dirs, &format!(".{extension}"))? {
        if opens(&path, true)? {
            files.push(path);
        }
    }
    if let Some(path) = &paths.extra_override {
        opens(path, false)?;
        files.push(path.clone());
    }
    Ok(files)
}

/// Whether `path` opens: a missing file is `false` when `may_be_missing`, else an error.
fn opens(path: &Path, may_be_missing: bool) -> Result<bool, ReadError> {
    match std::fs::File::open(path) {
        Ok(_) => Ok(true),
        Err(e) if may_be_missing && e.kind() == ErrorKind::NotFound => Ok(false),
        Err(source) => Err(ReadError {
            path: path.to_owned(),
            source,
        }),
    }
}

/// `readDropInsFromPaths`: the files that end in `suffix`, one per name, by name.
fn drop_ins(dirs: &[PathBuf], suffix: &str) -> Result<Vec<PathBuf>, ReadError> {
    let mut by_name = BTreeMap::new();
    for dir in dirs.iter().rev() {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(ReadError {
                    path: dir.clone(),
                    source,
                });
            }
        };
        for entry in entries {
            let read = |source| ReadError {
                path: dir.clone(),
                source,
            };
            let entry = entry.map_err(read)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !entry.file_type().map_err(read)?.is_dir() && name.ends_with(suffix) {
                by_name.insert(name.clone(), dir.join(name));
            }
        }
    }
    Ok(by_name.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_at(root: &str) -> Context {
        Context {
            root: PathBuf::from(root),
            ..Context::root()
        }
    }

    fn registries(ctx: &Context) -> SearchPaths {
        search_paths(
            ctx,
            &Wanted {
                name: "registries",
                extension: "conf",
                bare: false,
                custom_file: None,
                env_file: None,
                custom_dir: None,
                env_override: None,
            },
        )
    }

    #[test]
    fn a_root_service_reads_the_user_then_the_admin_then_the_system_files() {
        let paths = registries(&root_at("/r"));
        assert_eq!(
            paths.main_files,
            [
                "/root/.config/containers/registries.conf",
                "/r/etc/containers/registries.conf",
                "/r/usr/share/containers/registries.conf"
            ]
            .map(PathBuf::from)
        );
        assert_eq!(
            paths.drop_in_dirs,
            [
                "/root/.config/containers/registries.conf.d",
                "/r/etc/containers/registries.rootful.conf.d",
                "/r/etc/containers/registries.conf.d",
                "/r/usr/share/containers/registries.rootful.conf.d",
                "/r/usr/share/containers/registries.conf.d"
            ]
            .map(PathBuf::from)
        );
    }

    #[test]
    fn a_rootless_user_adds_a_directory_of_its_uid() {
        let ctx = Context {
            uid: 1000,
            xdg_config_home: Some(PathBuf::from("/x")),
            ..Context::root()
        };
        let paths = registries(&ctx);
        assert_eq!(
            paths.main_files[0],
            PathBuf::from("/x/containers/registries.conf")
        );
        assert_eq!(
            paths.drop_in_dirs[1..4],
            [
                "/etc/containers/registries.rootless.conf.d/1000",
                "/etc/containers/registries.rootless.conf.d",
                "/etc/containers/registries.conf.d"
            ]
            .map(PathBuf::from)
        );
    }

    #[test]
    fn a_bare_name_has_no_extension_but_its_directories_do() {
        let paths = search_paths(
            &root_at(""),
            &Wanted {
                name: "certs",
                extension: "d",
                bare: true,
                custom_file: None,
                env_file: None,
                custom_dir: None,
                env_override: None,
            },
        );
        assert_eq!(
            paths.drop_in_dirs[1..3],
            ["/etc/containers/certs.rootful.d", "/etc/containers/certs.d"].map(PathBuf::from)
        );
    }

    #[test]
    fn a_named_file_is_alone_and_must_exist() {
        let named = PathBuf::from("/x/registries.conf");
        let env = PathBuf::from("/e/registries.conf");
        let custom = |custom_file, env_file, custom_dir| {
            search_paths(
                &Context::root(),
                &Wanted {
                    name: "registries",
                    extension: "conf",
                    bare: false,
                    custom_file,
                    env_file,
                    custom_dir,
                    env_override: None,
                },
            )
        };
        let paths = custom(Some(&named), Some(&env), None);
        assert_eq!(paths.main_files, std::slice::from_ref(&named));
        assert!(!paths.ignore_main_missing);
        assert_eq!(paths.drop_in_dirs.len(), 5);
        // The environment's file stops the drop-ins; the custom file does not.
        let paths = custom(None, Some(&env), None);
        assert_eq!(paths.main_files, std::slice::from_ref(&env));
        assert_eq!(paths.drop_in_dirs, Vec::<PathBuf>::new());
        let dir = PathBuf::from("/d");
        assert_eq!(custom(None, None, Some(&dir)).drop_in_dirs, [dir]);
    }

    #[test]
    fn the_first_main_file_that_exists_and_the_drop_ins_by_name_are_read() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let write = |path: &str, text: &str| {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
            std::fs::write(&path, text).expect("a file");
        };
        write("etc/containers/registries.conf", "");
        write("usr/share/containers/registries.conf", "");
        write("etc/containers/registries.conf.d/20-b.conf", "");
        write("etc/containers/registries.conf.d/10-a.conf", "");
        write("etc/containers/registries.conf.d/skip.txt", "");
        write("usr/share/containers/registries.conf.d/15-c.conf", "");
        write("usr/share/containers/registries.conf.d/10-a.conf", "");
        std::fs::create_dir_all(dir.path().join("etc/containers/registries.conf.d/dir.conf"))
            .expect("a directory");
        // A drop-in that is gone when it is opened is skipped.
        std::os::unix::fs::symlink(
            dir.path().join("none"),
            dir.path()
                .join("etc/containers/registries.conf.d/05-gone.conf"),
        )
        .expect("a symbolic link");
        let ctx = Context {
            root: dir.path().to_owned(),
            home: dir.path().join("none"),
            ..Context::root()
        };
        let found = files(&registries(&ctx), "conf").expect("files");
        let relative: Vec<_> = found
            .iter()
            .map(|path| path.strip_prefix(dir.path()).expect("below").to_owned())
            .collect();
        assert_eq!(
            relative,
            [
                "etc/containers/registries.conf",
                "etc/containers/registries.conf.d/10-a.conf",
                "usr/share/containers/registries.conf.d/15-c.conf",
                "etc/containers/registries.conf.d/20-b.conf"
            ]
            .map(PathBuf::from)
        );
    }

    #[test]
    fn an_empty_path_from_the_environment_names_nothing() {
        let empty = PathBuf::new();
        let paths = search_paths(
            &Context::root(),
            &Wanted {
                name: "registries",
                extension: "conf",
                bare: false,
                custom_file: None,
                env_file: Some(&empty),
                custom_dir: None,
                env_override: Some(&empty),
            },
        );
        assert_eq!(paths.main_files.len(), 3);
        assert!(paths.ignore_main_missing);
        assert_eq!(paths.drop_in_dirs.len(), 5);
        assert_eq!(paths.extra_override, None);
    }

    #[test]
    fn a_named_file_that_is_missing_and_an_unreadable_directory_are_errors() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut paths = registries(&Context {
            root: dir.path().to_owned(),
            home: dir.path().join("none"),
            ..Context::root()
        });
        assert_eq!(
            files(&paths, "conf").expect("no file"),
            Vec::<PathBuf>::new()
        );
        paths.main_files = vec![dir.path().join("none.conf")];
        paths.ignore_main_missing = false;
        assert!(files(&paths, "conf").is_err());
        paths.main_files.clear();
        let file = dir.path().join("file");
        std::fs::write(&file, "").expect("a file");
        paths.drop_in_dirs = vec![file.clone()];
        assert!(files(&paths, "conf").is_err());
        paths.drop_in_dirs.clear();
        paths.extra_override = Some(dir.path().join("none"));
        assert!(files(&paths, "conf").is_err());
        paths.extra_override = Some(file.clone());
        assert_eq!(files(&paths, "conf").expect("the file"), [file]);
    }
}
