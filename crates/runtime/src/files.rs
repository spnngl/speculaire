//! Files written whole, by temporary file and rename (D55).

use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// What a write or removal did to a file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// The file did not exist.
    Created(PathBuf),
    /// The file's contents or mode changed.
    Updated(PathBuf),
    /// The file is gone.
    Removed(PathBuf),
}

impl Change {
    /// The file.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Created(path) | Self::Updated(path) | Self::Removed(path) => path,
        }
    }
}

impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (verb, path) = match self {
            Self::Created(path) => ("created", path),
            Self::Updated(path) => ("updated", path),
            Self::Removed(path) => ("removed", path),
        };
        write!(f, "{verb} {}", path.display())
    }
}

/// Makes `path` hold `contents` with permission bits `mode`, or reports that it already does.
///
/// The contents go to a temporary file in the same directory, which gets `mode` and is renamed over `path`: a reader
/// sees the old file or the new one whole, and a file that existed with a looser mode ends with `mode` (D55). Missing
/// directories are made with mode 0755.
///
/// # Errors
///
/// When the directory cannot be made, or the file cannot be written, set or renamed.
pub fn write(path: &Path, contents: &[u8], mode: u32) -> io::Result<Option<Change>> {
    // A symlink, as config management makes of a config file, is written through, not replaced.
    let target = std::fs::canonicalize(path).ok();
    let real = target.as_deref().unwrap_or(path);
    // A file that cannot be looked at is written as if new: the write then fails, or replaces it.
    let existing = std::fs::metadata(real).ok();
    if let Some(meta) = &existing
        && meta.is_file()
        && meta.mode() & 0o7777 == mode
        && std::fs::read(real)? == contents
    {
        return Ok(None);
    }
    let dir = real.parent().unwrap_or_else(|| Path::new("."));
    make_dir(dir)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".speculaire-")
        .tempfile_in(dir)?;
    temporary.write_all(contents)?;
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))?;
    temporary.as_file().sync_all()?;
    temporary.persist(real).map_err(|e| e.error)?;
    Ok(Some(if existing.is_some() {
        Change::Updated(path.to_owned())
    } else {
        Change::Created(path.to_owned())
    }))
}

/// [`write()`], keeping the mode the file has when it exists: `default_mode` is for a new one.
///
/// # Errors
///
/// As [`write()`].
pub fn write_keeping_mode(
    path: &Path,
    contents: &[u8],
    default_mode: u32,
) -> io::Result<Option<Change>> {
    let mode = std::fs::metadata(path).map_or(default_mode, |meta| meta.mode() & 0o7777);
    write(path, contents, mode)
}

/// Makes `dir` and its missing parents, with mode 0755 whatever the umask says.
fn make_dir(dir: &Path) -> io::Result<()> {
    let missing: Vec<&Path> = dir
        .ancestors()
        .take_while(|path| !path.as_os_str().is_empty() && !path.exists())
        .collect();
    for path in missing.into_iter().rev() {
        std::fs::create_dir(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

/// Removes `path`, or reports that it was not there.
///
/// # Errors
///
/// When the file exists and cannot be removed.
pub fn remove(path: &Path) -> io::Result<Option<Change>> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(Some(Change::Removed(path.to_owned()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Removes `dir` when it is empty. A directory that is missing, or has something in it, stays as it is.
///
/// # Errors
///
/// When `dir` cannot be removed for another reason.
pub fn remove_dir_if_empty(dir: &Path) -> io::Result<()> {
    match std::fs::remove_dir(dir) {
        Ok(()) => Ok(()),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// The text of a file, or `None` when it does not exist.
///
/// # Errors
///
/// When the file exists and cannot be read as UTF-8 text.
pub fn read(path: &Path) -> io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().mode() & 0o7777
    }

    #[test]
    fn a_file_is_created_with_its_mode_whatever_the_umask() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/key");
        assert_eq!(
            write(&path, b"secret", 0o600).unwrap(),
            Some(Change::Created(path.clone()))
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&dir.path().join("a/b")), 0o755);
        assert_eq!(mode(&dir.path().join("a")), 0o755);
    }

    #[test]
    fn writing_the_same_file_again_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.crt");
        write(&path, b"pem", 0o644).unwrap();
        let before = std::fs::metadata(&path).unwrap().ino();
        assert_eq!(write(&path, b"pem", 0o644).unwrap(), None);
        assert_eq!(
            std::fs::metadata(&path).unwrap().ino(),
            before,
            "not replaced"
        );
    }

    #[test]
    fn a_looser_mode_is_tightened_and_new_contents_replace_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.pem");
        std::fs::write(&path, "pem").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            write(&path, b"pem", 0o600).unwrap(),
            Some(Change::Updated(path.clone()))
        );
        assert_eq!(mode(&path), 0o600);
        assert_eq!(
            write(&path, b"new", 0o600).unwrap(),
            Some(Change::Updated(path.clone()))
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn a_write_leaves_no_temporary_file_and_a_reader_never_sees_half_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big");
        write(&path, &vec![b'a'; 1 << 20], 0o644).unwrap();
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["big"]);
    }

    #[test]
    fn a_symlink_is_written_through_and_a_mode_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::write(&real, "old").unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o640)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(write_keeping_mode(&link, b"new", 0o644).unwrap().is_some());
        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(std::fs::read(&real).unwrap(), b"new");
        assert_eq!(mode(&real), 0o640);
        let fresh = dir.path().join("fresh");
        write_keeping_mode(&fresh, b"x", 0o644).unwrap();
        assert_eq!(mode(&fresh), 0o644);
    }

    #[test]
    fn a_path_through_a_file_is_an_error_for_every_call_but_a_missing_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, "").unwrap();
        let through = file.join("sub");
        assert!(remove(&through).is_err());
        assert!(read(&through).is_err());
        assert!(remove_dir_if_empty(&file).is_err());
        assert!(write(&through, b"x", 0o644).is_err());
        let missing = dir.path().join("missing/sub");
        assert_eq!(remove(&missing).unwrap(), None);
        assert_eq!(read(&missing).unwrap(), None);
        remove_dir_if_empty(&missing).unwrap();
    }

    #[test]
    fn writing_into_a_directory_that_exists_makes_nothing_and_missing_ones_get_0755() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("a"), b"x", 0o600).unwrap();
        write(&dir.path().join("b/c/d"), b"x", 0o600).unwrap();
        assert_eq!(mode(&dir.path().join("b")), 0o755);
        assert_eq!(mode(&dir.path().join("b/c")), 0o755);
        write(&dir.path().join("b/c/e"), b"x", 0o600).unwrap();
        // A relative path has a parent that is empty, and that is the working directory.
        assert_eq!(make_dir(Path::new("")).ok(), Some(()));
    }

    #[test]
    fn a_directory_in_the_way_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("d");
        std::fs::create_dir(&path).unwrap();
        assert!(write(&path, b"x", 0o644).is_err());
        let file = dir.path().join("f");
        std::fs::write(&file, "").unwrap();
        assert!(write(&file.join("sub"), b"x", 0o644).is_err());
    }

    #[test]
    fn removal_reports_what_it_did() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x");
        std::fs::write(&path, "").unwrap();
        assert_eq!(remove(&path).unwrap(), Some(Change::Removed(path.clone())));
        assert_eq!(remove(&path).unwrap(), None);
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("kept"), "").unwrap();
        remove_dir_if_empty(&sub).unwrap();
        assert!(sub.exists(), "a directory with a file stays");
        std::fs::remove_file(sub.join("kept")).unwrap();
        remove_dir_if_empty(&sub).unwrap();
        remove_dir_if_empty(&sub).unwrap();
        assert!(!sub.exists());
        assert_eq!(read(&path).unwrap(), None);
        assert_eq!(Change::Removed(path.clone()).path(), path);
        assert!(Change::Created(path).to_string().starts_with("created /"));
    }
}
