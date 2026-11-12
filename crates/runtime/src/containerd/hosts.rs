//! containerd: the mirror as a `hosts.toml` entry (D14, D32, D56, D82).
//!
//! `config_path` names directories, one per registry, each with a `hosts.toml` whose `[host."<url>"]` tables are the
//! endpoints containerd tries, in file order (`core/remotes/docker/config/hosts.go`, containerd v2.4.2). `configure`
//! puts the mirror's table first in every `hosts.toml` under `config_path`, and in a `_default/hosts.toml` of its own
//! for the registries that have no directory. Its tables are recognised by a `ca` under the mirror's directory, never
//! by their address (D56).

use std::io;
use std::path::{Path, PathBuf};

use toml_edit::{Array, DocumentMut, Item, Key, Table, TableLike, value};

use crate::wiring::{Error, io_at};

/// The directory of the registries that have none of their own (`hosts.go`, `hostPaths`).
pub const DEFAULT_DIR: &str = "_default";

/// The comment above the mirror's table.
const MARKER: &str = "# Added by `speculaire configure`; `speculaire unconfigure` removes it.";

/// The mirror's table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The table's name, `https://<mirror.address>`.
    pub url: String,
    /// `ca`: the mirror's CA certificate.
    pub ca: PathBuf,
    /// `client`: the client certificate and its key, in one PEM.
    pub client: PathBuf,
}

/// A `hosts.toml` that cannot be edited.
#[derive(Debug, thiserror::Error)]
pub enum EditError {
    /// The text is not TOML.
    #[error("{0}")]
    Parse(#[from] toml_edit::TomlError),
    /// `host` is not a table.
    #[error("`host` is not a table")]
    NotATable,
    /// A key is `host` in another case, which containerd reads as `host` too: it cannot tell which one to edit.
    #[error("`{0}` is `host` in another case: containerd reads both, so no edit is safe")]
    Cased(String),
    /// A table is named like the mirror's address, and its `ca` is not in the mirror's directory.
    #[error("`host.\"{0}\"` is not the mirror's: its `ca` is not in the mirror directory")]
    Taken(String),
}

/// `text` with the mirror's table first: added when there is none, or made equal to `entry` when there is one.
///
/// Another table of the file is never touched, and neither is its position, comments or spacing. Of several tables
/// with a `ca` in the mirror's directory, the first stays and the others go.
///
/// # Errors
///
/// When `text` is not a `hosts.toml` that can be edited.
pub fn add(text: &str, entry: &Entry, mirror_dir: &Path) -> Result<String, EditError> {
    let mut doc: DocumentMut = text.parse()?;
    let own = own_urls(&doc, mirror_dir)?;
    let host = host_table(&mut doc)?;
    if let Some((first, extra)) = own.split_first() {
        for url in extra {
            host.remove(url);
        }
        if *first != entry.url {
            rename(host, first, &entry.url);
        }
        if let Some(table) = host.get_mut(&entry.url).and_then(Item::as_table_like_mut) {
            set_fields(table, entry);
        }
    } else {
        if host.contains_key(&entry.url) {
            return Err(EditError::Taken(entry.url.clone()));
        }
        let mut table = Table::new();
        table.decor_mut().set_prefix(format!("\n{MARKER}\n"));
        // Parsed tables are numbered from 0 up.
        table.set_position(Some(-1));
        set_fields(&mut table, entry);
        host.insert(&entry.url, Item::Table(table));
    }
    Ok(tidy(doc.to_string()))
}

/// Renames the table `old` of `host` to `new`, in the same place and with the comments it had.
fn rename(host: &mut Table, old: &str, new: &str) {
    let Some((old_key, item)) = host.remove_entry(old) else {
        return;
    };
    let mut key = Key::new(new);
    *key.leaf_decor_mut() = old_key.leaf_decor().clone();
    *key.dotted_decor_mut() = old_key.dotted_decor().clone();
    let position = item.as_table().and_then(Table::position);
    host.insert_formatted(&key, item);
    if let Some(table) = host.get_mut(new).and_then(Item::as_table_mut) {
        table.set_position(position);
    }
}

/// `text` without the tables of the mirror, and nothing else changed.
///
/// # Errors
///
/// When `text` is not a `hosts.toml` that can be edited.
pub fn remove(text: &str, mirror_dir: &Path) -> Result<String, EditError> {
    let mut doc: DocumentMut = text.parse()?;
    let own = own_urls(&doc, mirror_dir)?;
    if own.is_empty() {
        return Ok(text.to_owned());
    }
    let host = host_table(&mut doc)?;
    for url in &own {
        host.remove(url);
    }
    // `[host]` that held only the mirror's tables prints nothing once it is implicit and empty.
    if host.is_empty() {
        host.set_implicit(true);
    }
    Ok(tidy(doc.to_string()))
}

/// Whether `text` has no `[host]` content at all: nothing a `hosts.toml` could say, but blank lines.
#[must_use]
pub fn is_blank(text: &str) -> bool {
    text.trim().is_empty()
}

/// The names of the `[host.*]` tables whose `ca` is in `mirror_dir`.
fn own_urls(doc: &DocumentMut, mirror_dir: &Path) -> Result<Vec<String>, EditError> {
    if let Some((key, _)) = doc
        .iter()
        .find(|(key, _)| *key != "host" && key.eq_ignore_ascii_case("host"))
    {
        return Err(EditError::Cased(key.to_owned()));
    }
    let Some(host) = doc.get("host") else {
        return Ok(Vec::new());
    };
    let host = host.as_table_like().ok_or(EditError::NotATable)?;
    Ok(host
        .iter()
        .filter(|(_, item)| is_own(item, mirror_dir))
        .map(|(url, _)| url.to_owned())
        .collect())
}

fn is_own(item: &Item, mirror_dir: &Path) -> bool {
    item.as_table_like()
        .and_then(|table| table.get("ca"))
        .and_then(Item::as_str)
        .is_some_and(|ca| Path::new(ca).starts_with(mirror_dir))
}

/// The `host` table, made if the document has none.
fn host_table(doc: &mut DocumentMut) -> Result<&mut Table, EditError> {
    if doc.get("host").is_none() {
        let mut table = Table::new();
        table.set_implicit(true);
        doc.insert("host", Item::Table(table));
    }
    doc.get_mut("host")
        .and_then(Item::as_table_mut)
        .ok_or(EditError::NotATable)
}

fn set_fields(table: &mut dyn TableLike, entry: &Entry) {
    let mut set = |key: &str, new: Item| {
        let same = table
            .get(key)
            .is_some_and(|old| old.to_string().trim() == new.to_string().trim());
        if !same {
            // `insert` keeps the position of a key that exists, and the comments around it.
            let decor = table.key(key).map(|k| k.leaf_decor().clone());
            table.insert(key, new);
            if let (Some(decor), Some(mut k)) = (decor, table.key_mut(key)) {
                *k.leaf_decor_mut() = decor;
            }
        }
    };
    set("capabilities", value(Array::from_iter(["pull"])));
    set("ca", value(entry.ca.to_string_lossy().into_owned()));
    set("client", value(entry.client.to_string_lossy().into_owned()));
    set("dial_timeout", value("200ms"));
    for key in ["capabilities", "ca", "client", "dial_timeout"] {
        if let Some(mut k) = table.key_mut(key)
            && k.leaf_decor().prefix().is_none()
        {
            k.leaf_decor_mut().set_prefix("  ");
        }
    }
}

/// A file that starts with a blank line loses it: the mirror's table, first in an otherwise empty document, has one.
fn tidy(text: String) -> String {
    text.strip_prefix('\n').map(str::to_owned).unwrap_or(text)
}

/// A `hosts.toml` of the directories of `config_path`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// The file.
    pub path: PathBuf,
    /// Whether it exists.
    pub exists: bool,
}

/// What `configure` leaves alone, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    /// The directory.
    pub dir: PathBuf,
    /// Why.
    pub reason: &'static str,
}

/// The `hosts.toml` files `configure` edits under `roots`, the directories of `config_path` in order, and the
/// directories it leaves alone.
///
/// Every non-empty `hosts.toml` of a directory is a target. A directory with none is read by containerd as
/// certificate files, which a `hosts.toml` would replace, so it is left alone. The first root's `_default` is a
/// target as well, to be created when it holds nothing (D82).
///
/// # Errors
///
/// When a directory cannot be listed: the error names it.
pub fn targets(roots: &[PathBuf]) -> Result<(Vec<Target>, Vec<Skipped>), Error> {
    let mut targets = Vec::new();
    let mut skipped = Vec::new();
    for root in roots {
        let mut dirs = match std::fs::read_dir(root) {
            Ok(entries) => entries
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<io::Result<Vec<_>>>()
                .map_err(io_at(root))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(io_at(root)(e)),
        };
        dirs.sort();
        for dir in dirs.into_iter().filter(|dir| dir.is_dir()) {
            let file = dir.join("hosts.toml");
            if std::fs::metadata(&file).is_ok_and(|meta| meta.len() > 0) {
                targets.push(Target {
                    path: file,
                    exists: true,
                });
            } else if dir.file_name().is_none_or(|name| name != DEFAULT_DIR) {
                skipped.push(Skipped {
                    dir,
                    reason: "has no hosts.toml: containerd reads its certificate files, which a hosts.toml would replace",
                });
            }
        }
    }
    if let Some(root) = roots.first() {
        let dir = root.join(DEFAULT_DIR);
        let file = dir.join("hosts.toml");
        if !targets.iter().any(|t| t.path == file) {
            let alone = match std::fs::read_dir(&dir) {
                Ok(mut entries) => entries.next().is_none(),
                Err(e) if e.kind() == io::ErrorKind::NotFound => true,
                Err(e) => return Err(io_at(&dir)(e)),
            };
            if alone || std::fs::metadata(&file).is_ok() {
                targets.push(Target {
                    path: file,
                    exists: false,
                });
            } else {
                skipped.push(Skipped {
                    dir,
                    reason: "has files but no hosts.toml: containerd reads them as certificate files, which a hosts.toml would replace",
                });
            }
        }
    }
    Ok((targets, skipped))
}

#[cfg(test)]
mod tests {
    use speculaire_registry_config::containerd::hosts::parse_hosts_file;

    use super::*;

    const DIR: &str = "/var/lib/speculaire/mirror";

    /// The examples of containerd's `docs/hosts.md` (v2.4.2), and files in the styles admins write.
    const FILES: [(&str, &str); 7] = [
        ("empty", ""),
        (
            "docker-io",
            "server = \"https://docker.io\"\n\n[host.\"https://registry-1.docker.io\"]\n  capabilities = [\"pull\", \"resolve\"]\n",
        ),
        (
            "commented-hosts",
            "# registry config for docker.io\n\nserver = \"https://registry-1.docker.io\"    # default: https://docker.io\n\n[host.\"https://public-mirror.example.com\"]\n  capabilities = [\"pull\"]  # default: [\"pull\", \"resolve\"]\n\n# The internal mirror.\n[host.\"https://docker-mirror.internal\"]\n  capabilities = [\"pull\", \"resolve\"]\n  ca = \"docker-mirror.crt\"  # or absolute path\n  skip_verify = false\n",
        ),
        (
            "comment-before-first-table",
            "# mirrors of registry.k8s.io\n[host.\"https://mirror-a.example\"]\n  capabilities = [\"pull\"]\n[host.\"https://mirror-b.example\"]\n  capabilities = [\"pull\"]\n",
        ),
        (
            "server-only",
            "server = \"https://registry.example:5000\"\nca = \"/etc/ssl/registry.crt\"\n",
        ),
        (
            "explicit-host-table",
            "[host]\n[host.\"https://mirror.example\"]\n  capabilities = [\"pull\"]\n",
        ),
        (
            "dotted-keys",
            "[host.\"https://mirror.example\"]\ncapabilities = [\"pull\"]\nheader.x-token = \"abc\"\n",
        ),
    ];

    fn entry(address: &str) -> Entry {
        Entry {
            url: format!("https://{address}"),
            ca: PathBuf::from(format!("{DIR}/ca.crt")),
            client: PathBuf::from(format!("{DIR}/client.pem")),
        }
    }

    fn added(text: &str) -> String {
        add(text, &entry("127.0.0.1:7480"), Path::new(DIR)).unwrap()
    }

    #[test]
    fn the_entry_goes_first_whatever_the_file_looks_like() {
        for (name, text) in FILES {
            let out = added(text);
            insta::assert_snapshot!(name, out);
            // containerd reads the mirror first, and the admin's hosts after it, in their order.
            let hosts = parse_hosts_file(Path::new("/dir"), &out).unwrap();
            let before = parse_hosts_file(Path::new("/dir"), text).unwrap();
            assert_eq!(hosts[0].host, "127.0.0.1:7480", "{name}");
            assert_eq!(hosts[0].scheme, "https", "{name}");
            assert_eq!(
                hosts[1..].iter().map(|h| &h.host).collect::<Vec<_>>(),
                before.iter().map(|h| &h.host).collect::<Vec<_>>(),
                "{name}"
            );
            assert_eq!(
                hosts[0].ca(),
                [PathBuf::from(format!("{DIR}/ca.crt"))],
                "{name}"
            );
        }
    }

    #[test]
    fn adding_twice_changes_nothing_and_removing_restores_the_file() {
        for (name, text) in FILES {
            let once = added(text);
            assert_eq!(added(&once), once, "{name}: a second add");
            assert_eq!(
                remove(&once, Path::new(DIR)).unwrap(),
                text,
                "{name}: add, then remove"
            );
            assert_eq!(remove(text, Path::new(DIR)).unwrap(), text, "{name}");
        }
    }

    #[test]
    fn a_new_address_rewrites_the_entry_in_place_and_keeps_what_follows() {
        for (name, text) in FILES {
            let once = added(text);
            let moved = add(&once, &entry("127.0.0.1:7481"), Path::new(DIR)).unwrap();
            assert_eq!(
                moved,
                once.replace("127.0.0.1:7480", "127.0.0.1:7481"),
                "{name}"
            );
            // Tables of the admin are never touched, even with the address of the mirror in them.
            assert_eq!(remove(&moved, Path::new(DIR)).unwrap(), text, "{name}");
        }
    }

    #[test]
    fn an_edited_entry_is_made_equal_again_and_extra_ones_go() {
        let once = added(FILES[2].1);
        let edited = once
            .replace(
                "capabilities = [\"pull\"]\n  ca = \"/var",
                "capabilities = [\"pull\", \"resolve\"]\n  ca = \"/var",
            )
            .replace("dial_timeout = \"200ms\"", "dial_timeout = \"5s\"");
        assert_ne!(edited, once);
        assert_eq!(added(&edited), once);
        let twice = format!("{once}\n[host.\"https://127.0.0.1:7999\"]\n  ca = \"{DIR}/ca.crt\"\n");
        assert_eq!(added(&twice), once);
        assert_eq!(remove(&twice, Path::new(DIR)).unwrap(), FILES[2].1);
    }

    #[test]
    fn only_a_ca_in_the_mirror_directory_makes_a_table_the_mirrors() {
        let admin = "[host.\"https://127.0.0.1:7480\"]\n  capabilities = [\"pull\"]\n  ca = \"/etc/other/ca.crt\"\n";
        let taken = add(admin, &entry("127.0.0.1:7480"), Path::new(DIR)).unwrap_err();
        assert!(
            matches!(&taken, EditError::Taken(url) if url == "https://127.0.0.1:7480"),
            "{taken}"
        );
        assert_eq!(remove(admin, Path::new(DIR)).unwrap(), admin);
    }

    #[test]
    fn a_host_key_in_another_case_is_refused() {
        let text = "[host]\n[Host.\"https://mirror.example\"]\n  capabilities = [\"pull\"]\n";
        for result in [
            add(text, &entry("127.0.0.1:7480"), Path::new(DIR)),
            remove(text, Path::new(DIR)),
        ] {
            assert!(
                matches!(&result, Err(EditError::Cased(key)) if key == "Host"),
                "{result:?}"
            );
        }
    }

    #[test]
    fn a_file_that_is_not_a_hosts_toml_is_an_error() {
        let bad = add("[host\n", &entry("127.0.0.1:7480"), Path::new(DIR)).unwrap_err();
        assert!(bad.to_string().contains("line 1"), "{bad}");
        assert!(matches!(
            add("host = 1\n", &entry("127.0.0.1:7480"), Path::new(DIR)),
            Err(EditError::NotATable)
        ));
        assert!(remove("[host\n", Path::new(DIR)).is_err());
        assert!(is_blank("\n  \n") && !is_blank("# comment\n"));
    }

    #[test]
    fn targets_are_every_hosts_toml_and_the_default_to_create() {
        let dir = tempfile::tempdir().unwrap();
        let (first, second) = (dir.path().join("a"), dir.path().join("b"));
        for (root, name, file) in [
            (&first, "docker.io", Some("x")),
            (&first, "quay.io", Some("")),
            (&first, "empty-hosts", Some("empty")),
            (&first, "certs-only", None),
            (&second, "ghcr.io", Some("y")),
            (&second, "_default", Some("z")),
        ] {
            let sub = root.join(name);
            std::fs::create_dir_all(&sub).unwrap();
            match file {
                Some("") | None => std::fs::write(sub.join("ca.crt"), "").unwrap(),
                Some("empty") => std::fs::write(sub.join("hosts.toml"), "").unwrap(),
                Some(text) => std::fs::write(sub.join("hosts.toml"), text).unwrap(),
            }
        }
        std::fs::write(first.join("not-a-dir"), "").unwrap();
        let roots = [first.clone(), second.clone(), dir.path().join("missing")];
        let (targets, skipped) = targets(&roots).unwrap();
        let paths: Vec<_> = targets.iter().map(|t| (t.path.clone(), t.exists)).collect();
        assert_eq!(
            paths,
            [
                (first.join("docker.io/hosts.toml"), true),
                (second.join("_default/hosts.toml"), true),
                (second.join("ghcr.io/hosts.toml"), true),
                (first.join("_default/hosts.toml"), false),
            ]
        );
        let names: Vec<_> = skipped.iter().map(|s| s.dir.clone()).collect();
        assert_eq!(
            names,
            [
                first.join("certs-only"),
                first.join("empty-hosts"),
                first.join("quay.io")
            ]
        );
    }

    #[test]
    fn a_root_or_a_default_that_cannot_be_listed_is_an_error_naming_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, "").unwrap();
        let failed = |roots: &[PathBuf]| match targets(roots) {
            Err(Error::Io { path, .. }) => path,
            other => panic!("{other:?}"),
        };
        assert_eq!(failed(&[root.clone(), file.clone()]), file);
        std::fs::write(root.join("_default"), "").unwrap();
        assert_eq!(failed(std::slice::from_ref(&root)), root.join("_default"));
    }

    #[test]
    fn the_default_directory_is_left_alone_when_it_holds_certificate_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("certs.d");
        std::fs::create_dir_all(root.join("_default")).unwrap();
        std::fs::write(root.join("_default/ca.crt"), "").unwrap();
        let (found, skipped) = targets(std::slice::from_ref(&root)).unwrap();
        assert_eq!(found, []);
        assert_eq!(skipped[0].dir, root.join("_default"));
        // An empty `_default`, and a missing root, are to be created.
        std::fs::remove_file(root.join("_default/ca.crt")).unwrap();
        assert_eq!(targets(std::slice::from_ref(&root)).unwrap().0.len(), 1);
        std::fs::remove_dir_all(&root).unwrap();
        let (found, _) = targets(std::slice::from_ref(&root)).unwrap();
        assert_eq!(found[0].path, root.join("_default/hosts.toml"));
        assert!(!found[0].exists);
    }
}
