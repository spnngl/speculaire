//! Registry credentials from the files CRI-O's image library reads (D66).
//!
//! Ported from go.podman.io/image v5.40.0 `pkg/docker/config/config.go`, as vendored by CRI-O v1.37.2
//! (`getAuthFilePaths`, `getPathToAuth`, `getCredentialsWithHomeDir`, `findCredentialsInFile`, `authKeyLookupOrder`,
//! `decodeDockerAuth`, `normalizeAuthFileKey`, `validateKey`), for Linux. (D25)
//!
//! An external credential helper is not run: a lookup that reaches one, from `credential-helpers` of
//! `registries.conf` or `credHelpers` of an auth file, says which ([`Lookup::Helper`]). Every secret is a
//! [`SecretString`] (D37).

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::marker::PhantomData;
use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};

use super::Context;
use super::registries::AUTHENTICATION_FILE_HELPER;
use crate::ParseError;

/// A registry login.
#[derive(Clone, Debug)]
pub struct Auth {
    /// The user name.
    pub username: String,
    /// The password.
    pub password: SecretString,
    /// The identity token of an `OAuth2` login.
    pub identity_token: SecretString,
}

impl Auth {
    fn is_empty(&self) -> bool {
        self.username.is_empty()
            && self.password.expose_secret().is_empty()
            && self.identity_token.expose_secret().is_empty()
    }
}

/// What a lookup found.
#[derive(Clone, Debug)]
pub enum Lookup {
    /// A login.
    Found(Auth),
    /// No file holds one.
    NotFound,
    /// The login lives in this external credential helper, which this does not run.
    Helper(String),
}

/// A lookup that fails.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The key is not a registry, namespace or repository.
    #[error("key {key} {reason}")]
    InvalidKey {
        /// The key.
        key: String,
        /// Why it is refused.
        reason: &'static str,
    },
    /// A credential file cannot be read.
    #[error("cannot read {}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// What failed.
        #[source]
        source: std::io::Error,
    },
    /// A credential file is not valid.
    #[error("unmarshaling JSON at {}: {source}", path.display())]
    Parse {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        #[source]
        source: ParseError,
    },
    /// The `auth` field of an entry is not base64.
    #[error("entry {key:?} of {}: auth is not base64", path.display())]
    Base64 {
        /// The file.
        path: PathBuf,
        /// The entry.
        key: String,
    },
    /// A lookup reached a credential file that [`Files::load`] could not use.
    #[error("{} could not be read or parsed when the files were loaded", path.display())]
    Unusable {
        /// The file.
        path: PathBuf,
    },
    /// Every helper failed.
    #[error("errors looking up credentials: {} failed", .0.len())]
    Helpers(Vec<Error>),
}

/// A credential file and its format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthPath {
    /// The file.
    pub path: PathBuf,
    /// The format of `~/.dockercfg`, a bare map of entries.
    pub legacy: bool,
}

#[derive(Debug, Default)]
struct Entry {
    auth: SecretString,
    identity_token: SecretString,
}

/// A credential file, parsed (`dockerConfigFile`).
#[derive(Debug, Default)]
pub struct AuthFile {
    auths: BTreeMap<String, Entry>,
    cred_helpers: BTreeMap<String, String>,
}

impl AuthFile {
    /// The entries whose `auth` is not base64: a lookup that reaches one fails.
    fn undecodable<'a>(&'a self, path: &'a AuthPath) -> impl Iterator<Item = Error> + 'a {
        self.auths
            .iter()
            .filter(|(_, entry)| base64_decode(entry.auth.expose_secret()).is_none())
            .map(|(key, _)| Error::Base64 {
                path: path.path.clone(),
                key: key.clone(),
            })
    }
}

/// Whether `key` names the field `name`, as `encoding/json` matches it: by `bytes.EqualFold`, which also folds
/// K (U+212A) to k and ſ (U+017F) to s. `name` is ASCII, its k and s lower case.
fn names(key: &str, name: &str) -> bool {
    let mut chars = key.chars();
    name.chars().all(|n| {
        chars.next().is_some_and(|c| {
            c.eq_ignore_ascii_case(&n) || matches!((c, n), ('\u{212a}', 'k') | ('\u{17f}', 's'))
        })
    }) && chars.next().is_none()
}

/// A struct as `encoding/json` fills it: each key, in the order of the text, sets the field it names; `null`
/// leaves the zero value.
trait Fields: Default {
    /// Reads the value of `key` into the field it names, or skips it.
    fn read<'de, A: MapAccess<'de>>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>;
}

fn fields<'de, D: Deserializer<'de>, T: Fields>(deserializer: D) -> Result<T, D::Error> {
    Ok(Option::<Object<T>>::deserialize(deserializer)?
        .map(|object| object.0)
        .unwrap_or_default())
}

/// The object of a [`Fields`]; [`fields`] reads `null` too.
struct Object<T>(T);

impl<'de, T: Fields> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Keys<T>(PhantomData<T>);
        impl<'de, T: Fields> Visitor<'de> for Keys<T> {
            type Value = Object<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Object<T>, A::Error> {
                let mut fields = T::default();
                while let Some(key) = map.next_key::<String>()? {
                    fields.read(&key, &mut map)?;
                }
                Ok(Object(fields))
            }
        }
        deserializer.deserialize_map(Keys(PhantomData))
    }
}

/// A string field: `null` leaves it as it is.
fn read_string<'de, A: MapAccess<'de>>(
    field: &mut impl From<String>,
    map: &mut A,
) -> Result<(), A::Error> {
    if let Some(text) = map.next_value::<Option<String>>()? {
        *field = text.into();
    }
    Ok(())
}

/// A map field: `null` empties it, and an object adds its entries, a `null` one as the zero value.
fn read_map<'de, A: MapAccess<'de>, V: Deserialize<'de> + Default>(
    field: &mut BTreeMap<String, V>,
    map: &mut A,
) -> Result<(), A::Error> {
    match map.next_value::<Option<BTreeMap<String, Option<V>>>>()? {
        None => field.clear(),
        Some(entries) => field.extend(
            entries
                .into_iter()
                .map(|(key, value)| (key, value.unwrap_or_default())),
        ),
    }
    Ok(())
}

impl Fields for Entry {
    fn read<'de, A: MapAccess<'de>>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error> {
        let field = if names(key, "auth") {
            &mut self.auth
        } else if names(key, "identitytoken") {
            &mut self.identity_token
        } else {
            return map.next_value::<IgnoredAny>().map(drop);
        };
        read_string(field, map)
    }
}

impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        fields(deserializer)
    }
}

impl Fields for AuthFile {
    fn read<'de, A: MapAccess<'de>>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error> {
        if names(key, "auths") {
            read_map(&mut self.auths, map)
        } else if names(key, "credHelpers") {
            read_map(&mut self.cred_helpers, map)
        } else {
            map.next_value::<IgnoredAny>().map(drop)
        }
    }
}

/// Parses a credential file (`authPath.parse`); `legacy` is the format of `~/.dockercfg`.
///
/// # Errors
///
/// When the text is not JSON of the expected shape: a map of entries, with string `auth` and `identitytoken`.
pub fn parse_auth_file(text: &str, legacy: bool) -> Result<AuthFile, ParseError> {
    let mut json = serde_json::Deserializer::from_str(text);
    let file = if legacy {
        Option::<BTreeMap<String, Entry>>::deserialize(&mut json).map(|auths| AuthFile {
            auths: auths.unwrap_or_default(),
            cred_helpers: BTreeMap::new(),
        })
    } else {
        fields(&mut json)
    };
    file.and_then(|file| json.end().map(|()| file))
        .map_err(|e| ParseError::new("", e.to_string()).at(e.line(), e.column()))
}

/// `getPathToAuth` on Linux: the file `ctx` names and whether it was named, or the per-user default.
fn path_to_auth(ctx: &Context) -> Result<(AuthPath, bool), String> {
    let plain = |path: PathBuf| AuthPath {
        path,
        legacy: false,
    };
    if let Some(path) = ctx
        .auth_file
        .as_ref()
        .filter(|path| !path.as_os_str().is_empty())
    {
        return Ok((plain(path.clone()), true));
    }
    if !ctx.root.as_os_str().is_empty() {
        return Ok((
            plain(ctx.under_root(&format!("/run/containers/{}/auth.json", ctx.uid))),
            false,
        ));
    }
    if let Some(runtime) = ctx
        .xdg_runtime_dir
        .as_ref()
        .filter(|dir| !dir.as_os_str().is_empty())
    {
        return match std::fs::metadata(runtime) {
            Err(e) if e.kind() == ErrorKind::NotFound => Err(format!(
                "{} directory set by $XDG_RUNTIME_DIR does not exist. Either create the directory or unset $XDG_RUNTIME_DIR.",
                runtime.display()
            )),
            _ => Ok((plain(runtime.join("containers/auth.json")), false)),
        };
    }
    Ok((
        plain(PathBuf::from(format!(
            "/run/containers/{}/auth.json",
            ctx.uid
        ))),
        false,
    ))
}

/// `getAuthFilePaths`: the files to search, in order; some may not exist. A `$XDG_RUNTIME_DIR` that does not exist is
/// logged and skipped, as the library does.
#[must_use]
pub fn auth_file_paths(ctx: &Context) -> Vec<AuthPath> {
    let mut paths = Vec::new();
    let user_specified = match path_to_auth(ctx) {
        Ok((path, user_specified)) => {
            paths.push(path);
            user_specified
        }
        Err(message) => {
            tracing::warn!(%message, "no per-user credential file");
            false
        }
    };
    if !user_specified {
        let config_home = ctx
            .xdg_config_home
            .clone()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or_else(|| ctx.home.join(".config"));
        paths.push(AuthPath {
            path: config_home.join("containers/auth.json"),
            legacy: false,
        });
        let docker = match ctx
            .docker_config
            .as_ref()
            .filter(|dir| !dir.as_os_str().is_empty())
        {
            Some(dir) => dir.join("config.json"),
            None => ctx.home.join(".docker/config.json"),
        };
        paths.push(AuthPath {
            path: docker,
            legacy: false,
        });
        paths.push(AuthPath {
            path: ctx.home.join(".dockercfg"),
            legacy: true,
        });
    }
    paths
}

/// `validateKey`: a registry, a namespace or a repository, without scheme, tag or digest.
fn validate_key(key: &str) -> Result<(), Error> {
    let refuse = |reason| {
        Err(Error::InvalidKey {
            key: key.to_owned(),
            reason,
        })
    };
    if key.starts_with("http://") || key.starts_with("https://") {
        return refuse("contains http[s]:// prefix");
    }
    if key.contains('@') {
        return refuse("contains a '@' character");
    }
    if key
        .split_once('/')
        .is_some_and(|(_, rest)| rest.contains(':'))
    {
        return refuse("contains a ':' character after host[:port]");
    }
    Ok(())
}

/// `normalizeRegistry`.
fn normalize_registry(registry: &str) -> &str {
    match registry {
        "registry-1.docker.io" | "docker.io" => "index.docker.io",
        other => other,
    }
}

/// `normalizeAuthFileKey`: a key as a host name, normalized.
fn normalize_auth_file_key(key: &str, legacy: bool) -> &str {
    let stripped = key.strip_prefix("http://").unwrap_or(key);
    let stripped = stripped.strip_prefix("https://").unwrap_or(stripped);
    let stripped = if legacy || stripped.len() != key.len() {
        stripped.split('/').next().unwrap_or_default()
    } else {
        stripped
    };
    normalize_registry(stripped)
}

/// `authKeyLookupOrder`: the key, then each namespace above it, down to the registry; a legacy file only the registry.
fn key_lookup_order<'a>(key: &'a str, registry: &'a str, legacy: bool) -> Vec<&'a str> {
    if legacy {
        return vec![registry];
    }
    let mut keys = vec![key];
    let mut key = key;
    while let Some(slash) = key.rfind('/') {
        key = &key[..slash];
        keys.push(key);
    }
    keys
}

/// Go's `base64.StdEncoding.DecodeString`: padded, and blind to line breaks.
pub(crate) fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let data: Vec<u8> = text
        .bytes()
        .filter(|b| *b != b'\r' && *b != b'\n')
        .collect();
    if !data.len().is_multiple_of(4) {
        return None;
    }
    let value = |b: u8| match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let mut out = Vec::with_capacity(data.len() / 4 * 3);
    let quads = data.len() / 4;
    #[expect(
        clippy::chunks_exact_to_as_chunks,
        reason = "a trailing partial chunk was refused above"
    )]
    for (i, quad) in data.chunks_exact(4).enumerate() {
        let padding = quad.iter().rev().take_while(|b| **b == b'=').count();
        if padding > 2 || (padding > 0 && i + 1 != quads) {
            return None;
        }
        let mut bits = 0u32;
        for b in &quad[..4 - padding] {
            bits = (bits << 6) + u32::from(value(*b)?);
        }
        bits <<= 6 * padding;
        let bytes = bits.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - padding]);
    }
    Some(out)
}

/// `decodeDockerAuth`: the login of an entry; none when its `auth` has no `:`.
fn decode(path: &AuthPath, key: &str, entry: &Entry) -> Result<Lookup, Error> {
    let decoded = base64_decode(entry.auth.expose_secret()).ok_or_else(|| Error::Base64 {
        path: path.path.clone(),
        key: key.to_owned(),
    })?;
    let decoded = String::from_utf8_lossy(&decoded);
    let Some((user, password)) = decoded.split_once(':') else {
        return Ok(Lookup::NotFound);
    };
    Ok(Lookup::Found(Auth {
        username: user.to_owned(),
        password: password.trim_matches('\0').to_owned().into(),
        identity_token: entry.identity_token.clone(),
    }))
}

/// `findCredentialsInFile`.
fn find_in_file(key: &str, registry: &str, path: &AuthPath) -> Result<Lookup, Error> {
    find_in_parsed(key, registry, path, &read_auth_file(path)?)
}

/// `findCredentialsInFile` on a file already read.
fn find_in_parsed(
    key: &str,
    registry: &str,
    path: &AuthPath,
    file: &AuthFile,
) -> Result<Lookup, Error> {
    if let Some(helper) = file.cred_helpers.get(registry) {
        return Ok(Lookup::Helper(helper.clone()));
    }
    for candidate in key_lookup_order(key, registry, path.legacy) {
        if let Some(entry) = file.auths.get(candidate) {
            return decode(path, candidate, entry);
        }
    }
    // Entries written as URLs, or with the Docker Hub's special name.
    let registry = normalize_registry(registry);
    for (candidate, entry) in &file.auths {
        if normalize_auth_file_key(candidate, path.legacy) == registry {
            return decode(path, candidate, entry);
        }
    }
    Ok(Lookup::NotFound)
}

/// `authPath.parse`: a missing file is an empty one.
fn read_auth_file(path: &AuthPath) -> Result<AuthFile, Error> {
    let bytes = match std::fs::read(&path.path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(AuthFile::default()),
        Err(source) => {
            return Err(Error::Read {
                path: path.path.clone(),
                source,
            });
        }
    };
    parse_auth_file(&String::from_utf8_lossy(&bytes), path.legacy).map_err(|source| Error::Parse {
        path: path.path.clone(),
        source,
    })
}

/// `GetCredentials`: the login for `key`, a registry, a namespace or a repository (`docker.io`,
/// `quay.io/org`, `localhost:5000/app`), from the first helper of `helpers` that has one. The helper
/// [`AUTHENTICATION_FILE_HELPER`] searches [`auth_file_paths`].
///
/// # Errors
///
/// When the key is invalid, or every helper fails and none finds a login.
pub fn credentials(ctx: &Context, helpers: &[String], key: &str) -> Result<Lookup, Error> {
    lookup(helpers, key, |key, registry| {
        search_files(ctx, key, registry)
    })
}

/// The credential files of a [`Context`], parsed once, so that a reader can hold the logins of a moment (D91). A file
/// that is not valid is kept as one that fails the lookups that reach it (D92).
#[derive(Debug, Default)]
pub struct Files(Vec<(AuthPath, Option<AuthFile>)>);

impl Files {
    /// Reads [`auth_file_paths`]; a file that does not exist is an empty one.
    ///
    /// A file that cannot be read or is not valid does not fail the whole: its [`Error`] is returned beside the files,
    /// with those of the entries whose `auth` is not base64. A lookup that reaches such a file or entry fails as
    /// [`credentials`] does, and one that is answered before it is not affected.
    #[must_use]
    pub fn load(ctx: &Context) -> (Self, Vec<Error>) {
        let mut problems = Vec::new();
        let files = auth_file_paths(ctx)
            .into_iter()
            .map(|path| match read_auth_file(&path) {
                Ok(file) => {
                    problems.extend(file.undecodable(&path));
                    (path, Some(file))
                }
                Err(error) => {
                    problems.push(error);
                    (path, None)
                }
            })
            .collect();
        (Self(files), problems)
    }

    /// [`credentials`] over the parsed files.
    ///
    /// # Errors
    ///
    /// As [`credentials`].
    pub fn credentials(&self, helpers: &[String], key: &str) -> Result<Lookup, Error> {
        lookup(helpers, key, |key, registry| {
            for (path, file) in &self.0 {
                let Some(file) = file else {
                    return Err(Error::Unusable {
                        path: path.path.clone(),
                    });
                };
                match find_in_parsed(key, registry, path, file)? {
                    Lookup::Found(auth) if auth.is_empty() => {}
                    Lookup::NotFound => {}
                    found => return Ok(found),
                }
            }
            Ok(Lookup::NotFound)
        })
    }
}

fn lookup(
    helpers: &[String],
    key: &str,
    mut search_files: impl FnMut(&str, &str) -> Result<Lookup, Error>,
) -> Result<Lookup, Error> {
    validate_key(key)?;
    let registry = key.split('/').next().unwrap_or(key);
    let mut errors = Vec::new();
    for helper in helpers {
        if helper != AUTHENTICATION_FILE_HELPER {
            return Ok(Lookup::Helper(helper.clone()));
        }
        match search_files(key, registry) {
            Ok(Lookup::NotFound) => {}
            Ok(found) => return Ok(found),
            Err(e) => errors.push(e),
        }
    }
    if errors.is_empty() {
        Ok(Lookup::NotFound)
    } else {
        Err(Error::Helpers(errors))
    }
}

fn search_files(ctx: &Context, key: &str, registry: &str) -> Result<Lookup, Error> {
    for path in auth_file_paths(ctx) {
        match find_in_file(key, registry, &path)? {
            Lookup::Found(auth) if auth.is_empty() => {}
            Lookup::NotFound => {}
            found => return Ok(found),
        }
    }
    Ok(Lookup::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &std::path::Path, path: &str, text: &str) {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
        std::fs::write(path, text).expect("a file");
    }

    fn context(root: &std::path::Path) -> Context {
        Context {
            root: root.to_owned(),
            home: root.join("home"),
            ..Context::root()
        }
    }

    fn files() -> Vec<String> {
        vec![AUTHENTICATION_FILE_HELPER.to_owned()]
    }

    fn found(lookup: Result<Lookup, Error>) -> Option<(String, String, String)> {
        match lookup.expect("a lookup") {
            Lookup::Found(auth) => Some((
                auth.username,
                auth.password.expose_secret().to_owned(),
                auth.identity_token.expose_secret().to_owned(),
            )),
            _ => None,
        }
    }

    #[test]
    fn base64_is_padded_and_blind_to_line_breaks() {
        assert_eq!(base64_decode("dXNlcjpwYXNz"), Some(b"user:pass".to_vec()));
        assert_eq!(base64_decode("dXNlcjpwdw=="), Some(b"user:pw".to_vec()));
        assert_eq!(base64_decode("dXNlcjpwYQ=="), Some(b"user:pa".to_vec()));
        assert_eq!(base64_decode("YWI="), Some(b"ab".to_vec()));
        assert_eq!(
            base64_decode("dXNl\r\ncjpw\nYXNz"),
            Some(b"user:pass".to_vec())
        );
        assert_eq!(base64_decode(""), Some(Vec::new()));
        assert_eq!(base64_decode("+/+/"), Some(vec![0xfb, 0xff, 0xbf]));
        assert_eq!(base64_decode("Pz8/"), Some(b"???".to_vec()));
        for bad in [
            "dXNlcjpwYXN",
            "dXN=cjpw",
            "====",
            "A===",
            "dXNl!jpw",
            "dXNlcjpwYXNz=",
            "YQ==YQ==",
        ] {
            assert_eq!(base64_decode(bad), None, "{bad}");
        }
    }

    #[test]
    fn keys_are_registries_namespaces_or_repositories() {
        for key in [
            "docker.io",
            "quay.io/org",
            "localhost:5000",
            "localhost:5000/app/img",
        ] {
            assert!(validate_key(key).is_ok(), "{key}");
        }
        for key in [
            "https://docker.io",
            "http://x",
            "a.io/x@sha256:00",
            "a.io/x:tag",
        ] {
            assert!(
                matches!(validate_key(key), Err(Error::InvalidKey { .. })),
                "{key}"
            );
        }
    }

    #[test]
    fn lookups_try_the_key_then_each_namespace_above() {
        assert_eq!(
            key_lookup_order("q.io/a/b/c", "q.io", false),
            ["q.io/a/b/c", "q.io/a/b", "q.io/a", "q.io"]
        );
        assert_eq!(key_lookup_order("q.io", "q.io", false), ["q.io"]);
        assert_eq!(key_lookup_order("q.io/a/b", "q.io", true), ["q.io"]);
    }

    #[test]
    fn registries_are_normalized_as_the_library_does() {
        assert_eq!(normalize_registry("docker.io"), "index.docker.io");
        assert_eq!(
            normalize_registry("registry-1.docker.io"),
            "index.docker.io"
        );
        assert_eq!(normalize_registry("quay.io"), "quay.io");
        assert_eq!(
            normalize_auth_file_key("https://index.docker.io/v1/", false),
            "index.docker.io"
        );
        assert_eq!(normalize_auth_file_key("http://q.io", false), "q.io");
        assert_eq!(normalize_auth_file_key("q.io/ns", false), "q.io/ns");
        assert_eq!(normalize_auth_file_key("q.io/v1/", true), "q.io");
        assert_eq!(
            normalize_auth_file_key("docker.io", false),
            "index.docker.io"
        );
    }

    #[test]
    fn parsed_files_answer_as_the_files_do_and_hold_what_they_read() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let ctx = context(dir.path());
        write(
            dir.path(),
            "run/containers/0/auth.json",
            r#"{"auths": {"a.io": {"auth": "dXNlcg=="}, "c.io": {"auth": "Og=="}, "h.io": {"auth": "dTpw"}}, "credHelpers": {"h.io": "pass"}}"#,
        );
        write(
            dir.path(),
            "home/.docker/config.json",
            r#"{"auths": {"a.io": {"auth": "dTpw"}, "b.io": {"auth": "dTpw"}, "c.io": {"auth": "dTpw"}}}"#,
        );
        let (parsed, problems) = Files::load(&ctx);
        assert!(problems.is_empty(), "{problems:?}");
        for key in ["a.io", "b.io", "c.io", "h.io", "none.io", "b.io/ns/repo"] {
            let from_files = credentials(&ctx, &files(), key).expect("a lookup");
            let from_parsed = parsed.credentials(&files(), key).expect("a lookup");
            assert_eq!(
                format!("{from_files:?}"),
                format!("{from_parsed:?}"),
                "{key}"
            );
        }
        // An empty login in a file does not hide the one in the next.
        assert!(matches!(
            parsed.credentials(&files(), "c.io").expect("a lookup"),
            Lookup::Found(auth) if auth.username == "u"
        ));
        // What the parsed files hold is what was read, whatever happens to the files.
        std::fs::remove_dir_all(dir.path().join("home")).expect("removed");
        assert!(matches!(
            parsed.credentials(&files(), "b.io").expect("a lookup"),
            Lookup::Found(_)
        ));
        // A file that is not valid is reported, and fails the lookups that reach it.
        write(dir.path(), "run/containers/0/auth.json", "{");
        let (broken, problems) = Files::load(&ctx);
        assert!(matches!(problems.as_slice(), [Error::Parse { .. }]));
        assert!(matches!(
            broken.credentials(&files(), "a.io"),
            Err(Error::Helpers(errors)) if matches!(errors.as_slice(), [Error::Unusable { .. }])
        ));
        assert!(matches!(
            Files::default()
                .credentials(&files(), "a.io")
                .expect("a lookup"),
            Lookup::NotFound
        ));
    }

    #[test]
    fn files_are_parsed_in_both_formats_with_keys_in_any_case() {
        let file = parse_auth_file(r#"{"AUTHS": {"a.io": {"AUTH": "x", "IdentityToken": "t"}, "b.io": null, "c.io": {}}, "CredHelpers": {"d.io": "pass", "e.io": null}}"#, false).expect("a file");
        assert_eq!(file.auths.len(), 3);
        assert_eq!(file.auths["a.io"].identity_token.expose_secret(), "t");
        assert_eq!(file.cred_helpers["d.io"], "pass");
        assert_eq!(file.cred_helpers["e.io"], "");
        let legacy = parse_auth_file(r#"{"a.io": {"auth": "x"}}"#, true).expect("a file");
        assert_eq!(legacy.auths.len(), 1);
        assert!(
            parse_auth_file("null", false)
                .expect("a file")
                .auths
                .is_empty()
        );
        assert!(
            parse_auth_file(r#"{"auths": null}"#, false)
                .expect("a file")
                .auths
                .is_empty()
        );
        for bad in [
            "",
            "{",
            "[]",
            r#"{"auths": []}"#,
            r#"{"auths": {"a": "x"}}"#,
            r#"{"auths": {"a": {"auth": 1}}}"#,
            r#"{"credHelpers": {"a": 1}}"#,
            r#"{"credHelpers": []}"#,
        ] {
            assert!(parse_auth_file(bad, false).is_err(), "{bad:?} is accepted");
        }
        let error = parse_auth_file(r#"{"auths": {"a": "x"}}"#, false).expect_err("a refusal");
        assert!(error.to_string().contains("expected an object"), "{error}");
        assert!(parse_auth_file(r#"{"auths": {}}"#, true).is_ok());
        assert!(parse_auth_file(r#"{"a": 1}"#, true).is_err());
        let error = parse_auth_file("{\n  x", false).expect_err("a refusal");
        assert_eq!(error.position().map(|(line, _)| line), Some(2));
    }

    #[test]
    fn the_spellings_of_a_field_are_read_in_order_as_encoding_json_does() {
        let file = parse_auth_file(r#"{"auths": {"a.io": {"auth": "x", "AUTH": "y"}}, "AUTHS": {"b.io": {"Auth": "z", "auth": null}}, "credHelpers": {"c.io": "p"}, "CredHelpers": {"d.io": "q"}}"#, false).expect("a file");
        assert_eq!(file.auths["a.io"].auth.expose_secret(), "y");
        assert_eq!(file.auths["b.io"].auth.expose_secret(), "z");
        assert_eq!(file.cred_helpers.len(), 2);
        let emptied =
            parse_auth_file(r#"{"auths": {"a.io": {}}, "Auths": null}"#, false).expect("a file");
        assert!(emptied.auths.is_empty());
        let replaced = parse_auth_file(
            r#"{"a.io": {"auth": "x"}, "a.io": {"identitytoken": "t"}}"#,
            true,
        )
        .expect("a file");
        assert_eq!(replaced.auths["a.io"].auth.expose_secret(), "");
        // `bytes.EqualFold` folds K (U+212A) to k and ſ (U+017F) to s.
        let folded = parse_auth_file(
            "{\"auth\u{17f}\": {\"a.io\": {\"identityto\u{212a}en\": \"t\"}}}",
            false,
        )
        .expect("a file");
        assert_eq!(folded.auths["a.io"].identity_token.expose_secret(), "t");
        // A key names a field when the whole of it folds to the name, no less and no more.
        let others = parse_auth_file(r#"{"auths": {"a.io": {"a": "x", "authx": "y"}}}"#, false)
            .expect("a file");
        assert_eq!(others.auths["a.io"].auth.expose_secret(), "");
        // `null` is the zero value of an entry in both formats.
        let legacy = parse_auth_file(r#"{"a.io": null}"#, true).expect("a file");
        assert_eq!(legacy.auths["a.io"].auth.expose_secret(), "");
        assert!(
            parse_auth_file("null", false)
                .expect("a file")
                .auths
                .is_empty()
        );
    }

    #[test]
    fn the_per_user_file_is_searched_before_the_config_home_and_docker() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let ctx = context(dir.path());
        let paths: Vec<_> = auth_file_paths(&ctx)
            .into_iter()
            .map(|p| (p.path, p.legacy))
            .collect();
        assert_eq!(
            paths,
            [
                (dir.path().join("run/containers/0/auth.json"), false),
                (dir.path().join("home/.config/containers/auth.json"), false),
                (dir.path().join("home/.docker/config.json"), false),
                (dir.path().join("home/.dockercfg"), true)
            ]
        );
        let named = Context {
            auth_file: Some(dir.path().join("named.json")),
            ..ctx.clone()
        };
        assert_eq!(auth_file_paths(&named).len(), 1);
        let moved = Context {
            xdg_config_home: Some(dir.path().join("xdg")),
            docker_config: Some(dir.path().join("dc")),
            ..ctx
        };
        let paths: Vec<_> = auth_file_paths(&moved)
            .into_iter()
            .map(|p| p.path)
            .collect();
        assert_eq!(paths[1], dir.path().join("xdg/containers/auth.json"));
        assert_eq!(paths[2], dir.path().join("dc/config.json"));
        let rootless = Context {
            root: PathBuf::new(),
            uid: 1000,
            xdg_runtime_dir: Some(dir.path().join("none")),
            ..Context::root()
        };
        // A runtime directory that does not exist is skipped.
        assert_eq!(auth_file_paths(&rootless).len(), 3);
        // Any other failure to look at it is not: the library uses the path and fails reading it.
        std::fs::write(dir.path().join("file"), "").expect("a file");
        let beyond = Context {
            xdg_runtime_dir: Some(dir.path().join("file/sub")),
            ..rootless.clone()
        };
        assert_eq!(
            auth_file_paths(&beyond)[0].path,
            dir.path().join("file/sub/containers/auth.json")
        );
        let runtime = Context {
            xdg_runtime_dir: Some(dir.path().to_owned()),
            ..rootless.clone()
        };
        assert_eq!(
            auth_file_paths(&runtime)[0].path,
            dir.path().join("containers/auth.json")
        );
        let plain = Context {
            xdg_runtime_dir: None,
            ..rootless
        };
        assert_eq!(
            auth_file_paths(&plain)[0].path,
            PathBuf::from("/run/containers/1000/auth.json")
        );
    }

    #[test]
    fn credentials_come_from_the_first_file_that_has_them() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let ctx = context(dir.path());
        write(
            dir.path(),
            "run/containers/0/auth.json",
            r#"{"auths": {"q.io/org": {"auth": "b3JnOnRva2Vu"}, "e.com": {"auth": "ZTpwdw==", "identitytoken": "tok"}}}"#,
        );
        write(
            dir.path(),
            "home/.docker/config.json",
            r#"{"auths": {"q.io": {"auth": "ZG9ja2VyOnB3"}, "https://index.docker.io/v1/": {"auth": "aGlzdG9yaWM6cHc="}}}"#,
        );
        write(
            dir.path(),
            "home/.dockercfg",
            r#"{"https://l.io/v1/": {"auth": "bGVnYWN5OnB3"}}"#,
        );
        let login = |key: &str| found(credentials(&ctx, &files(), key));
        let owned = |a: &str, b: &str, c: &str| Some((a.to_owned(), b.to_owned(), c.to_owned()));
        assert_eq!(login("q.io/org/img"), owned("org", "token", ""));
        assert_eq!(login("q.io/other"), owned("docker", "pw", ""));
        assert_eq!(login("e.com"), owned("e", "pw", "tok"));
        assert_eq!(
            login("docker.io/library/busybox"),
            owned("historic", "pw", "")
        );
        assert_eq!(login("registry-1.docker.io"), owned("historic", "pw", ""));
        assert_eq!(login("l.io/x"), owned("legacy", "pw", ""));
        assert_eq!(login("none.io"), None);
        assert!(matches!(
            credentials(&ctx, &files(), "https://q.io"),
            Err(Error::InvalidKey { .. })
        ));
        assert!(matches!(
            credentials(&ctx, &["pass".to_owned()], "q.io").expect("a lookup"),
            Lookup::Helper(helper) if helper == "pass"
        ));
        assert!(matches!(
            credentials(&ctx, &[], "q.io").expect("a lookup"),
            Lookup::NotFound
        ));
    }

    #[test]
    fn an_entry_without_a_login_stops_the_search_of_its_file_only() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let ctx = context(dir.path());
        write(
            dir.path(),
            "run/containers/0/auth.json",
            r#"{"auths": {"a.io": {"auth": "dXNlcg=="}, "b.io": {"auth": "Og=="}, "c.io": {"auth": "!"}}, "credHelpers": {"h.io": "pass"}}"#,
        );
        write(
            dir.path(),
            "home/.docker/config.json",
            r#"{"auths": {"a.io": {"auth": "dTpw"}, "b.io": {"auth": "dTpw"}}}"#,
        );
        let login = |key: &str| found(credentials(&ctx, &files(), key));
        assert_eq!(login("a.io").map(|l| l.0), Some("u".to_owned()));
        assert_eq!(login("b.io").map(|l| l.0), Some("u".to_owned()));
        assert!(
            matches!(credentials(&ctx, &files(), "c.io"), Err(Error::Helpers(errors)) if matches!(errors[0], Error::Base64 { .. }))
        );
        assert!(matches!(
            credentials(&ctx, &files(), "h.io").expect("a lookup"),
            Lookup::Helper(helper) if helper == "pass"
        ));
        write(dir.path(), "run/containers/0/auth.json", "{");
        assert!(matches!(
            credentials(&ctx, &files(), "a.io"),
            Err(Error::Helpers(_))
        ));
        std::fs::remove_file(dir.path().join("run/containers/0/auth.json")).expect("removed");
        std::fs::create_dir(dir.path().join("run/containers/0/auth.json")).expect("a directory");
        assert!(matches!(
            credentials(&ctx, &files(), "a.io"),
            Err(Error::Helpers(_))
        ));
    }

    #[test]
    fn a_login_prints_no_secret() {
        let auth = Auth {
            username: "user".to_owned(),
            password: "hunter2".to_owned().into(),
            identity_token: "tok3n".to_owned().into(),
        };
        let printed = format!("{auth:?} {:?}", Lookup::Found(auth.clone()));
        assert!(
            !printed.contains("hunter2") && !printed.contains("tok3n"),
            "{printed}"
        );
        let file = parse_auth_file(
            r#"{"auths": {"a.io": {"auth": "c2VjcmV0", "identitytoken": "tok3n"}}}"#,
            false,
        )
        .expect("a file");
        assert!(!format!("{file:?}").contains("c2VjcmV0"));
    }
}
