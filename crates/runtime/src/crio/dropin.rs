//! CRI-O: the mirror as a `registries.conf.d` drop-in (D66, D83).
//!
//! CRI-O takes the manifest and every blob of an image from the first source that serves the manifest, and has no
//! per-request fallback, so the mirror has to be the first mirror of every registry it serves. A drop-in named
//! `99-speculaire.conf` loads after the admin's files, and a later `[[registry]]` with the same prefix replaces an
//! earlier one whole (go.podman.io/image v5.40.0 `pkg/sysregistriesv2/system_registries_v2.go:933-942`), so each entry
//! of the drop-in copies the admin's effective entry for its prefix, with the mirror put first.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use speculaire_registry_config::crio::registries::{Config, Endpoint, Registry};

/// The comment on top of the drop-in.
const HEADER: &str =
    "# Written by `speculaire configure`; `speculaire unconfigure` removes it (D66).\n";

/// What `pull-from-mirror` says for the mirror: every pull, by tag or digest. By digest only, a pull by tag, which is
/// what kubelet does with most images, would not reach it (D66, Measured).
const PULL_FROM_MIRROR: &str = "all";

/// A registry the drop-in leaves out, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Left {
    /// Its prefix.
    pub prefix: String,
    /// Why.
    pub reason: &'static str,
}

/// The entries of the drop-in: the admin's effective entry of each prefix to mirror, with the mirror first.
///
/// The prefixes are `names`, besides every prefix of `admin`, the config of the admin's own files. A registry the
/// admin blocked, or whose entry has no location (a wildcard prefix, which names no registry to relay), or whose
/// location has a port, is left out, and so is the mirror itself.
#[must_use]
pub fn entries(
    names: &[String],
    admin: &Config,
    address: SocketAddr,
) -> (Vec<Registry>, Vec<Left>) {
    let mut by_prefix: BTreeMap<&str, Registry> = BTreeMap::new();
    for name in names {
        by_prefix.insert(
            name,
            admin
                .registries
                .iter()
                .find(|r| r.prefix == *name)
                .cloned()
                .unwrap_or_else(|| Registry {
                    prefix: name.clone(),
                    endpoint: Endpoint {
                        location: name.clone(),
                        ..Endpoint::default()
                    },
                    ..Registry::default()
                }),
        );
    }
    for registry in &admin.registries {
        by_prefix.insert(&registry.prefix, registry.clone());
    }
    let own = address.to_string();
    let mut mirrored = Vec::new();
    let mut left = Vec::new();
    for (prefix, mut registry) in by_prefix {
        let reason = if registry.blocked {
            Some("blocked")
        } else if registry.endpoint.location.is_empty() {
            Some("a wildcard prefix has no location to relay")
        } else if registry.endpoint.location.split('/').next() == Some(own.as_str()) {
            Some("is the mirror itself")
        } else if registry
            .endpoint
            .location
            .split('/')
            .next()
            .is_some_and(|host| host.contains(':'))
        {
            // The mirror's location carries the registry as a path component, and a name has no colon (D88).
            Some("has a port, which the mirror's path cannot hold")
        } else {
            None
        };
        if let Some(reason) = reason {
            left.push(Left {
                prefix: prefix.to_owned(),
                reason,
            });
            continue;
        }
        // The library refuses `mirror-by-digest-only` beside a `pull-from-mirror`, so the admin's flag moves to their
        // mirrors, which is what it means.
        if std::mem::take(&mut registry.mirror_by_digest_only) {
            for mirror in &mut registry.mirrors {
                if mirror.pull_from_mirror.is_empty() {
                    "digest-only".clone_into(&mut mirror.pull_from_mirror);
                }
            }
        }
        registry.mirrors.insert(
            0,
            Endpoint {
                location: format!("{address}/{}", registry.endpoint.location),
                insecure: false,
                pull_from_mirror: PULL_FROM_MIRROR.to_owned(),
            },
        );
        mirrored.push(registry);
    }
    (mirrored, left)
}

/// The drop-in's text for `entries`.
#[must_use]
pub fn render(entries: &[Registry]) -> String {
    let mut text = String::from(HEADER);
    for registry in entries {
        text.push_str("\n[[registry]]\n");
        field(&mut text, "prefix", &registry.prefix);
        field(&mut text, "location", &registry.endpoint.location);
        flag(&mut text, "insecure", registry.endpoint.insecure);
        flag(&mut text, "blocked", registry.blocked);
        for mirror in &registry.mirrors {
            text.push_str("\n[[registry.mirror]]\n");
            field(&mut text, "location", &mirror.location);
            flag(&mut text, "insecure", mirror.insecure);
            if !mirror.pull_from_mirror.is_empty() {
                field(&mut text, "pull-from-mirror", &mirror.pull_from_mirror);
            }
        }
    }
    text
}

fn field(text: &mut String, key: &str, value: &str) {
    text.push_str(key);
    text.push_str(" = ");
    text.push_str(&toml_edit::Value::from(value).to_string());
    text.push('\n');
}

fn flag(text: &mut String, key: &str, value: bool) {
    if value {
        text.push_str(key);
        text.push_str(" = true\n");
    }
}

#[cfg(test)]
mod tests {
    use speculaire_registry_config::crio::registries::parse_file;

    use super::*;

    const ADDRESS: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 7480);

    fn admin(text: &str) -> Config {
        let mut config = Config {
            registries: Vec::new(),
            credential_helpers: Vec::new(),
        };
        let file = parse_file(text).unwrap();
        config.registries = file.registries;
        config
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    const ADMIN: &str = r#"
unqualified-search-registries = ["docker.io"]

[[registry]]
prefix = "docker.io"
location = "registry-1.docker.io"
[[registry.mirror]]
location = "mirror.corp:5000/dockerhub"
insecure = true
pull-from-mirror = "digest-only"

[[registry]]
location = "registry.corp:5000"
insecure = true
mirror-by-digest-only = true
[[registry.mirror]]
location = "digests.corp"

[[registry]]
prefix = "evil.example"
location = "evil.example"
blocked = true

[[registry]]
prefix = "*.wild.example"

[[registry]]
prefix = "*.rewritten.example"
location = "rewritten.corp"

[[registry]]
location = "127.0.0.1:7480/self"
"#;

    #[test]
    fn the_drop_in_copies_the_admins_entries_with_the_mirror_first() {
        let config = admin(ADMIN);
        let (entries, left) = entries(
            &names(&["docker.io", "quay.io", "ghcr.io"]),
            &config,
            ADDRESS,
        );
        insta::assert_snapshot!("crio-dropin", render(&entries));
        let skipped: Vec<_> = left.iter().map(|l| (l.prefix.as_str(), l.reason)).collect();
        assert_eq!(
            skipped,
            [
                (
                    "*.wild.example",
                    "a wildcard prefix has no location to relay"
                ),
                ("127.0.0.1:7480/self", "is the mirror itself"),
                ("evil.example", "blocked"),
                (
                    "registry.corp:5000",
                    "has a port, which the mirror's path cannot hold"
                ),
            ]
        );
        // What was written is what is read back, entry for entry.
        let back = parse_file(&render(&entries)).unwrap();
        assert_eq!(back.registries, entries);
        for registry in &entries {
            assert_eq!(registry.mirrors[0].pull_from_mirror, "all");
            assert!(registry.mirrors[0].location.starts_with("127.0.0.1:7480/"));
        }
    }

    #[test]
    fn a_registry_with_a_port_is_left_out_as_a_name_with_a_colon_is_no_path() {
        let config = admin(
            "[[registry]]\nprefix = \"harbor.corp:8443\"\nlocation = \"harbor.corp:8443\"\n\n[[registry]]\nprefix = \"alias.corp\"\nlocation = \"harbor.corp:8443/team\"\n\n[[registry]]\nprefix = \"plain.corp\"\nlocation = \"plain.corp\"\n",
        );
        let (entries, left) = entries(&names(&["harbor.corp:8443"]), &config, ADDRESS);
        let skipped: Vec<_> = left.iter().map(|l| l.prefix.as_str()).collect();
        assert_eq!(skipped, ["alias.corp", "harbor.corp:8443"]);
        assert!(left.iter().all(|l| l.reason.contains("port")));
        let kept: Vec<_> = entries.iter().map(|r| r.prefix.as_str()).collect();
        assert_eq!(kept, ["plain.corp"]);
    }

    #[test]
    fn a_registry_the_admin_never_named_is_relayed_as_itself() {
        let (entries, left) = entries(&names(&["registry.k8s.io"]), &admin(""), ADDRESS);
        assert_eq!(left, []);
        insta::assert_snapshot!("crio-dropin-defaults", render(&entries));
        assert_eq!(parse_file(&render(&entries)).unwrap().registries, entries);
    }

    #[test]
    fn a_name_that_is_already_a_prefix_of_the_admin_is_not_doubled() {
        let config = admin(ADMIN);
        let (entries, _) = entries(&names(&["docker.io", "docker.io"]), &config, ADDRESS);
        assert_eq!(
            entries.iter().filter(|r| r.prefix == "docker.io").count(),
            1
        );
    }

    #[test]
    fn nothing_to_mirror_is_a_drop_in_with_only_its_header() {
        let (entries, _) = entries(&[], &admin(""), ADDRESS);
        assert_eq!(entries, []);
        assert_eq!(render(&entries), HEADER);
    }

    #[test]
    fn an_ipv6_mirror_is_written_in_brackets() {
        let v6 = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 7480));
        let (entries, _) = entries(&names(&["docker.io"]), &admin(""), v6);
        assert_eq!(entries[0].mirrors[0].location, "[::1]:7480/docker.io");
        assert_eq!(parse_file(&render(&entries)).unwrap().registries, entries);
    }
}
