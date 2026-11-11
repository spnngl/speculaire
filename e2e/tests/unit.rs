//! The agent as `packaging/speculaire.service` on every node (D39, D53): the unit, its endpoints, metrics and logs.
//! Each test leaves the unit running and unchanged; `unit_reload.rs` and `unit_restart.rs`, test binaries of their
//! own, reload and stop it.

use e2e::{Cluster, Failure};
use serde_json::Value;

/// `systemd-analyze security` entries of D53's settings that stay unset by design: `@system-service` includes
/// `@resources`, and the agent needs local and IP sockets.
const UNSET_BY_DESIGN: [&str; 3] = [
    "SystemCallFilter=~@resources",
    "RestrictAddressFamilies=~AF_UNIX",
    "RestrictAddressFamilies=~AF_(INET|INET6)",
];

/// The settings of D53 that `systemd-analyze security` reports, by the prefix of its entries' names.
const ANALYZED: [&str; 21] = [
    "NoNewPrivileges=",
    "CapabilityBoundingSet=",
    "AmbientCapabilities=",
    "ProtectSystem=",
    "ProtectHome=",
    "PrivateTmp=",
    "PrivateDevices=",
    "ProtectKernelTunables=",
    "ProtectKernelModules=",
    "ProtectKernelLogs=",
    "ProtectControlGroups=",
    "ProtectClock=",
    "ProtectHostname=",
    "RestrictAddressFamilies=",
    "RestrictNamespaces=",
    "RestrictRealtime=",
    "RestrictSUIDSGID=",
    "LockPersonality=",
    "MemoryDenyWriteExecute=",
    "SystemCallArchitectures=",
    "SystemCallFilter=",
];

/// The unit's properties that `systemd-analyze security` does not report, as `systemctl show` prints them.
const SHOWN: [&str; 10] = [
    "Type=notify",
    "User=root",
    "TimeoutStopUSec=20s",
    "Restart=on-failure",
    "StateDirectory=speculaire",
    "RuntimeDirectory=speculaire",
    "RuntimeDirectoryMode=0700",
    "RuntimeDirectoryPreserve=yes",
    "LimitNOFILE=524288",
    // EPERM.
    "SystemCallErrorNumber=1",
];

fn show(cluster: &Cluster, node: &str, property: &str) -> Result<String, Failure> {
    let out = cluster.exec(node, &["systemctl", "show", "speculaire", "-p", property])?;
    Ok(out.trim().to_owned())
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_unit_is_active_with_its_settings_and_a_watchdog() {
    let cluster = Cluster::from_env();
    for node in cluster.nodes().unwrap() {
        let node = node.name;
        let active = cluster
            .exec(&node, &["systemctl", "is-active", "speculaire"])
            .unwrap();
        assert_eq!(active.trim(), "active", "{node}");
        for want in SHOWN {
            let (property, _) = want.split_once('=').unwrap();
            assert_eq!(show(&cluster, &node, property).unwrap(), want, "{node}");
        }
        let watchdog = show(&cluster, &node, "WatchdogUSec").unwrap();
        assert!(
            watchdog != "WatchdogUSec=0" && watchdog != "WatchdogUSec=infinity",
            "{node}: {watchdog}"
        );
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_unit_has_every_hardening_setting() {
    let cluster = Cluster::from_env();
    for node in cluster.nodes().unwrap() {
        let node = node.name;
        let out = cluster
            .exec(
                &node,
                &[
                    "systemd-analyze",
                    "security",
                    "speculaire.service",
                    "--no-pager",
                    "--json=short",
                ],
            )
            .unwrap();
        let entries: Vec<Value> = serde_json::from_str(&out).unwrap();
        for prefix in ANALYZED {
            let mine: Vec<&Value> = entries
                .iter()
                .filter(|e| e["name"].as_str().is_some_and(|n| n.starts_with(prefix)))
                .collect();
            assert!(!mine.is_empty(), "{node}: no {prefix} entry");
            for entry in mine {
                let name = entry["name"].as_str().unwrap();
                let set = entry["set"].as_bool() == Some(true);
                assert_eq!(
                    set,
                    !UNSET_BY_DESIGN.contains(&name),
                    "{node}: {name} set is {set}"
                );
            }
        }
        // `@system-service` includes `@aio`, and so io_uring, which D4 denies by name.
        let filter = show(&cluster, &node, "SystemCallFilter").unwrap();
        assert!(
            filter.contains(" read ") && !filter.contains("io_uring"),
            "{node}: {filter}"
        );
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn every_scraped_metric_is_in_the_catalog() {
    let catalog =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/metrics.md"))
            .unwrap();
    let cluster = Cluster::from_env();
    for node in cluster.nodes().unwrap() {
        let node = node.name;
        let text = cluster
            .exec(&node, &["curl", "-sf", "http://127.0.0.1:7482/metrics"])
            .unwrap();
        let names: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("# TYPE "))
            .filter_map(|l| l.split(' ').next())
            .collect();
        assert!(
            names.contains(&"speculaire_build_info"),
            "{node}: {names:?}"
        );
        for name in names {
            assert!(
                catalog.contains(&format!("| `{name}` |")),
                "{node}: {name} is not in docs/metrics.md (D34)"
            );
        }
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_journal_holds_structured_entries_and_nothing_at_warning() {
    let cluster = Cluster::from_env();
    for node in cluster.nodes().unwrap() {
        let node = node.name;
        let journal = |args: &[&str]| {
            let mut command = vec!["journalctl", "-u", "speculaire", "--no-pager", "-q"];
            command.extend_from_slice(args);
            cluster.exec(&node, &command).unwrap()
        };
        let warnings = journal(&["-p", "warning", "-o", "cat"]);
        assert!(warnings.trim().is_empty(), "{node}: {warnings}");
        // The agent's own entries, from tracing-journald: its fields carry the `F_` prefix.
        let opened = journal(&["-o", "json"])
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|e| e["MESSAGE"] == "status listener open")
            .unwrap_or_else(|| panic!("{node}: no `status listener open` entry"));
        assert_eq!(opened["F_ADDRESS"], "[::]:7482", "{node}: {opened}");
        assert_eq!(
            opened["TARGET"], "speculaire_agent::serve",
            "{node}: {opened}"
        );
        assert_eq!(
            opened["SYSLOG_IDENTIFIER"], "speculaire",
            "{node}: {opened}"
        );
    }
}
