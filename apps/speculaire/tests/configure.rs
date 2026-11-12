//! The admin commands as processes: each stops on a config file it cannot read, before it touches the node.

use std::process::Command;

#[test]
fn a_missing_config_file_stops_every_command_naming_it() {
    for args in [
        ["check-config", "/nonexistent/config.toml"].as_slice(),
        ["configure", "--config", "/nonexistent/config.toml"].as_slice(),
        ["unconfigure", "--config", "/nonexistent/config.toml"].as_slice(),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_speculaire"))
            .args(args)
            .args(["--runtime", "containerd"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?}: {stderr}");
        assert!(
            stderr.contains("/nonexistent/config.toml"),
            "{args:?}: {stderr}"
        );
    }
}
