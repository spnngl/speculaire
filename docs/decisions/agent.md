# Decisions: agent

The agent process on a node: its settings, and how it installs into and leaves containerd's config. Index: `docs/decisions/README.md`.

## D30: One strict config file, reloaded on SIGHUP and when a file changes (amended by D37, D47)

- **Decision:**
  - Settings live in `/etc/speculaire/config.toml`, or the file given by `--config`. They parse into typed structs that reject unknown fields. An unknown key or a bad value stops startup, and the error names the key.
  - `packaging/config.toml` is the reference: it lists every key, commented, at its default value. A test checks that it parses to `Config::default()` once uncommented (D47). No other file lists the settings.
  - `speculaire check-config [path]` checks a config file, plus the policy and trust root it names, without starting the agent. It exits 0 when all are valid and 1 otherwise.
  - **Triggers:** a reload runs on SIGHUP (`ExecReload` in the unit). It also runs from a poll every `config.poll_interval` (default 10 s):
    1. The agent keeps `last_check`, the epoch time at which the previous poll started.
    2. Each poll records its own start time first, then `stat`s every watched file, following symlinks.
    3. If any file's modification time is at or after `last_check`, the poll reloads.
    4. The poll then stores its start time as the new `last_check`.

    `>=` covers filesystems with coarse timestamps, and recording the start time first covers a write made during the poll. A file replaced with its old modification time kept (`cp -p`, `rsync -t`) is not seen; SIGHUP covers it.
  - **Watched files:**
    - the agent config;
    - `policy.yaml` and `trusted_root.json` (D26);
    - the *registry config*: containerd's `config.toml` with its `imports`, and the `hosts.toml` tree (D17).

    The kubelet certificate (D16) uses the same watcher.
  - **Apply:** a reload parses every changed file, then swaps them all at once. If any file is invalid, the previous config keeps running, the agent logs the error, and `speculaire_config_reload_failures_total` increments.
  - **Live keys:** the restart keys are listed in D47; every other key reloads live. A reload that changes a restart key keeps the old value and logs a warning that names the key.
  - A changed policy or trust root starts re-verification (D21).
- **Because:**
  - The user chose both triggers, and change detection by comparing modification times with the last check time. SIGHUP lets config management apply a change at once. The poll catches edits that nobody signalled and works on every filesystem. Because `stat` follows symlinks, it also sees a ConfigMap symlink swap, which an inotify watch misses (D26, DaemonSet phase).
  - A typo in a security setting (`gate.unmached`) must stop the agent, not quietly fall back to a default.
  - A bad reload keeps the old config because the gate must keep deciding. Failing closed on a typo would block every container creation on the node.
- **Revisit when:** —

## D32: `configure` and `unconfigure` change only what speculaire added (amends D14; amended by D55, D56, D66)

- **Decision:**
  - `speculaire configure` edits each `hosts.toml` with a format-preserving TOML editor, so the admin's comments and ordering stay. It recognises its own entries by their `ca` path (D56).
  - `speculaire unconfigure` replaces `configure --restore`. It runs these steps in order:
    1. If containerd's NRI config lists `speculaire` in `[plugins.'io.containerd.nri.v1.nri'.default_validator] required_plugins`, it stops and prints that key. `--force` skips this check.
    2. It removes its own entries from each `hosts.toml`, and keeps everything else, including edits made after `configure`. It deletes a `hosts.toml` that `configure` created once it is empty.
    3. Only then does it delete `/var/lib/speculaire/mirror/`.
  - Both commands are idempotent.
  - The deb and rpm removal scripts run `speculaire unconfigure` on remove and purge, not on upgrade. If it fails, the removal stops and shows its message.
- **Because:**
  - containerd fails every pull for a registry whose `hosts.toml` names a missing `ca` or `client` file (D14). So the certificates go last.
  - Removing the agent while `required_plugins` still names it blocks every container creation on the node.
  - Restoring backups would undo admin edits made after `configure`.
- **Revisit when:** —

## D37: Logs through `tracing`, with an opt-in audit log (amends D30; amended by D52)

- **Decision:**
  - **Sinks:** `tracing-subscriber` with `tracing-journald` when `JOURNAL_STREAM` is set, and JSON on stderr otherwise.
  - **Filter:** `log.filter`, in `EnvFilter` syntax, default `"warn"`. It reloads live through `tracing_subscriber::reload`.
  - **Audit log:** off by default; `audit.enabled = true` turns it on, live. Audit events use the target `speculaire::audit` at `INFO`. Their own per-layer filter lets them through when the audit is on, whatever `log.filter` says. In journald they carry `SYSLOG_IDENTIFIER=speculaire-audit`, so `journalctl -t speculaire-audit` shows them alone. Three events exist:
    - `gate`, one per `CreateContainer`: namespace, pod, container, image name, image identity, identity path (D15), matched policies, mode, result, reason, whether the verdict was stale, and the exemption that applied, if any;
    - `verdict`, one per verification whose result differs from the previous verdict for its key: image identity, matched policies, trust-root hash, result, reason, and the signer identities (certificate subject and issuer) that satisfied each policy;
    - `peer`, one per peer denied for a digest mismatch (D52): node identity, peer address, digest, and the end of the denial.
  - **Secrets never reach a log:**
    - registry passwords, auth strings, identity tokens and Bearer tokens are held in `secrecy::SecretString`, whose `Debug` prints a placeholder;
    - HTTP tracing records method, path, status and duration, never headers;
    - private keys are never formatted.
- **Because:**
  - The user chose `tracing` and an audit log that is off by default. On a busy node, one line per container creation is too much to keep by default; the reason of a rejection already shows in `kubectl describe pod` and in metrics (D34).
  - Metrics may not carry pod or image labels (D34), so the audit log is where "which pod ran which image, and who signed it" lives.
  - A separate filter keeps a `log.filter` change from silently dropping the audit trail.
- **Revisit when:** someone needs OpenTelemetry traces or log export; add `tracing-opentelemetry` as a layer behind a cargo feature.

## D39: Shutdown withdraws first, drains, saves, and leaves NRI last (amended by D69)

- **Decision:** on SIGTERM, the agent:
  1. sends `STOPPING=1` to systemd, and `/readyz` returns 503;
  2. answers new peer requests with `503`, and new mirror requests with `404`, so containerd falls through;
  3. closes its stream to every reflector, which drops this node's entries at EOF (D2), so no lookup returns it any more;
  4. waits for in-flight mirror responses and peer uploads for up to `shutdown.drain_timeout` (default 10 s), then aborts the rest; a fetching peer resumes elsewhere with `Range` (D7);
  5. saves the cache (D31);
  6. disconnects from NRI and exits. Until then, the gate keeps deciding from memory.

  The unit sets `TimeoutStopSec=20s`. A stopping reflector closes the streams of its agents. They keep their streams to the other members and retry this one with jittered backoff (D33).
- **Because:**
  - Withdrawing before draining stops new work from arriving at a node that is leaving.
  - With `required_plugins` set, every container creation fails while the plugin is gone, so NRI goes last to keep that window as short as possible.
  - 10 s finishes a 1 GB blob at 1 Gb/s; a bigger transfer resumes elsewhere.
- **Revisit when:** —

## D42: `/metrics`, `/readyz` and `/livez` listen on `metrics.address`, plain HTTP (amended by D45)

- **Decision:** one HTTP listener serves `/metrics`, `/readyz` and `/livez` on `metrics.address`, port 7482 (default address: D45). It is plain HTTP without authentication, and a restart key (D30).
- **Because:**
  - It is what Prometheus scrapes on every node without extra credentials, as with node-exporter.
  - The catalog holds no secret and no per-pod or per-image label (D34), so the endpoints reveal only counts.
- **Revisit when:** a user needs the endpoints behind TLS; then serve them with the peer API's certificate and verifier (D16).

## D45: The health and metrics listener binds `[::]:7482` from startup (amends D42)

- **Decision:** `metrics.address` defaults to `"[::]:7482"`. The listener opens before NRI registration and before any reflector connection. `/livez` answers 200 once it listens. `/readyz` answers 200 once every component the agent has started is ready: the config is loaded, the mirror listens, and the gate is registered with NRI (D41). It answers 503 while stopping (D39). A component that a build doesn't have yet adds no condition.
- **Because:**
  - D42's default, the peer address (D36), exists only after the first `Announce` stream, which needs the kubelet certificate (D16) and a reachable member. A joining node, a node whose members are all down, and every node before reflectors exist would serve no health endpoint and no metrics, exactly when they are needed.
  - node-exporter listens on every address the same way.
- **Revisit when:** an admin needs the endpoints on one interface only; `metrics.address` already allows it.

## D47: Every setting has a key, a literal default and a reload class (amends D30; amended by D56, D60)

- **Decision:**
  - Each key in `packaging/config.toml` shows a literal default. A default computed at startup is written `"auto"`: `peer.max_uploads` (4 × CPUs, D24) and `peer.address` (D36).
  - The config test (D30) uncomments every key, then checks that the file parses to `Config::default()`.
  - Keys named here, with their defaults:
    - `gate.mode = "audit"`, or `"enforce"` (ARCHITECTURE.md § Gate);
    - `gate.wait = "300ms"` (D41);
    - `nri.socket = "/var/run/nri/nri.sock"` (D9);
    - `verify.policy = "/etc/speculaire/policy.yaml"` (D26);
    - `verify.trusted_root = ""`: empty follows the Sigstore public-good root through TUF; a path pins a `trusted_root.json` (D26);
    - `reflector.listen = "[::]:7483"`, and `prewarm.images = []` (image references, D26), both read only with `role = "reflector"`.
  - **Restart keys:** `role`, `mirror.address` (D56), `metrics.address`, `reflector.listen`, `peer.address`, `reflector.url`, `reflector.members`, `nri.socket` and certificate paths. Every other key reloads live, including `config.poll_interval`, `shutdown.drain_timeout`, `verify.policy`, `verify.trusted_root` and `prewarm.*`.
- **Because:**
  - D30 makes `packaging/config.toml` the only list of settings, so a key that exists only in prose cannot be checked.
  - A file of commented defaults parses to `Config::default()` whatever the defaults are; uncommenting makes the test compare values.
  - Restart keys are those that open sockets or define who the agent is; changing them live would leave peers or containerd holding stale addresses.
- **Revisit when:** —

## D53: The systemd unit's hardening (amended by D69)

- **Decision:** the unit runs the agent as root and sets:
  - `NoNewPrivileges=yes`, `CapabilityBoundingSet=` (empty), `AmbientCapabilities=` (empty);
  - `ProtectSystem=strict`, `StateDirectory=speculaire`, `RuntimeDirectory=speculaire` (D31), `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`;
  - `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes`, `ProtectClock=yes`, `ProtectHostname=yes`;
  - `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `RestrictNamespaces=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`;
  - `SystemCallArchitectures=native`, `SystemCallFilter=@system-service`, `SystemCallFilter=~@privileged io_uring_setup io_uring_enter io_uring_register` (D4), `SystemCallErrorNumber=EPERM`;
  - `LimitNOFILE=524288`.

  e2e (D27) checks the installed unit with `systemd-analyze security` and fails when a setting above is missing.
- **Because:**
  - Root is needed for the root-owned containerd and NRI sockets, the content directory and the kubelet key (D27). All of them are owned by root, and every port is above 1024, so root needs no capability.
  - `@system-service` includes `@aio` and so io_uring (`docs/research/rust-stack.md:39`); D4 needs the explicit deny.
  - The list matches dedens' unit where the two agree (`docs/research/ci-dedens.md:64`).
- **Revisit when:** a host keeps a file the agent reads under another owner; then add `CAP_DAC_READ_SEARCH` only.

## D55: The admin runs `configure`; the agent refuses to start without it (amends D32)

- **Decision:**
  - Installing the package neither runs `speculaire configure` nor edits containerd's config. The admin runs `configure` once per node (`docs/operations.md` § Install).
  - At startup, the agent stops with an error naming `speculaire configure` when the mirror certificates in `/var/lib/speculaire/mirror/` (D14) are missing.
  - `speculaire check-config` also exits 1 when a `hosts.toml` that `configure` would edit lacks the speculaire entry (D56), and names the file.
  - `configure` writes each certificate and key to a temporary file in the same directory, sets its mode (0600 for keys), then renames it into place.
- **Because:**
  - containerd reads `ca` and `client` on every resolve (D14), so a file written in place can be read half-written. Setting the mode only at creation would keep the mode of a looser file that already exists (M0 spike 04).
  - Editing containerd's config changes every pull on the node, so the admin chooses when, as with `required_plugins`. Removal still runs `unconfigure` (D32), because it must undo what the admin chose to add.
  - Without the certificates the mirror cannot listen (D14). Without the entry, containerd never calls the mirror, so verification starts only at the gate (D22), and every first start waits.
- **Revisit when:** a packaging runs `configure` for the admin, as the DaemonSet's init container would.

## D60: Config values parse into types, and the remaining keys get names (amends D16, D47)

- **Decision:**
  - Keys the decisions left unnamed, with their defaults:
    - `role = "agent"`, or `"reflector"` (D2);
    - `identity.certificate = "/var/lib/kubelet/pki/kubelet-client-current.pem"` and `identity.ca = "/etc/kubernetes/pki/ca.crt"`, D16's paths;
    - `reflector.url = ""`, meaning no reflector and no peers, or an `https://host[:port]` URL with no path;
    - `reflector.members = []`, a list of `{ node = "<node name>", address = "<ip:port>" }`.
  - **Value syntax:** durations are strings that `humantime` reads (`"300ms"`, `"10m"`); sizes are strings with a binary unit (`"64MiB"`; `B`, `KiB`, `MiB`, `GiB`, `TiB`); paths are absolute; `config.poll_interval` is longer than zero; `peer.max_uploads` and `prewarm.seeds` are at least 1; `log.filter` must parse as an `EnvFilter`. Each value parses once into a type that prints back as written. `gate.exempt.images` and `prewarm.images` stay strings until the gate compiles its globs and the reflector resolves its references.
  - The reload class lives in the type: each restart key (D47) is a `Restart<T>`.
  - `check-config` reports the file, line, column and dotted key, such as `line 22, column 1: gate.unmached: unknown field`. It checks the file alone until the agent reads containerd's config (D41, D54) and the policy and trust root (D26).
  - Two tests hold `packaging/config.toml` to the code: the uncommented file parses to `Config::default()` (D47), and its TOML equals `Config::default()` serialized, so a key missing from the file fails. A third fails when ARCHITECTURE.md, `docs/*.md` or `docs/decisions/*.md` names a dotted key in backticks that the file lacks; `docs/TODECIDE.md` is skipped, because its keys are not decided.
- **Because:**
  - Parsing at the boundary keeps an invalid value from reaching the agent, and the type's `Display` is what the reference file shows, so the second test compares literals.
  - A path relative to the agent's working directory would depend on how it was started.
  - Comparing serialized TOML catches what D47's test cannot: a file with a key missing still parses to the default.
  - `serde_path_to_error` gives the dotted key; `toml` alone names only the last segment (`unmached`).
- **Revisit when:** —


## D69: The unit is `Type=notify`, with a 30 s watchdog, and restarts on failure (amends D39, D53)

- **Decision:**
  - `packaging/speculaire.service` runs `/usr/bin/speculaire agent` with `Type=notify`, `ExecReload=/bin/kill -HUP $MAINPID` (D30), `Restart=on-failure`, `WatchdogSec=30s` and `TimeoutStopSec=20s` (D39), `RuntimeDirectoryMode=0700` and `RuntimeDirectoryPreserve=yes` (D31), and D53's settings. It starts after `network-online.target`, `containerd.service` and `crio.service`, whichever exist.
  - The agent sends `READY=1` once its status listener is open, `STOPPING=1` first on SIGTERM (D39, step 1), and `WATCHDOG=1` every half of `WATCHDOG_USEC` from a task of its tokio runtime. Outside systemd, without `NOTIFY_SOCKET`, it sends nothing.
  - e2e (D27) installs the unit, the binary and `packaging/config.toml` at the packages' paths on every node of every leg (D63), with `log.filter = "info"` so the journal holds entries to check, and runs the suites against the running unit.
- **Because:**
  - `Type=notify` makes `systemctl start` wait for the listener, so a unit that cannot bind fails its start instead of running half-started.
  - A runtime whose worker threads all block stops scheduling the ping task; systemd then kills it with SIGABRT and `Restart=on-failure` starts it again. 30 s is well past any pause the agent should have, and short against the 15 min of a pod that waits on a blocked gate.
  - Ordering after the runtime units starts the agent once the sockets it reads exist; `After=` on a missing unit is a no-op.
- **Measured (M1 step 06, `just e2e containerd 2.4 1.37` and `just e2e crio 1.37`, arm64):** the unit is active on every node with `Type=notify` and `WatchdogUSec=30s`; `systemd-analyze security` reports D53's settings set, except `SystemCallFilter=~@resources`, `RestrictAddressFamilies=~AF_UNIX` and `RestrictAddressFamilies=~AF_(INET|INET6)`, which D53 leaves open; removing `ProtectClock=` and `WatchdogSec=` from one node failed the suite; `systemctl stop` exits 0 in under a second; `/run/speculaire` survives a restart; the journal holds the agent's fields with tracing-journald's `F_` prefix, such as `F_ADDRESS=[::]:7482`.
- **Revisit when:** a component holds a thread for longer than the watchdog allows by design.