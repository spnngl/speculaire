# Decisions: gate

The NRI enforcement point. Index: `docs/decisions/README.md`.

## D9: Enforcement lives in an NRI external plugin

- **Decision:** the agent connects to `/var/run/nri/nri.sock` as an external NRI plugin. We write our own `nri` workspace crate on `ttrpc` 0.10 plus the NRI multiplexer (8-byte header: ConnID + length).
  - Each ConnID is an in-memory `tokio::io::duplex` wrapped by `ttrpc`'s `Socket::new`: ConnID 1 feeds a `Listener::new` stream, ConnID 2 feeds `Client::new`. There is no file descriptor and no `socketpair`.
  - Codegen is `ttrpc` features `async` and `prost` (prost 0.13) with `ttrpc-codegen-prost` 0.1, from NRI v0.12.3's `api.proto`; it serves both containerd 2.3 and 2.4.
  - The multiplexer writes frames of at most 4096 payload bytes, because the Go side reads a frame through a 4096-byte buffer and fails with `ENOMEM` on a larger one (`mux.go` `conn.Read`).
  - It reads like Go's multiplexer at v0.12.3: it closes the trunk on a header length above `maxPayloadSize` (`pkg/net/multiplex/mux.go:141`), and gives each ConnID its own bounded queue, so a stalled connection cannot block the other (`:349-355`).
- **Because:**
  - No Rust NRI crate exists.
  - An external plugin survives restarts; containerd never restarts a crashed pre-installed plugin.
  - NRI is the only hook that covers every container creation, however the image arrived.
  - The gate only rejects and never adjusts a container. So our NRI subset is small: registration, `Configure`, `Synchronize`, `CreateContainer` returning an error, and `Shutdown`, in about 1.5k lines. The Go helpers for adjustments, field owners, `strip.go` and `UpdateContainers` are not needed.
  - M0 spike 01 ran this on containerd 2.3.7 (NRI v0.12.0) and 2.4.2 (NRI v0.12.3): the plugin registers in under 10 ms, `Configure` carries `runtime_name=containerd`, `NRI_version=v0.12.0` or `v0.12.3`, `registration_timeout=5000ms`, `request_timeout=2000ms`, and `Synchronize` lists the same containers as `crictl ps -q`.
  - containerd names the plugin `50-speculaire` (`registered as "50-speculaire"`), but `default_validator.required_plugins` matches the bare name `speculaire`.
  - A rejection reaches the pod event as `Error: failed to create containerd container: failed to get NRI adjustment for container: rpc error: code = FailedPrecondition desc = speculaire spike: rejected`. With the plugin missing, the event is `... failed to get NRI adjustment for container: validator "00-default-validator" rejected container adjustment, reason: validation error: required plugin "speculaire" not present`. Both leave the pod in `CreateContainerError`, and kubelet retries.
  - A restarted plugin re-registers without a containerd restart, and the blocked pod then starts. A containerd restart closes the trunk, so the plugin must reconnect.
  - 2.3.7 sends no `Container.image`; it carries the annotation `io.kubernetes.cri.image-name` (D15). 2.4.2 fills `image.name`, `image.digest` and `image.config_digest`.
- **Cost:** we rewrite and keep current what the Go stub (`pkg/stub/stub.go`) and the multiplexer (`pkg/net/multiplex/mux.go`) give Go plugins (lines at NRI `main` d817e4e):
  - the registration sequence (`stub.go:594-646`);
  - the timeouts and event-mask check in `Configure` (`stub.go:701-728`);
  - the table that infers the NRI version from the runtime version (`pkg/api/version.go:35-105`), which D15 needs. The table stops at containerd v2.2.1, so it infers NRI v0.11.0 for 2.3 and 2.4, which selects D15's annotation path;
  - `Synchronize` split across several requests flagged `More` (`stub.go:741-789`). The plugin answers each chunk with `More` echoed, and replies with updates only to the last one (v0.12.3 `stub.go:720-744`).

  The test oracle (D29) checks our crate against NRI's own runtime side.
- **Revisit when:**
  - `FailurePolicy.fail_request` ships in a containerd release. Then use it instead of `required_plugins`.
  - A Rust NRI crate appears upstream (for example in `containerd/rust-extensions`). Then adopt it, or offer ours there.

## D10: The containerd image-verifier (bindir) is not in v1

- **Because:** CRI silently bypasses it through the local-pull fallback, through imports, and through `IfNotPresent` when the image is cached. The gate covers all of these cases.
- **Revisit when:** users want unsigned images rejected before download.

## D15: containerd 2.3 minimum, 2.4+ main target

- **Decision:**
  - containerd 2.3 is the minimum. 2.4+ is the main target, and new features land there first.
  - The gate derives the *image identity* in one of two ways. This is modelled as an enum, chosen once at `Configure` from the runtime's NRI version. When the runtime leaves that version empty, it is inferred from the containerd version with our copy of NRI's table (D9):
    - **2.4+:** `container.image.digest` from NRI.
    - **2.3:** resolve the normalised `io.kubernetes.cri.image-name` annotation in containerd's image store (namespace `k8s.io`) to a target digest. Then check that the container snapshot's parent (the snapshot key is the container ID) equals that image's chain ID for the node platform. For a user-namespace pod on a snapshotter without ID remapping, that parent is a remapped snapshot whose own parent is the chain ID (v2.3.0 `client/snapshotter_opts_unix.go:105-135`); the check follows that one extra level. A mismatch is `Rejected("image identity mismatch")`.
  - The agent keeps an in-memory copy of the image store, updated from events, so the 2.3 path makes at most two snapshot `Stat` calls while it holds the NRI lock.
  - On 2.3 the agent logs a warning at startup naming the residual gap below, and sets `speculaire_identity_path{path="annotation"}` to 1.
  - Preflight reads `discard_unpacked_layers` from the parsed `config.toml` on 2.3, and from introspection on 2.4.
  - CI tests both versions.
- **Because:**
  - containerd 2.3 vendors NRI v0.12.0, which has `required_plugins` (`default_validator`) but no `Container.image`. That field arrives in NRI v0.12.2; containerd 2.4 vendors v0.12.3 and fills `image.digest` with the CRI image's target digest (v2.4.0 `internal/cri/nri/nri_api_linux.go:973-988`, `internal/cri/server/container_create.go:330`).
  - containerd 2.3 and 2.4 send their NRI version in `Configure` (NRI v0.12.0 `ConfigureRequest.NRI_version`, from build info); inference covers builds without build info. Spike 01 confirmed it: 2.3.7 sends `v0.12.0` and 2.4.2 sends `v0.12.3`.
  - On 2.3 the annotation is the pod-spec string, possibly a bare tag that can be retagged between CRI resolution and the gate.
  - In containerd 2.3 the snapshot is prepared before NRI `CreateContainer` runs (v2.3.7 `internal/cri/server/container_create.go:378` `WithNewSnapshot` vs `:450` `WithContainerAdjustment`, both applied in `NewContainer` at `:462`), so the chain-ID check catches a retag to different layers.
  - M0 spike 02 measured it on containerd 2.3.7 and 2.4.2 (kind, overlayfs, busybox:1.37, linux/arm64). For 20 pods created at once, every container's snapshot existed in `CreateContainer`, its parent equalled the chain ID computed from the config's `rootfs.diff_ids`, and all pods ran. A snapshot `Stat` took a median of 0.2 ms and at most 3.2 ms; the whole check (image lookup, three blob reads, `Stat`) took at most 12.8 ms, well inside `gate.wait`. No handler deadlocked containerd.
  - A `hostUsers: false` pod on 2.3.7 (kernel 7.0.14, overlayfs) had the chain ID as its direct parent: overlayfs remaps with idmapped mounts, so there was no remapped snapshot. The extra level stays for snapshotters that remap IDs themselves.
  - On 2.4.2 `container.image.digest` equalled the image's target digest for all 20 pods.
  - The residual gap is a retag to an image with identical layers but a different config. It is accepted on 2.3 with the warning, and closed on 2.4.
- **Revisit when:** containerd 2.3 reaches end of life. Then drop the 2.3 path.

## D18: Exemptions are explicit and empty by default

- **Decision:** `gate.exempt.namespaces` (exact names) and `gate.exempt.images` (globs on the normalised pod-spec image name). Both are empty by default and logged at startup.
- **Because:** the user wants no implicit exemptions, but an escape hatch. Anyone who can create pods in an exempt namespace bypasses the gate, so the setting stays explicit.
- **Revisit when:** —

## D23: `gate.unmatched` decides images that no policy matches

- **Decision:** `gate.unmatched = "deny" | "allow"`, default `"deny"`. With `"allow"`, an image that matches no policy starts without any signature check, and is logged and counted under `speculaire_gate_total{result="unmatched"}`.
- **Because:** sites roll policies out gradually and need to let images that have no policy yet through. Denying by default is the safe side, and the user confirmed `deny` as the default.
- **Revisit when:** —

## D41: The gate answers inside containerd's NRI timeout, and reconnects at once

- **Decision:**
  - Startup and `speculaire check-config` refuse a `gate.wait` at or above half of containerd's `plugin_request_timeout`, read from containerd's `config.toml` and its `imports` (default 2 s). The error names both values.
  - When the runtime closes the NRI connection, the agent registers again at once, then retries every second until it succeeds. `speculaire_nri_connected` is 1 while registered.
- **Because:**
  - A `CreateContainer` that exceeds `plugin_request_timeout` makes NRI close the plugin and let that container start ungated, even with `required_plugins` set (NRI v0.12.0 `pkg/adaptation/plugin.go:751-763`, `adaptation.go:341-355`). Until the plugin registers again, the validator rejects every creation.
  - The whole answer must fit: `gate.wait`, plus the 2.3 snapshot check (D15).
- **Revisit when:** `FailurePolicy` ships in a containerd release (D9).

## D44: The DaemonSet's own pod carries the tolerate annotation

- **Decision:** the Helm chart installs in `kube-system`, and sets the NRI tolerate annotation chosen in `docs/operations.md` on the agent pod.
- **Because:**
  - The user chose it. Under `required_plugins`, the agent's containers are gated by the plugin they provide, so after a node reboot nothing could start them.
  - The annotation is already the accepted escape hatch for static pods (`docs/security.md`).
- **Revisit when:** containerd offers a way to exempt a plugin's own pod from validation.

## D54: The gate cannot be turned off

- **Decision:** no setting disables the gate. Startup and `speculaire check-config` refuse a containerd config whose NRI plugin is disabled or closed to external plugins (`disable = true` or `disable_connections = true` under `[plugins.'io.containerd.nri.v1.nri']`, v2.3.7 `internal/nri/config.go:30,42`), and the error names the key. `gate.mode = "audit"` and `gate.exempt` (D18) are the ways to let containers through.
- **Because:** a node that mirrors but never gates looks protected and is not. `audit` keeps the mirror and the verdicts, and the gap stays visible in `speculaire_gate_total{mode="audit"}`.
- **Revisit when:** users ask for a mirror-only deployment; then add an explicit `gate.enabled = false` that logs a warning at startup and sets a metric.
