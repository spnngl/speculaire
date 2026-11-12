# Decisions: gate

The NRI enforcement point. Index: `docs/decisions/README.md`.

## D9: Enforcement lives in an NRI external plugin (amended by D64)

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
  - Right after a containerd restart, `Synchronize` came after `Configure` with delays of up to tens of seconds, on amd64 and arm64: over 2 s in 3 of 4 CI legs of one run, over 15 s in 2 of 4 of another, and within 60 s in all 4 of a third. containerd takes the sync write lock before calling it (NRI v0.12.3 `pkg/adaptation/adaptation.go:687`), so the agent must not treat a late `Synchronize` as a failed registration.
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

## D15: containerd 2.3 minimum, 2.4+ main target (amended by D65, D81)

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

## D81: References and platforms are parsed as containerd's CRI plugin parses them, by a port that only its parser can build (amends D11, D15, D70)

- **Decision:**
  - `crates/oci` (`speculaire-oci`) holds `reference` and `platform`. A `Reference` is `domain/path` with an optional tag and digest, built only by `Reference::parse_docker_ref` (what `ParseDockerRef` makes of an image name: normalized, with `latest` when there is no tag or digest, and only the digest when there are both) or `parse_normalized_named` (the same, a missing tag staying missing). It has no constructor from parts and no `From<String>`, so one that exists is normalized. Policies match its `name()` (D11).
  - The port is of `github.com/distribution/reference` v0.6.0 (`reference.go`, `normalize.go`, `regexp.go`), which containerd v2.4.2 vendors and its CRI plugin calls (`internal/cri/server/images/image_pull.go:153`), and of go-digest v1.0.0's `Validate`. The library's regular expressions are written as a grammar; the differential tests are what holds the two together. Its quirks stay: a first segment that is not a valid domain but is a valid path makes the whole name the path, with an empty domain (`my_registry.example/app`); an upper-case first segment is a domain; the path, not the name, is limited to 255 characters; a digest uses sha256, sha384 or sha512 in lower-case hexadecimal, and nothing else, because those are the algorithms go-digest registers in containerd's binary.
  - A platform is `oci-spec`'s `Platform`: the types of an image index are the ones a walk reads. `platform` ports `github.com/containerd/platforms` v1.0.0-rc.5 (`Parse`, `Normalize`, `Format`, `FormatAll`, `Only`, `OnlyStrict`, the arm and arm64 variant rules) for Linux nodes. What a specifier leaves out comes from a `Host` (`Host::current()` in the agent, the oracle's own in the tests). A matcher for a Windows platform is refused: the library's OS version matching is not ported, and a node is Linux (D13).
  - The gate and the walks use `Matcher::only` for the node platform: it is what containerd's pull uses (`platforms.Default()` is `Only(DefaultSpec())`, `defaults_unix.go:38`), so the manifest the gate picks is one containerd may run, `arm/v8` for an `arm64` node included. `Matcher::only_strict` stays for where containerd calls `OnlyStrict` (`DefaultStrict`), none today.
  - The oracle gains `reference` (`ParseDockerRef` and `ParseNormalizedNamed`) and `platform` (`Parse`, `Normalize`, `Format`, `FormatAll`, and for each platform as a node, `Only` and `OnlyStrict`, with their `Match` and `Less` on a list of candidates).
- **Because:**
  - The gate matches policies on normalized names (D11) and picks the platform manifest (D15): a difference with containerd is a policy that does not apply to an image that runs, or a manifest that is not the one that runs. That makes a parser bug a security bug.
  - A reference that cannot be built unnormalized cannot reach a policy match unnormalized.
  - `Only`, not `OnlyStrict`, because a gate that rejected the `arm/v8` manifest of an `arm64` node would disagree with a pull that took it.
- **Measured (M2 step 02, arm64, Docker):** the differential tests send the oracle 19214 `reference` cases (the string literals of the test files of distribution/reference v0.6.0, 40 mutations of each, the e2e images, and about 70 by hand) and 3555 `platform` cases (specifiers, 20 mutations of each literal of containerd/platforms' tests, and 63 nodes against 63 candidates for `Only`, `OnlyStrict` and their `Less`), and every answer is the same. Two planted faults, no `library/` added to official images and an `arm64` matcher that does not match `arm/v8` (throwaway PR 40, closed), turned the `oracle` job red in run 43136382265: both the `reference` and the `platform` test failed.
- **Revisit when:** a Windows node is supported, or containerd 2.5 moves `platforms` or `reference`.

## D18: Exemptions are explicit and empty by default

- **Decision:** `gate.exempt.namespaces` (exact names) and `gate.exempt.images` (globs on the normalised pod-spec image name). Both are empty by default and logged at startup.
- **Because:** the user wants no implicit exemptions, but an escape hatch. Anyone who can create pods in an exempt namespace bypasses the gate, so the setting stays explicit.
- **Revisit when:** —

## D23: `gate.unmatched` decides images that no policy matches

- **Decision:** `gate.unmatched = "deny" | "allow"`, default `"deny"`. With `"allow"`, an image that matches no policy starts without any signature check, and is logged and counted under `speculaire_gate_total{result="unmatched"}`.
- **Because:** sites roll policies out gradually and need to let images that have no policy yet through. Denying by default is the safe side, and the user confirmed `deny` as the default.
- **Revisit when:** —

## D41: The gate answers inside containerd's NRI timeout, and reconnects at once (amended by D64)

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

## D54: The gate cannot be turned off (amended by D64)

- **Decision:** no setting disables the gate. Startup and `speculaire check-config` refuse a containerd config whose NRI plugin is disabled or closed to external plugins (`disable = true` or `disable_connections = true` under `[plugins.'io.containerd.nri.v1.nri']`, v2.3.7 `internal/nri/config.go:30,42`), and the error names the key. `gate.mode = "audit"` and `gate.exempt` (D18) are the ways to let containers through.
- **Because:** a node that mirrors but never gates looks protected and is not. `audit` keeps the mirror and the verdicts, and the gap stays visible in `speculaire_gate_total{mode="audit"}`.
- **Revisit when:** users ask for a mirror-only deployment; then add an explicit `gate.enabled = false` that logs a warning at startup and sets a metric.

## D64: The same NRI plugin gates CRI-O; the agent finds its runtime by its socket (amends D9, D41, D54)

- **Decision:**
  - **One plugin:** D9's `nri` crate serves containerd and CRI-O with no runtime-specific code in the NRI path. `Configure.NRI_version` may be empty.
  - **Runtime detection:** startup, `speculaire check-config` and `speculaire configure` connect to `/run/containerd/containerd.sock` and `/var/run/crio/crio.sock`. Exactly one must accept; otherwise they refuse, naming both paths and what each answered. NRI's `Configure.runtime_name` (`containerd` or `cri-o`) must then name the same runtime; on a mismatch the agent logs an error and closes the NRI connection.
  - **D41 on CRI-O:** `gate.wait` stays under half of `nri_plugin_request_timeout` under `[crio.nri]` (default `"2s"`).
  - **D54 on CRI-O:** startup and `check-config` refuse `enable_nri = false` or `nri_disable_connections = true` under `[crio.nri]` (v1.37.2 `internal/config/nri/nri.go:15-46`), and the error names the key.
  - The agent reads CRI-O's settings from `GET /config` on `crio.sock`, which answers the merged TOML of `crio.conf` and `crio.conf.d/` (v1.37.2 `server/inspect.go:140,153`; `crio status config` is its client).
- **Because:**
  - **Measured** (CRI-O spike 01, M0b): M0's `nri-spike` binary, unchanged, ran on CRI-O 1.35.10, 1.36.7 and 1.37.2 on arm64. It registers in under 1 ms, and CRI-O logs `plugin "external:50-speculaire[921]" registered as "50-speculaire" (with NRI version unknown)`. `Configure` carries `runtime_name=cri-o`, `runtime_version=1.37.2`, `NRI_version=v0.12.2`, `registration_timeout=5000ms` and `request_timeout=2000ms`; 1.36.7 and 1.35.10 send an empty `NRI_version`. `Synchronize` lists the same containers as `crictl ps -q`.
  - CRI-O 1.35 and 1.36 vendor NRI v0.11.0, and 1.37 vendors v0.12.2. v0.12.2's `api.proto` is byte-identical to v0.12.3's. v0.11.0's lacks `NRI_version`, `Container.image` and the pod-sandbox events, keeps `CREATE_CONTAINER = 4`, and its `pkg/net/multiplex/mux.go` is identical to v0.12.2's. Unknown fields are skipped by protobuf, so v0.12.3 codegen talks to all three.
  - CRI-O passes the plugin's message without a wrapper: the pod event is `Error: speculaire spike: rejected`. With the drop-in `[crio.nri.default_validator]` `nri_enable_default_validator = true`, `nri_validator_required_plugins = ["speculaire"]` and the plugin stopped, it is `Error: validator "00-default-validator" rejected container adjustment, reason: validation error: required plugin "speculaire" not present`. Both leave the pod in `CreateContainerError`. A restarted plugin re-registers without a CRI-O restart and the blocked pod starts; a CRI-O restart closes the trunk, and keeps the running containers (`crictl ps -q` unchanged).
  - CRI-O fills no `Container.image` (v1.37.2 `internal/nri/container.go:53-76`). It names the image in annotations: `io.kubernetes.cri-o.ImageName` (one of the image's names in the store, unrelated to the pod's, `internal/storage/image.go:58-60`), `io.kubernetes.cri-o.Image` and `io.kubernetes.cri-o.ImageRef` (the 64-hex image ID), and `io.kubernetes.cri-o.ImageRepoDigests` (`repo@sha256:…`, comma-separated). D65 chooses among them.
  - Probing the sockets needs no setting: the CRI-O node image keeps containerd installed but disabled, and `/run/containerd/` does not exist there. `Configure` cannot decide it alone, because preflight and `configure` run before NRI connects.
- **Cost:** two runtime configs to read, from a file and its imports for containerd and from an HTTP endpoint for CRI-O.
- **Revisit when:** CRI-O fills `Container.image`, or a node runs both runtimes.


## D65: On CRI-O the image identity is CRI-O's image ID, read from its annotations (amends D11, D15, D20, D21, D22)

- **Decision:**
  - **Identity:** in `CreateContainer` on CRI-O, the *image identity* is the `io.kubernetes.cri-o.ImageRef` annotation, CRI-O's image ID, which is the config digest of the platform manifest the image was pulled by. The gate reads it from the NRI request and makes no lookup.
  - **Verdict:** the verifier records the config digest of every platform manifest it verifies. On CRI-O, the verdict for an image ID is `Allow` when a verified target digest whose platform manifest has that config digest has `Allow`. Otherwise it is the verdict of those digests, and `Unverifiable("image ID is not a config digest")` when none has that config digest (D20).
  - **Policy match (D11):** CRI-O passes no pod-spec image name. The names are every repository and tag the image ID has in the agent's copy of CRI-O's image list, and an image must pass every policy any of them matches.
  - **Image list and events (D21, D22):** the agent watches the directory of `images.json` in CRI-O's storage (`<root>/<driver>-images/`, `root` and `storage_driver` from `GET /config`, D64) with inotify. On a change it reads the list with CRI `ListImages` on `crio.sock`. That change is D22's second trigger on CRI-O, and the list is the one D21 re-verifies. The agent parses no storage file.
  - **Pinning:** the agent does not pin prewarmed images on CRI-O.
- **Because:**
  - **Measured** (CRI-O spike 02, M0b, CRI-O 1.35.10, 1.36.7 and 1.37.2, locally on arm64 and in CI run 43012287495 on amd64 and arm64): for 20 pods created at once, all `Running`, and one `hostUsers: false` pod, `ImageRef` equalled the config digest of `busybox:1.37`'s manifest for the node's platform. Locally the `hostUsers: false` pod ran in a user namespace. On GitHub's runners runc then failed to mount sysfs for it inside the kind node (`operation not permitted`), after `CreateContainer`. The value is in the request, so the lookup takes no time and cannot stall CRI-O.
  - CRI-O sets `ImageRef` and `ImageRepoDigests` after it copies the pod's annotations (v1.37.2 `internal/factory/container/container.go:226-275`). A pod annotated with a forged `io.kubernetes.cri-o.ImageRef` and `io.kubernetes.cri-o.ImageName` reached the plugin with the real values.
  - CRI-O creates the container's storage from that image ID (`server/container_create.go:1633-1635,1703`) before `s.nri.createContainer` (`:1168`). go.podman.io/image v5.40.0 makes the image ID the config digest (`storage/storage_dest.go:786,836`) and checks each layer against the config's `rootfs.diff_ids`, so the ID binds the root filesystem. D15's chain-ID check adds nothing here.
  - zstd:chunked partial pulls still compute each layer's uncompressed digest (go.podman.io/storage v1.63.0 `pkg/chunked/storage_linux.go:1871-1880`). An `alpine:3.22` copy pushed with `--dest-compress-format zstd:chunked`, pulled with `enable_partial_images = "true"`, kept the config digest as its ID, and `layers.json` recorded its `toc-digest`. Only `insecure_allow_unpredictable_image_contents = "true"` (`:148`) makes the ID a TOC digest (`storage_dest.go:840-859`), and that image is `Unverifiable`.
  - One image ID gathers every manifest pulled for it, and `RepoDigests` pairs each of its repositories with each of those digests. After the zstd:chunked copy of `busybox:1.37` came from a local registry, `docker.io/library/busybox@sha256:0b43d29a…` was listed though Docker Hub never served it. Repository digests do not name the source, so they are verification inputs, not identity. A config digest commits to the layers' uncompressed digests, so every manifest with that config digest yields the same root filesystem.
  - `ImageName` is any one of the image's names (`internal/storage/image.go:58-60`), and `io.kubernetes.cri-o.Image` is the image ID kubelet resolved. CRI-O reads CRI's `user_specified_image` only for its own signature check (`server/container_create.go:1710-1713`), and puts it in no annotation.
  - CRI-O streams container events only (`server/container_events.go:29`). `images.json` was rewritten at most 5 ms before `crictl pull` returned and 13 ms before `crictl rmi` returned; go.podman.io/storage replaces it by rename (`images.go:566-586`), so the watch is on the directory.
  - A `pinned_images` drop-in under `/etc/crio/crio.conf.d/` and `systemctl reload crio` kept `nginx:alpine` through `crictl rmi --prune` on all three versions (`server/server.go:701-745`). It needs write access to CRI-O's configuration and a signal to CRI-O, and a drop-in's list replaces the admin's `pinned_images`. Without pinning, kubelet's image GC may remove a prewarmed image under disk pressure, and the next pull fetches it again from peers.
- **Cost:** a pod-spec name matched by no policy can still be held to a policy through another name of the same image, so CRI-O can reject what containerd allows.
- **Revisit when:** CRI-O fills `Container.image` or passes `user_specified_image`, or gains a pin that does not edit its configuration.
