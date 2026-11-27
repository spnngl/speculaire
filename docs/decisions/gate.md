# Decisions: gate

The NRI enforcement point. Index: `docs/decisions/README.md`.

## D9: Enforcement lives in an NRI external plugin (amended by D64, D163, D166, D180, D198)

- **Decision:** the agent connects to `/var/run/nri/nri.sock` as an external NRI plugin. We write our own `nri` workspace crate on `ttrpc` 0.10 plus the NRI multiplexer (8-byte header: ConnID + length).
  - Each ConnID is an in-memory `tokio::io::duplex` wrapped by `ttrpc`'s `Socket::new`: ConnID 1 feeds a `Listener::new` stream, ConnID 2 feeds `Client::new`. There is no file descriptor and no `socketpair`.
  - Codegen is `ttrpc` features `async` and `prost` (prost 0.13) with `ttrpc-codegen-prost` 0.1, from NRI v0.12.3's `api.proto`; it serves both containerd 2.3 and 2.4.
  - The multiplexer writes frames of at most 4096 payload bytes, because the Go side reads a frame through a 4096-byte buffer and fails with `ENOMEM` on a larger one (`mux.go` `conn.Read`).
  - It reads like Go's multiplexer at v0.12.5: it closes the trunk on a header length above `maxPayloadSize` (`pkg/net/multiplex/mux.go:325-336`), and gives each ConnID its own bounded queue, so a stalled connection cannot block the other (`:360-367`). D163 holds the details.
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

## D15: containerd 2.3 minimum, 2.4+ main target (amended by D65, D81, D86, D167, D169, D170)

- **Decision:**
  - containerd 2.3 is the minimum. 2.4+ is the main target, and new features land there first.
  - The gate derives the *image identity* in one of two ways. This is modelled as an enum, chosen once at `Configure` from the runtime's NRI version. When the runtime leaves that version empty, it is inferred from the containerd version with our copy of NRI's table (D9):
    - **2.4+:** `container.image.digest` from NRI.
    - **2.3:** resolve the normalised `io.kubernetes.cri.image-name` annotation in containerd's image store (namespace `k8s.io`) to a target digest. Then check that the container snapshot's parent (the snapshot key is the container ID) equals that image's chain ID for the node platform. For a user-namespace pod on a snapshotter without ID remapping, that parent is a remapped snapshot whose own parent is the chain ID (v2.3.0 `client/snapshotter_opts_unix.go:105-135`); the check follows that one extra level. A mismatch is `Rejected("image identity mismatch")`.
  - The agent keeps an in-memory copy of the image store, updated from events, so the 2.3 path makes at most two snapshot `Stat` calls while it holds the NRI lock. D167 holds how.
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

## D18: Exemptions are explicit and empty by default (amended by D172)

- **Decision:** `gate.exempt.namespaces` (exact names) and `gate.exempt.images` (globs on the normalised pod-spec image name). Both are empty by default and logged at startup.
- **Because:** the user wants no implicit exemptions, but an escape hatch. Anyone who can create pods in an exempt namespace bypasses the gate, so the setting stays explicit.
- **Revisit when:** —

## D23: `gate.unmatched` decides images that no policy matches

- **Decision:** `gate.unmatched = "deny" | "allow"`, default `"deny"`. With `"allow"`, an image that matches no policy starts without any signature check, and is logged and counted under `speculaire_gate_total{result="unmatched"}`.
- **Because:** sites roll policies out gradually and need to let images that have no policy yet through. Denying by default is the safe side, and the user confirmed `deny` as the default.
- **Revisit when:** —

## D41: The gate answers inside containerd's NRI timeout, and reconnects at once (amended by D64, D168, D198)

- **Decision:**
  - Startup and `speculaire check-config` refuse a `gate.wait` at or above half of containerd's `plugin_request_timeout`, read from containerd's `config.toml` and its `imports` (default 2 s). The error names both values.
  - When the runtime closes the NRI connection, the agent registers again at once, then retries every second until it succeeds. `speculaire_nri_connected` is 1 while registered.
- **Because:**
  - A `CreateContainer` that exceeds `plugin_request_timeout` makes NRI close the plugin and let that container start ungated, even with `required_plugins` set (NRI v0.12.0 `pkg/adaptation/plugin.go:751-763`, `adaptation.go:341-355`). Until the plugin registers again, the validator rejects every creation.
  - The whole answer must fit: `gate.wait`, plus the 2.3 snapshot check (D15).
- **Revisit when:** `FailurePolicy` ships in a containerd release (D9).

## D44: The DaemonSet's own pod carries the tolerate annotation (amended by D209)

- **Decision:** the Helm chart installs in `kube-system`, and sets the NRI tolerate annotation chosen in `docs/operations.md` on the agent pod.
- **Because:**
  - The user chose it. Under `required_plugins`, the agent's containers are gated by the plugin they provide, so after a node reboot nothing could start them.
  - The annotation is already the accepted escape hatch for static pods (`docs/security.md`).
- **Revisit when:** containerd offers a way to exempt a plugin's own pod from validation.

## D54: The gate cannot be turned off (amended by D64, D86, D180, D198)

- **Decision:** no setting disables the gate. Startup and `speculaire check-config` refuse a containerd config whose NRI plugin is disabled or closed to external plugins (`disable = true` or `disable_connections = true` under `[plugins.'io.containerd.nri.v1.nri']`, v2.3.7 `internal/nri/config.go:30,42`), and the error names the key. `gate.mode = "audit"` and `gate.exempt` (D18) are the ways to let containers through.
- **Because:** a node that mirrors but never gates looks protected and is not. `audit` keeps the mirror and the verdicts, and the gap stays visible in `speculaire_gate_total{mode="audit"}`.
- **Revisit when:** users ask for a mirror-only deployment; then add an explicit `gate.enabled = false` that logs a warning at startup and sets a metric.

## D64: The same NRI plugin gates CRI-O; the agent finds its runtime by its socket (amends D9, D41, D54; amended by D84, D86, D90, D169)

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


## D65: On CRI-O the image identity is CRI-O's image ID, read from its annotations (amends D11, D15, D20, D21, D22; amended by D169, D172, D191)

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

## D86: One preflight stops the agent and fails `check-config` on a node where it would mirror or gate wrongly (amends D15, D54, D64; amended by D90)

- **Decision:**
  - **One function:** `speculaire_configure::preflight` returns every problem of the node, each naming the file or socket and what to set. `speculaire agent` runs it before it opens a listener and exits 1 with `N problems on this node keep the agent from starting (<runtime>):` and one line each, as `<file or socket>: <message>`. `speculaire check-config` prints the same lines, plus what D82 and D83 check (`hosts.toml` entries, the CRI-O drop-in's text), each once, and exits 1 with their count. Both stop (D54): no flag skips preflight, as none turns the gate off.
  - **Both runtimes:** `RuntimeService.Version` over the CRI on the runtime's socket (`/runtime.v1.RuntimeService/Version`, hand-written prost messages, 5 s). The runtime must answer as itself (`containerd` or `cri-o`, D64), report a `runtime_version` of the form `[v]major.minor.patch[-pre][+build]`, and be at least the floor: containerd 2.3.0 (D15), CRI-O 1.35.0, the oldest Kubernetes minor that kind ships (D63). There is no ceiling: a newer runtime starts, and the e2e window (D63) is what is tested. The mirror's certificates are those `check` reads (D55, D82), and `mirror.address` is loopback by its type at config load (D56).
  - **containerd NRI:** from the merged `config.toml` and its imports: `disable = true` and `disable_connections = true` under `[plugins.'io.containerd.nri.v1.nri']`, and the plugin named in `disabled_plugins`, each its own problem (D54). A node without a config file runs on containerd's defaults, which are all fine.
  - **containerd image service:** on 2.4 and later, from what the running service exports through introspection (`Plugins`, type `io.containerd.cri.v1`, id `images`): `DiscardUnpackedLayers` must be `false` and `RegistryConfigPath` non-empty (v2.4.2 `plugins/cri/images/plugin.go:170`). A service that is not listed, or has no exports, is a problem naming the socket. On 2.3, which exports nothing (v2.3.7 `plugins/cri/images/plugin.go:235-260` has none), from the parsed `config.toml`: `discard_unpacked_layers` of the image service, and `config_path` set (`mirrors` in use is the problem). A version 1 to 3 config keeps `discard_unpacked_layers` under `[plugins.'io.containerd.grpc.v1.cri'.containerd]`, and containerd's migration copies it only when that table also has `runtimes` (`migrateConfig`, which returns before its copy otherwise); the parser does the same, with the type assertions that panic containerd as errors (D78).
  - **CRI-O:** `enable_nri = true` and `nri_disable_connections = false` under `[crio.nri]`, from `GET /config` (D64: `Nri::parse`, fuzzed by `crio_inspect` since M2 step 03), and the drop-in present (D66).
  - **Each message** names the key, the section when two spellings exist, why it matters, what to set, and that the runtime restarts after the change.
  - **Readiness:** the status listener opens first, and `/readyz` answers 503 until the mirror listens, then 200 (D45); `/livez` answers 200 throughout. An agent that cannot open the mirror stops.
- **Because:**
  - A node that is wrong in one of these ways looks protected and is not: no NRI means no gate (D54), a discarded layer is one the node cannot serve, and without `config_path` no pull reaches the mirror.
  - The running service is what counts on 2.4, and it answers the question without parsing a file that its own migrations rewrite. 2.3 offers no such answer, so the file, parsed as containerd parses it (the differential tests), is the only source.
  - One list of problems gives `check-config` exactly what the unit prints in the journal, so the admin sees the refusal before the restart.
  - The CRI-O floor follows the Kubernetes minors the support window names (D63), so a CRI-O older than the oldest tested one is the unsupported case, as for containerd.
- **Measured (M2 step 05, arm64, Docker):**
  - The config cases of the oracle now include `discard_unpacked_layers`, the NRI keys and `disabled_plugins` (D79): 1682 of 1692 cases agree with containerd v2.4.2's own loader; the other 10 have no stable answer, as before (v1 plugin renames collide in a map).
  - On kind nodes the agent starts and passes preflight on containerd 2.3.7, containerd 2.4.2 and CRI-O 1.37.2; `check-config` exits 0 on every node of each. A second agent on a worker, given no certificates, a socket that nothing listens on, or (containerd) a config with `disable = true`, stops with the line of the key and exits 1 (`e2e/tests/preflight.rs`).
  - kindest/node ships `/etc/containerd` as `0644`, a directory root without capabilities (D53) cannot enter: the agent's first start on containerd 2.3.7 failed with `Permission denied` on `config.toml`. The e2e node image sets `0755`.
  - `fuzz runtime_version` (60 s budget, 20 s run): 135953 runs, no finding; `containerd_config`, now also through `load_plugins`: 91091 runs in 60 s, no finding.
- **Revisit when:** containerd 2.3 reaches end of life (then drop the config-file path of the image settings), or CRI-O reports its version in another form.

## D163: The NRI multiplexer is `speculaire-nri`'s `Mux`, which closes the trunk as NRI v0.12.5 does (amends D9)

- **Decision:**
  - **Crate:** `crates/nri` (`speculaire-nri`) speaks NRI's protocol and knows no runtime. `Mux::new(reader, writer)` returns the multiplexer and its `Connections`: `plugin_service` (ConnID 1) and `runtime_service` (ConnID 2), each `AsyncRead + AsyncWrite` for ttrpc. `Mux::run` carries frames until the trunk ends and returns why (`MuxError`); the caller spawns it, the crate spawns nothing.
  - **Reading,** as `pkg/net/multiplex/mux.go` at v0.12.5 reads: the 8-byte header is read in place (D107). A length over `maxPayloadSize`, 10 bytes plus 4 MiB, closes the trunk with `Oversize { conn, length }` before anything is allocated for it (`mux.go:325-336`). Each ConnID has a queue of 256 payloads (`readQueueLen`, `:138`), and the reader never waits for one: a frame for a full queue closes the trunk with `QueueFull { conn, length, capacity }` (`:360-367`). A frame for another ConnID, or for a dropped `Connection`, is read and dropped (`:357-368`).
  - **Ending:** a connection reads the payloads queued, then the end of file if the trunk ended between two frames, else `ConnectionAborted`, also when `run`'s future is dropped. It skips an empty payload, which would read as the end of file. Its writes fail once the trunk is closed.
  - **Writing:** a connection's writes go out in frames of at most 4096 payload bytes (D9), each written whole, through one heap buffer per connection.
  - **Checks:** the fuzz target `nri_mux` reads the trunk and compares the end and each connection's bytes with a plain model of the frames. Kani proves, for every 8-byte header, that the decoder reads both fields big-endian and yields no length over the maximum (`just kani`, the `kani` job of `deep.yml`, Kani 0.68.0, Linux only). Shuttle runs a stalled ConnID 2 beside a reading ConnID 1 over 2000 random schedules (`just shuttle`).
- **Because:**
  - D9 cited `mux.go:141` at v0.12.3 for the close on an oversize header, but v0.12.3 has no such check: it allocates `make([]byte, int(cnt))` for any length (`:325`). The check landed in v0.12.5, so a runtime on NRI v0.12.0 to v0.12.4 still allocates what its plugin claims; ours refuses whichever the peer.
  - The trunk's peer is the runtime, root on the node: the limits stop a broken frame from taking memory, not a hostile runtime. 256 payloads of up to 4 MiB per queue is Go's own bound.
  - Draining the queue before the end gives a connection every answer that came before a close; Go's `conn.Read` picks between the two at random.
  - A future, not a task, keeps the crate off any runtime, and lets Shuttle and the fuzz target drive it.
- **Measured (M6 step 01, arm64):**
  - Kani: 1 harness, 100 checks, 0.15 to 0.4 s. With the check moved one byte up it fails on `claimed <= MAX_PAYLOAD`.
  - Shuttle: 2000 schedules in 0.2 s; with the queue unbounded it reports a deadlock. A 4104-byte array inside `run`'s future overflowed Shuttle's 32 KiB task stack, which is why the write buffer is on the heap.
  - `just fuzz nri_mux 120`: 365924 runs in 121 s, 305 edges, no finding.
- **Revisit when:** NRI changes its framing, `readQueueLen` or `maxPayloadSize`, or ttrpc needs a half-closed connection.


## D166: `speculaire-nri` speaks NRI's plugin protocol on its own ttrpc subset, and infers the NRI version as NRI does (amends D9; amended by D189)

- **Decision:**
  - **ttrpc:** the crate implements ttrpc's unary calls itself, as containerd/ttrpc v1.2.7 frames them: a 10-byte header read in place (D107), then a protobuf `Request` or `Response`, at most 4 MiB (`channel.go:31`). Messages are generated by `prost-build` 0.14, the workspace's, from copies of the messages NRI v0.12.3's `pkg/api/api.proto` and ttrpc's `request.proto` use, each field kept with its upstream number, the others left out; a decoder skips fields it does not know. No `ttrpc` crate, no `ttrpc-codegen-prost`.
  - **Session:** `serve(reader, writer, &handler, registration_timeout)` plays the plugin on a connected socket until the session ends, and returns why (`End`: `Shutdown`, `Closed`, `Lost(MuxError)`, `Registration`, `Oversize`). The caller connects, and reconnects (D41); the crate spawns nothing. It registers on ConnID 2 as `speculaire`, index `50`, NRI version `v0.12.3`, within `registration_timeout` (`REGISTRATION_TIMEOUT`, 5 s, as `pkg/stub`), while it already serves ConnID 1, since NRI configures a plugin before it answers the registration (`pkg/adaptation/plugin.go:436-459`). It then drops ConnID 2.
  - **Calls,** as `pkg/stub/stub.go` v0.12.3 answers them: `Configure` (`:658-715`) gives the handler a `Configuration` (runtime name and version, both timeouts, the NRI version) and subscribes to `CREATE_CONTAINER` alone, mask 8; a mask of 0 would subscribe to every event (`plugin.go:490-497`). `Synchronize` (`:717-766`) answers each part with its `more` echoed and no update, and hands the handler every pod and container with the last part. `Shutdown` (`:768-774`) is answered, and the session ends when the runtime closes. Any other method answers `UNIMPLEMENTED`, a request that does not decode `INVALID_ARGUMENT`, and the session goes on; a ttrpc message over 4 MiB, which NRI's ttrpc never sends, ends it.
  - **CreateContainer:** `Handler::create_container(&request, deadline)` answers `Answer::Allow` or `Answer::Reject(reason)`, which goes back as `FAILED_PRECONDITION` with the reason, as the spike's did (D9). The deadline is the request's receipt plus its ttrpc `timeout_nano`, else Configure's request timeout, else NRI's default 2 s. Requests are answered concurrently, inside the session's future (`FuturesUnordered`); at the deadline the handler's future is dropped and the runtime gets `DEADLINE_EXCEEDED`. Past `MAX_IN_FLIGHT` (256) requests in flight, one more gets `Handler::overloaded` at once.
  - **NRI version:** when Configure's `NRI_version` is empty, `0.0.0-unknown` or `(devel)`, the plugin infers it as the stub does (`:671-680`), with `version::infer(runtime, version)`, a port of `pkg/api/version.go:34-205` and `pkg/version/version.go:65-119` over a port of golang.org/x/mod v0.32.0's semver; `NriVersion` is `Announced`, `Inferred` or `Unknown` with the reason. The table keeps only the releases where the NRI version changes, which answers the same for every version. CRI-O announces its version without a `v`, so neither NRI nor the port infers one for it (`docs/TODECIDE.md`).
  - **Checks:** `crates/nri/tests/oracle.rs` runs the plugin against `speculaire-oracle nri-runtime` (D162) and `infer` against `nri-version` on every tag of `crates/nri/tests/versions.txt`, each also without its `v`, the `justfile`'s runtime pins and edge cases of the semver port; a test fails when a pin is missing from the list. The fuzz target `nri_request` reads ttrpc messages and round-trips each request.
- **Because:**
  - `ttrpc` 0.10 builds on prost 0.13 against the workspace's 0.14, and brings about twenty crates more to vet (`nix` 0.26, `crossbeam`, `async-stream`, `tokio-vsock`, `thiserror` 1, and `prost-build` 0.13 with `protoc` at build). Its async server spawns a task per request with no bound (`src/asynchronous/server.rs:478` at v0.10.0), so it cannot answer past a limit at once. The unary subset is about 300 lines; the reflector made the same call (D105).
  - Answering in one future keeps the crate off any runtime and the in-flight bound in one place; a slow verdict holds one slot, not the connection.
  - NRI closes a plugin whose answer to a split `Synchronize` is not the request's `more`, or carries updates (`plugin.go:536-542`), and gives the whole split one request timeout (`:504-567`).
- **Measured (M6 step 02, arm64):** 400 containers of 25 KiB, 10 MiB, reach the handler once each from 3 `Synchronize` requests; the oracle reports `CREATE_CONTAINER` as the only event, and the handler's deadline lies within the 1.5 s request timeout. `infer` agrees with NRI on 107 runtime versions. A CreateContainer sent while another is held 1 s is answered within 50 ms, and the 257th in flight gets `overloaded` within 50 ms. The new code is about 960 lines besides tests: `plugin.rs` 400, `ttrpc.rs` 305, `version.rs` 255.
- **Revisit when:** the gate needs a call outside D9's subset or a ttrpc stream, or NRI changes ttrpc's framing or its version table's semantics.

## D167: containerd's image store is a lock-free copy kept by events, and the snapshot check follows a remap only where the container's snapshot names ID mappings (amends D15; amended by D170)

- **Decision:**
  - **Image store:** `containerd::store::Store` holds the `k8s.io` image store as name → target digest, behind an `ArcSwap`. `Store::get(name)` borrows the normalised name and returns the digest, which is inline: no lock and no allocation (D107). `Containerd::keep(&store)` fills it with one images `List`, then subscribes to `/images/create`, `/images/update` and `/images/delete` in `k8s.io`. A create or update is followed by a `Get` of that name, as the events carry no digest (v2.3.7 and v2.4.2 `core/metadata/images.go:169,270,337`); a delete removes it. It lists again 1 s after each subscription, every 60 s, and after the stream drops, as the inventory does (D99). Each change publishes a new map; nothing is held across an `await`.
  - **Snapshot base:** `Containerd::snapshot_base(snapshotter, key, chain)` makes one snapshots `Stat` and returns the parent. It makes a second, and returns the grandparent, only when the parent is not `chain` and the container's snapshot carries `containerd.io/snapshot/uidmapping` or `gidmapping`. The caller picks the snapshotter (D171).
  - **Chain ID:** `speculaire_oci::chain::of_config` reads `rootfs.diff_ids` and computes the OCI chain ID without allocating per layer.
  - Both are inherent methods of `Containerd`, reached through `NodeContent::Containerd`: CRI-O has neither (D65), so no trait of D90 grows.
  - The fake containerd answers images `List` and `Get`, snapshots `Stat` (counted), and events a test publishes or cuts.
- **Because:**
  - v2.3.7 `client/snapshotter_opts_unix.go:62-136` adds the remapped snapshot only when the snapshotter lacks the `remap-ids` capability and the labels are set; the labels are copied onto the container's snapshot. The labels without a remapped parent mean a snapshotter that maps IDs itself, so comparing the direct parent first covers both without reading the snapshotter's capabilities.
  - Events then `Get` keep the store one round trip behind containerd; the relist after subscribing covers an image created between the list and the subscription, which containerd does not replay.
- **Measured (M6 step 07a, arm64):**
  - `store_get` in a store of 1000 names: median 42 ns, no allocation; `chain` of 16 layers: median 3.7 µs, no allocation (`just bench-micro`).
  - On the fake containerd, a create, a retag and a delete each showed in the store within 12 ms; an image created while the event stream was cut was found after it returned.
  - On kind with containerd 2.3.7 (overlayfs), the store listed the worker's 28 images as `ctr -n k8s.io images ls` does, and each running container's snapshot parent equalled its image's chain ID with one `Stat`; the suite took 0.8 s. The configs of `kindnetd` (an OCI index, 4 layers) and `kube-proxy-arm64` (a Docker manifest, 3 layers) are recorded in `fuzz/seeds/image_config/` with their parents.
- **Revisit when:** containerd 2.3 reaches end of life (D15), or containerd's image events carry the target.

## D168: The gate registers once the verdicts are loaded, is ready once `Configure` names the node's runtime, and keeps one `speculaire_build_info` series at 1 (amends D41, D45, D61, D68)

- **Decision:**
  - **Connection:** once the verdicts are loaded and the mirror listens, `crates/agent/src/gate.rs` connects to `nri.socket` and plays `speculaire_nri::serve` on it. When the session ends, it connects again at once if the session lasted 1 s or more, else 1 s after the last attempt, until it succeeds (D41). A socket that refuses warns once, then logs at debug until it accepts. On SIGTERM the gate disconnects last (D39 step 6).
  - **Ready:** `/readyz` counts the gate as ready from the moment it answers a `Configure` that names the node's runtime, without waiting for `Synchronize`, and as not ready from the moment the session ends. `speculaire_nri_connected` follows the same state.
  - **Runtime mismatch (D64):** a `Configure` whose `runtime_name` is not the detected runtime's (`containerd` or `cri-o`, as `speculaire_runtime::detect::Runtime::name` gives them) logs an error naming both, closes the connection, and the gate does not connect again until the agent restarts.
  - **Request timeout:** a `Configure` whose request timeout is at most twice `gate.wait` logs an error naming both values and keeps the connection. Preflight and `check-config` stay the check that refuses (D41, D64); `Configure` reports what the runtime actually gives, which can differ when the runtime's config changed after the agent started.
  - **`speculaire_build_info`:** each `Configure` sets the series with the runtime, `runtime_version` and `nri_version` it carries to 1, and the series it named before, first the empty one of D61, to 0. `nri_version` is Configure's, else the one NRI's inference gives (D166), else empty, as on CRI-O 1.35 and 1.36. Queries select the series at 1.
  - Until the gate checks images, it allows every container.
  - Where no runtime runs (`apps/speculaire/tests/agent.rs`, `just load`, `just conformance`), the fake runtime's NRI registers the gate: `Fake::start_nri` plays NRI's runtime side with `speculaire_nri::testing`, behind the crate's `testing` feature (D86, D87).
- **Because:**
  - The recorder cannot drop a series once registered (`metrics-exporter-prometheus` 0.18.3 keeps every key it has seen), so D61's empty series could only stay at 1 or go to 0; a value of 0 keeps `speculaire_build_info == 1` true for one series per agent.
  - `Synchronize` came tens of seconds after `Configure` after a containerd restart (D9); waiting for it would hold `/readyz` at 503 for no gate decision, since CreateContainer reaches a configured plugin.
  - Retrying a runtime that names another runtime would retry forever against a node whose detection already disagrees with NRI; a restart redoes the detection.
- **Measured (M6 step 05, arm64):**
  - Against `speculaire-oracle nri-runtime` (NRI v0.12.3), the gate registered again 459 to 468 ms after a runtime came back, and within the 2 s the test allows after the oracle closed its plugins.
  - On kind, `/readyz` and `speculaire_nri_connected` read every 20 ms on a worker: `systemctl restart containerd` (2.4) gave 503 from 36 ms and 200 again at 894 ms; `systemctl restart crio` (1.37) 503 from 68 ms and 200 again at 878 ms. An agent held from its NRI socket answered 503, then 200 about 630 ms after the socket appeared, on both.
  - The gate is 205 lines besides tests, `speculaire_nri::testing` 102.
- **Revisit when:** the recorder can remove a series, or NRI makes plugins wait for `Synchronize` before CreateContainer.

## D169: The gate reads the image identity through one `Identity`, chosen by the runtime at `Configure`; on CRI-O it maps the image ID to the image's listed manifests (amends D15, D64, D65; amended by D170, D171, D172, D179)

- **Decision:**
  - **Trait:** `speculaire_runtime::identity::Identity::identify(&PodSandbox, &Container)` (D171) gives an `Identified`: `Listed { digest, name }`, `Image(Arc<Image>)` or `Unknown(reason)`. `NodeIdentity::of(runtime)` gives one enum, as `NodeContent` is, because the trait is async for step 07's `annotation` path and so has no `dyn` form (D90). The gate builds it once, so its copy of the image list outlives a connection, and sets `speculaire_identity_path{path}` to 1 at `Configure`, with `path` `nri` or `image_id` from `NodeIdentity::path()`. CRI-O logs no identity warning.
  - **Choice:** by runtime name, not NRI version: containerd gets `nri`, CRI-O gets `image_id` whatever NRI version it announces. Step 07 adds `annotation`, for containerd below NRI v0.12.2, and with it the version check at `Configure`.
  - **`nri`:** the identity is `Container.image.digest`, the image's target digest, and the name is `Container.image.name` (D179 makes it the pod's). A request without both is `Unknown("no image identity in the request")`.
  - **`image_id`:** the image ID of `io.kubernetes.cri-o.ImageRef` selects the image in a copy of CRI-O's image list, an `ArcSwap` map that `NodeIdentity::keep(&List)` replaces at each list change; the lookup allocates nothing. The identity is every repository digest of the image, each digest once; the names are every repository it has by a repository digest or a tag. An image ID the list lacks is `Unknown("image ID is not a config digest")`. The verifier records no config digest: CRI-O's own list stands for D65's "platform manifest has that config digest".
  - **Verdict:** `Verdicts::identified(&identified, &policies, root)` gives each listed manifest the worst verdict of the names' policy groups (D151). The image is `Allow` when one manifest is; otherwise it has the first of `Pending`, `Rejected`, `Unverifiable` that a manifest has. No manifest, or no identity, is `Unverifiable` with the reason above. Names no policy matches give no verdict, which step 08 decides on.
- **Because:**
  - **Measured** (M6 step 06, arm64, kind, requests recorded by an NRI plugin into `crates/runtime/tests/recorded/`): containerd 2.4.2 announced NRI v0.12.3. For a pod by `busybox:1.37` and one by its linux/arm64 manifest digest, `Container.image` carried the same `digest`, the index `sha256:a7dbc319…`, and the same `name`, `docker.io/library/busybox:1.37`, with `config_digest` the image ID. containerd fills them from the image the CRI image's first reference names (v2.4.2 `internal/cri/server/container_create.go:329-331`, `helpers.go:169-175`), so the digest is the index of a multi-platform image and the name a tag where one exists, not the pod's string. The index is a repository digest containerd lists for that image, so the engine keys verdicts by it (D151).
  - CRI-O 1.37.2 announced NRI v0.12.2, which has `Container.image`, but left it empty (v1.37.2 `internal/nri/container.go:53-76`). CRI-O 1.35 and 1.36 announce no version that NRI's inference reads (D166). The NRI version tells neither apart; the runtime name tells both.
  - On CRI-O, busybox pulled by `docker.io/library/busybox:1.37` and `mirror.gcr.io/library/busybox:1.37` was one image ID with four repository digests over two digests, and two names. Each pod's request named the same `ImageRef`.
  - Any manifest of the image yields the same root filesystem (D65), so an `Allow` on one allows the image. A rejection is final and tells its reason, so it comes before an unverifiable verdict that retries.
  - The runtime already decides what runs; its image list is no wider trust than the image it runs.
- **Cost:** with `insecure_allow_unpredictable_image_contents = "true"`, an image ID that is a TOC digest still maps to the image's manifests, so the gate no longer makes that image `Unverifiable` as D65 did (`docs/security.md`, `docs/TODECIDE.md`). `Verdicts::identified` parses each name and allocates; step 08 measures it.
- **Revisit when:** CRI-O fills `Container.image`, or containerd names the platform manifest in `Container.image.digest`.


## D170: On containerd below NRI v0.12.2, the gate resolves the image name annotation in its image store and rejects a container whose snapshot is not on that image's layers (amends D15, D167, D169; amended by D171, D189)

- **Decision:**
  - **Choice:** on containerd, each `Configure` picks the path by NRI version, announced or inferred (D166): `nri` from v0.12.2, `annotation` below and when the version does not parse. CRI-O stays `image_id`. `NodeIdentity::configure(&NriVersion)` gives the path; the gate sets its `speculaire_identity_path` series to 1 and the one it replaces to 0. On `annotation` it logs a warning naming the identity gap at each registration. `Node::identity()` builds the `NodeIdentity`, which keeps the image store (D167) from the gate's start on containerd, whatever the path.
  - **Name:** `io.kubernetes.cri.image-name`, parsed and normalised as `ParseDockerRef` does (D81), selects the target digest in `Store`. No parsable annotation is `Unknown("no image identity in the request")`; a name the store lacks is `Unknown("image name not in containerd's image store")`.
  - **Chain ID:** the target is read from containerd's content store. An index gives the platform manifest `Index::platform_manifest` picks for the node (D81), with OCI and Docker manifest media types exact; a manifest is read as is. Its config gives the chain ID (D167). The chain ID is kept per target digest, both content-addressed, in a map of at most 4096 entries emptied when full; the lock is never held across an `await`. A blob missing or over 4 MiB, a nested index or no image for the platform is `Unknown("image layers cannot be read")`.
  - **Snapshot:** `snapshot_base` with the container ID as key, in the snapshotter of the pod's runtime handler (D171), read from `config.toml` at each `Configure` (a config that cannot be read keeps the ones read before, as containerd keeps running on it). Any `Stat` error is `Unknown("container snapshot cannot be read")`.
  - **Verdict:** a base equal to the chain ID is `Listed { digest: target, name: annotation }`, verified as on `nri` (D169). Any other is `Identified::Mismatched`, which `Verdicts::identified` makes `Rejected("image identity mismatch")` whatever the policies.
- **Because:**
  - containerd 2.3.0 to 2.3.7 vendor NRI v0.12.0, which has no `Container.image`; v0.12.2 adds it, and containerd 2.4 fills it (D15). A version check rather than the runtime version keeps a 2.3 build that vendors v0.12.2 on `nri`.
  - containerd sets the annotation from the CRI image name after copying the pod's pass-through annotations (v2.3.7 `internal/cri/server/container_create.go:921-929`, then `:986`), so a pod cannot forge it.
  - The oracle agrees on the platform manifest: `speculaire-oracle platform` runs containerd v2.4.2 `images.Manifest` (`core/images/image.go:153`) with `platforms.Only` over 1000 generated indexes and both manifest media types, exact and near misses; both pick the same config in all 1000, an image in 261. Two differences are left out of the generator and fail closed: containerd walks a nested index, and checks the config platform of an entry without one.
  - The chain ID of a target never changes, so after the first check of an image one store lookup and one `Stat` remain on the NRI call.
- **Measured (M6 step 07, arm64):** `identity_check` against the fake containerd, 16 layers, chain ID kept: median 30 µs, slowest of 2000 116 µs, 23 allocations (`just bench-micro`); 1 `Stat`, 2 under a remap.
- **Cost:** the identity gap of D15 stays: a retag between pull and create to an image of identical layers and another config passes (`docs/security.md`).
- **Revisit when:** containerd 2.3 reaches end of life: drop `annotation` with it.

## D171: On containerd below NRI v0.12.2, the snapshot check asks the snapshotter of the pod's runtime handler (amends D169, D170)

- **Decision:**
  - **Config:** `load_snapshotters(path)` reads, at each `Configure`, the CRI images section's `snapshotter` (default `overlayfs`), the runtime section's `containerd.default_runtime_name` (default `runc`) and each `containerd.runtimes.<handler>.snapshotter` from `io.containerd.cri.v1.runtime`. Before version 4 the runtime section takes `[containerd]` from the CRI plugin, all but `snapshotter`, `disable_snapshot_annotations` and `discard_unpacked_layers`, where it has none of its own, as containerd migrates it.
  - **Trait:** `Identity::identify(&PodSandbox, &Container)` takes the container's pod, as NRI's `CreateContainer` gives it; only `annotation` reads it.
  - **Handler:** the pod's `runtime_handler` (NRI `PodSandbox` field 7), `untrusted` when the pod annotation `io.kubernetes.cri.untrusted-workload` is `true`, and `default_runtime_name` when empty. Its own `snapshotter` wins; a handler without one, or one the config lacks, takes the images section's.
- **Because:**
  - containerd creates the container's snapshot in `RuntimeSnapshotter`, the handler's `snapshotter` else the images section's (v2.3.7 `internal/cri/server/images/service.go:191`, called at `internal/cri/server/container_create.go:372`), on the handler `GetSandboxRuntime` resolves from the sandbox's (`internal/cri/config/config.go:731-760`). NRI's `runtime_handler` is the sandbox's, as the pod asked it (`internal/cri/nri/nri_api_linux.go:612-616`).
  - containerd refuses a sandbox on a handler it lacks, so the fallback for an unknown one only names a snapshotter that holds no such container: the `Stat` fails and the container stays unverifiable.
  - The oracle runs containerd v2.4.2's loader and runtime migration over the same configs, and agrees on the images snapshotter, the default handler and every handler's `snapshotter`.
- **Tested:** a unit test against the fake containerd, whose snapshots belong to one snapshotter, proves the handler's snapshotter is the one asked. No e2e: a RuntimeClass whose handler names another snapshotter needs a second snapshotter in the kind node.
- **Revisit when:** containerd 2.3 reaches end of life, with D170.

## D172: The gate decides each container from its verdict, waits up to `gate.wait` for a missing one, and on CRI-O keeps only the manifests whose config digest is the image ID (amends D18, D65, D169; amended by D174, D175, D179, D189)

- **Decision:**
  - **Order:** `gate::decision::Decider::decide` takes each `CreateContainer`. A pod namespace in `gate.exempt.namespaces` is `exempt` before any lookup. Then the identity is read (D169, D170); an image whose names match a `gate.exempt.images` glob is `exempt`. Then `Verdicts::identified` gives the verdict, and its `None`, no matching policy, is `unmatched` (D23). A verdict served stale is counted `stale="true"` (D21).
  - **Exempt images:** the globs match the names the identity gives, normalised (D81), every one of them (D179). An identity without names, `Unknown` or `Mismatched`, exempts nothing. `gate.exempt.images` is parsed as globs when the config loads, so a bad glob refuses the config.
  - **Wait:** a `Pending` verdict, and on CRI-O an image ID the agent's copy of the list lacks (`Identified::Unlisted`), wait until the earlier of `gate.wait` and the runtime's deadline, woken by each verdict kept and each list kept. A wait that ends is `Pending`. The first pending pass sends each manifest of the identity, with its names, to the engine as `Asked { by: Asking::GateMiss }`; a root the engine does not know is discovered at once, and its verdicts are counted `trigger="gate_miss"` (D22). The containers of `Synchronize` are asked as `Asking::Synchronize` (D175).
  - **Answers:** `audit` allows every container. `enforce` allows `exempt`, `allow`, and `unmatched` under `gate.unmatched = "allow"`. It rejects with the texts of `docs/operations.md` § Rejection reasons: the verdict as displayed (`rejected: …`, `unverifiable: …`), `unmatched`, and `verification pending` for `Pending` and for a request past the 256 in flight (`Handler::overloaded`, D166), counted `result="overloaded"`.
  - **Metrics:** each answer counts `speculaire_gate_total{mode, result, stale}`; each `CreateContainer` records `speculaire_gate_seconds{path}`, waits included.
  - **Config digest:** before a root's first verification, the engine records the config digest of its platform manifest for the node, read from the artifact store or the node (`Discovery::config`), or none when neither holds both. A root read as none is read again at its next verification and when a list names it, since a fetch's verification can come before the pull stores the platform manifest. `Verdicts::identified` keeps, of CRI-O's listed manifests, those whose recorded config digest is the image ID, and those not recorded yet: verdicts loaded from `cache.bin` before their root is verified again (D31). None left is `Unverifiable("image ID is not a config digest")`.
  - **Settings:** a reload swaps one `Settings` that the next decision reads. The exemptions are logged at start (D18).
- **Because:**
  - An exempt namespace costs one comparison and no lookup, for the pods meant to pass unchecked.
  - CRI-O lists an image once its pull ends, and the agent's copy follows by events or a relist, so a container can come before the copy names it. The user chose to wait for the list as for a pending verdict (2026-11-21).
  - The config digest brings back D65's check, which D169 dropped: under `insecure_allow_unpredictable_image_contents` the image ID is a TOC digest that no manifest has as config, so the image is `Unverifiable` again rather than allowed on a manifest whose layers CRI-O never checked. The user chose it (2026-11-21).
  - The waits hold no lock across an `await`: they wait on `Notify`, and the lookup takes the verdicts' read lock alone.
- **Measured (M6 step 08, arm64):** `just bench-micro decide`, the whole decision on a cached `Allow` under `enforce`, 2000 samples, four runs: the `nri` path takes 0.41–0.45 µs median and 1.6 µs at worst, with 4 allocations, the name parse and the policy match of `Verdicts::identified`; the `annotation` path, on a fake containerd 2.3, takes 31–33 µs median and 226 µs at worst, with 27 allocations, mostly the snapshot `Stat` over gRPC. Both are far under the 5 ms p99 target (D107). `Verdicts::get` itself allocates nothing.
- **Cost:** on CRI-O an image whose platform manifest the node holds in neither the artifact store nor the mirror's blob cache, as one pulled before the agent ran and since evicted, is unverifiable.
- **Revisit when:** —

## D174: A root listed and not yet discovered that the gate waits on is discovered at once, under `gate_miss` (amends D22, D146, D172)

- **Decision:**
  - An `Asked { by: Asking::GateMiss }` for a root a list named, whose discovery neither ran nor failed, with no discovery the engine asked for under way and no retry set, has the engine discover it at once, beside the listing's lanes. Its first verification counts `trigger="gate_miss"`. A root discovered, asking, or waiting on a retry goes on as it was.
  - `e2e/tests/gate.rs` checks `enforce` on one worker of each runtime: the agent's rejections reach the kubelet's `CreateContainerError`, `runnable` starts on its first pull by tag and by digest, the runtime's default validator rejects every container while the agent is down, exemptions and `gate.unmatched` decide, a cold node starts `runnable` within three of the kubelet's retries, and `speculaire_gate_seconds` keeps its p99 under half of `gate.wait`.
- **Because:**
  - A node that boots lists every image it holds, and each lane discovers one root at a time (D146): a held image the policies match queues behind images whose sources answer slowly or not at all, as kind's on `public.ecr.aws`, rate limited. A pod of it was refused `verification pending` until its turn came: on containerd 2.3, twice, 20 s of the kubelet's back-off. The gate already asks, but the engine ignored a root it knew.
  - A root whose discovery failed keeps the engine's back-off, so a pod retried in a loop does not hammer its sources.
- **Measured (M6 step 10, kind on arm64, Kubernetes 1.37):** the cold-node pod met `verification pending` twice on containerd 2.3 before the change, 20 s of back-off, and started at its first try after it, counted under `gate_miss`. `speculaire_gate_seconds` p99 under `enforce`, over seven decisions, across runs: `image_id` 40–61 µs on CRI-O 1.37, `nri` 0.07–20 ms on containerd 2.4, `annotation` 0.35–20 ms on containerd 2.3, under the 150 ms bound, half of `gate.wait`. The enforce cases take 44–47 s per leg.
- **Revisit when:** `cache.bin` (step 12) keeps verdicts over a restart: a cold node then starts from them.

## D175: The containers of NRI `Synchronize` become discovery roots under `trigger="synchronize"`, and the gate warns of each one a verdict does not allow (amends D22, D155, D172; amended by D176)

- **Decision:**
  - **Roots:** the gate keeps the containers of the latest `Synchronize`, created, running or paused. It reads each one's identity as for `CreateContainer` (D169, D170), and sends each manifest to the engine as `Asked { by: Asking::Synchronize }`, which discovers it at once, as any root no list named yet. An identity read before the image list (`Identified::Unlisted`) or containerd's image store (`image name not in containerd's image store`) loaded is read again every 100 ms for 5 s, and at each verdict or list kept. A container in an exempt namespace is skipped.
  - **Order:** at agent start, the image list's discovery (`speculaire_artifacts::follow`) waits until the gate has asked for every container it could identify, or 5 s: the running containers' roots are verified first, under `trigger="synchronize"`.
  - **Report:** each verdict kept wakes the gate, which looks up each container's as `CreateContainer` would. One `warn` names the namespace, pod, container, image (as D173's `gate` event) and the verdict, `rejected: …` or `unverifiable: …`, when it lands on a container and again only when it changes. `Allow`, `unmatched`, exempt images and identities that fail are not reported; `Pending` changes nothing. No metric, no audit event: the warning is the report.
  - **No eviction:** the gate stops nothing; its `Synchronize` answers no update. A container not allowed is decided again at its next start.
  - **Running set:** D155's CRI poll stays the set verified first after a change: `Synchronize` comes once per connection, and following stops and removals needs NRI events outside D9's subset.
- **Because:**
  - The engine is told of the runtime's images at start, before the gate registers, so the list's discovery used to verify a running container's root first, under `event`, and `trigger="synchronize"` counted nothing. Holding the list is deterministic and verifies first what runs, as D155 does after a change; relabelling a root not verified yet lost the race whenever the store held its artifacts. The wait is bounded, so a gate that never registers delays the list 5 s.
  - A warning per change, not per wake, keeps the log quiet: verdicts land for every image of the node.
  - Identity failures at start are the image store's not being loaded yet on containerd's `annotation` path (D170), not the image's fault; the next `CreateContainer` gives them their reason.
  - The user chose the report and the running set (plan Q6, Q7, defaults).
- **Measured (M6 step 11, kind on arm64, Kubernetes 1.37):** a pod started while the agent was stopped is verified under `synchronize` and warned of once, about 6 s after the agent starts, on containerd 2.4 and CRI-O 1.37. With the list not held, containerd 2.4 counted it under `event` only. The gate suite takes 67 s on containerd 2.4 and 76 s on CRI-O 1.37.
- **Cost:** fetches and new images wait up to 5 s at agent start. A running container's root may be verified twice at start: as asked, and again as its list's discovery ends. A container started and stopped between two connections is never seen. The warning goes to the journal only; an alert on it is the operator's log pipeline's.
- **Revisit when:** the gate subscribes to NRI's container lifecycle events, or evicts.

## D179: The name the pod asked for chooses the policies and the image exemptions when the runtime's list confirms it; otherwise every name does, the strictest wins and an exemption needs them all (amends D169, D172, D173)

- **Decision:**
  - **Requested name:** containerd's `io.kubernetes.cri.image-name` is the image as the pod spec names it, a tag, a short name or a digest: containerd takes the CRI `user_specified_image`, which the kubelet fills with the pod's string (v2.4.2 `internal/cri/server/container_create.go:259-262`, v2.3.7 `:320-322`; kubernetes v1.36.6 `pkg/kubelet/kuberuntime/kuberuntime_container.go:373`). CRI-O passes no requested name: `io.kubernetes.cri-o.Image` is the image ID the kubelet resolved and `io.kubernetes.cri-o.ImageName` an arbitrary name of the image (v1.37.2 `internal/annotations/annotations.go:75-83`).
  - **`nri`:** the gate keeps the runtime's image list on containerd too (`Nri::keep`). When the list gives the image of `Container.image.config_digest` the requested name's repository, the name is the requested one and the identity a manifest the list gives that repository, `Container.image.digest` when it is one, `Identified::Listed { digest, name }`. Otherwise, the list not caught up or the annotation missing or unparsable, it is `Identified::Unconfirmed { digest, names }`: the requested name's repository, `Container.image.name`'s and every repository the list gives the image.
  - **`annotation`:** unchanged: the annotation is the requested name, which the image store and the chain-ID check confirm (D170).
  - **`image_id`:** unchanged: every repository the list gives the image (D169).
  - **Policies:** `Verdicts::identified` takes the worst verdict over the policy groups of every name it is given (D169), and gives `None`, unmatched, only when no name matches a policy. A name no policy matches never lightens another's verdict.
  - **Exempt images:** `gate.exempt.images` exempts an image only when every name it is given matches a glob.
  - **Audit:** the `gate` event's `image_name` is the names the policies were matched on, comma-separated: the requested name on `nri` and `annotation` when confirmed, every name otherwise and on CRI-O; containerd's annotation when the identity gives none.
- **Because:**
  - M6 step 13 found `e2e/signed:1` and `e2e/unsigned:1`, one image ID, both on a containerd 2.4 node: `Container.image.name` is the image's first reference, sorted (v2.4.2 `internal/cri/server/helpers.go:169-175`, `internal/cri/store/image/image.go:258`), so a pod of `unsigned` was named `signed`, which no policy matched, and `unmatched = "allow"` let it start. `Container.image.digest` is that first name's manifest too: under the requested name's policies alone, the engine, which had discovered `signed`'s manifest under its own names, left it `verification pending`; the manifest of the requested repository is one the list names under it. The unit test `the_name_the_pod_asked_for_chooses_the_policies_and_never_another_name_of_its_image` failed on `main` for (a) unmatched, (b) a laxer policy and (c) an exemption on `nri`, and for (c) on `image_id`. On kind with `main`'s agent, `e2e/tests/gate.rs` started the pod of `unsigned` on containerd 2.4.2 (a), and on CRI-O 1.37.2 rejected it, `rejected: identity mismatch` from `signed`'s manifest, but started it under an exemption of `signed` (c).
  - The requested name is the pod's intent, the one an admin writes a policy or an exemption for. containerd sets the annotation after the pod's own, so a pod cannot forge it (D170); the list check keeps a name containerd did not resolve to the image from choosing its policies.
  - Every name, when the requested one is not confirmed, can only add policies: never fewer checks than the name the pod asked for alone.
- **Measured (arm64, `just bench-micro decide`, 2000 samples, on a cached `Allow`):** the `nri` path takes 0.65 µs median and 1.15 µs at worst, with 5 allocations, against 0.45 µs and 4 on `main` on the same machine: the parse of the requested name. The `annotation` path takes 32 µs median against 29 µs, the run-to-run spread D172 measured.
- **Cost:** a CRI client other than the kubelet that sets no `user_specified_image` gets the image's first reference in the annotation: that name, confirmed by the list, chooses the policies. Until the list follows a pull, a pod's other names on the node add their policies.
- **Revisit when:** CRI-O passes the requested name.


## D180: NRI's required-plugin gap stays open until the runtimes ship NRI v0.12.5; the agent registers no stand-in plugin (amends D9, D54; amended by D198)

- **Decision:**
  - After the agent leaves NRI, by a stop or a kill, the first container created in a pod that already runs passes the runtime's required-plugin check. speculaire accepts that window and documents it (`docs/operations.md` § Break glass, `docs/security.md`). It does not register a throwaway plugin after leaving NRI or from `ExecStopPost`.
  - The gate test `after_a_stop_the_first_container_in_a_running_pod_passes` (`e2e/tests/gate.rs`) asserts the gap as it is. It fails once a runtime the e2e matrix pins ships the fix, and then this decision is revisited.
  - We ask CRI-O and containerd to ship NRI v0.12.5 in their supported branches. The draft request is written outside the repository; the user files it.
- **Because:**
  - NRI keeps a plugin whose connection closed in its list until the end of the next request of any kind, or until a plugin registers (containerd/nri v0.12.3 `pkg/adaptation/adaptation.go:327`, `:608-632`, `:698`). `CreateContainer` adds every listed plugin to the validation request before calling it (`:341-345`), and a call that fails on the closed connection closes the plugin and answers nothing, not an error (`pkg/adaptation/plugin.go:757-763`). The default validator then finds the plugin in the request (`pkg/adaptation/builtin/default-validator.go:270-291`).
  - The window is one request, not a span of time: a new pod's `RunPodSandbox`, a container removal or a plugin registering clears the closed plugin first. New pods are rejected. What passes is one container in a pod that already runs: a kubelet retry, a restart, or an image that finished pulling after the stop.
  - Every NRI the supported runtimes pin has it: a Go reproduction fails on v0.11.0 (CRI-O 1.35, 1.36), v0.12.0 (containerd 2.3), v0.12.2 (CRI-O 1.37) and v0.12.3 (containerd 2.4), and passes on v0.12.5. It was seen on kind with CRI-O 1.37.2 and containerd 2.4.2, after a graceful stop and after SIGKILL.
  - NRI v0.12.5 fixes it upstream (containerd/nri#338: `CreateContainer` skips closed plugins). containerd's `release/2.4` carries it, unreleased; CRI-O main pins v0.12.2.
  - The agent's stop order cannot close it (D177): NRI sees the dropped connection only at its next request. A plugin of another name registering clears the closed entry, which the Go reproduction confirms, but that adds a connection at every stop and a code path in the unit to remove once the runtimes catch up, for one container in a running pod.
- **Cost:** while the agent is down, one container per node can start ungated if its pod already runs. Break glass and a crash both open it.
- **Revisit when:** a pinned runtime ships NRI v0.12.5, which the gate test reports. containerd's `release/2.4` and CRI-O's `main` already carry it (containerd/containerd#14477, cri-o/cri-o#10518), not in a release yet; backports are asked in https://github.com/containerd/containerd/issues/14635 and https://github.com/cri-o/cri-o/issues/10604. A runtime with NRI v0.12.4 or later also lets the agent answer `fail_request = true` (D198).


## D189: The gate reads `CreateContainerRequest` in place, and answers a request it decides without waiting with no allocation (amends D107, D166, D170, D172)

- **Decision:**
  - **Reader:** `speculaire_nri::create::Request::read(&payload)` reads a `CreateContainerRequest` in one pass over the ttrpc payload, safe Rust and no allocation. It keeps the fields the gate reads as `&str` borrowed from the message: the pod's name, namespace, annotations and runtime handler, the container's ID, name, annotations and image (name, digest, config digest), with NRI v0.12.3's field numbers. Annotations stay in the message; `Annotations::get` scans them for a key, the last written winning. Every other field is skipped by its wire type, unchecked. A message written twice merges as protobuf merges it.
  - **Refusals:** a truncated field, a field the gate reads of the wrong wire type or not UTF-8, a key of field 0, a varint over 10 bytes, a group, or wire type 6 or 7 answers `INVALID_ARGUMENT`, as a request prost refuses did (D166). proto3 writes no groups; prost skips them, the reader refuses them.
  - **prost stays** for every other message, `Synchronize`'s pods and containers included; `Pod`, `Container` and `Request` also view a prost value (`From<&api::…>`), so the gate and the identity read one type.
  - **At once:** `Handler::answer_now` answers a CreateContainer before a task is spawned for it. The agent's `Decider::decide_now` answers when the decision needs no wait: an exempt namespace, no container, or an identity in memory (`NodeIdentity::identify_now`) whose verdict is kept. It audits and counts that decision as `decide` would. Otherwise, a pending verdict or an identity containerd must be asked for, it returns none, having asked nothing, and the request is copied into a task as before (D166).
  - **Snapshots prepared:** on the `annotation` path the agent follows containerd's `/snapshot/prepare`, `/snapshot/commit` and `/snapshot/remove` events in `k8s.io` (`snapshots::Prepared`): each snapshot prepared on a digest, by snapshotter and key, up to 4096, emptied when full and at each subscription. The CRI plugin prepares the container's snapshot before NRI's CreateContainer (containerd v2.3.7 `internal/cri/server/container_create.go:378`, `:450`), so its parent is usually known when the request comes: a parent that is the chain ID kept for the image (D170) identifies the container with no `Stat`, at once. A snapshot not seen, or on another parent, as under an ID remap, is asked with `Stat` as before (D167). The name annotation is written out as `speculaire_oci::reference::DockerRef`, in a buffer inside the value, for the image store lookup. A `Stat` cache by image would not serve: each container's snapshot is its own, keyed by its ID.
  - **No allocation on that path:** ttrpc's `Reader` reads each message into one buffer per connection, cancel safe, and the envelope in place (`Call<'_>`). The multiplexer refills two spare payload buffers of up to 64 KiB. Names are checked as `speculaire_oci::reference::Repository`, the normalized name borrowed or written on the stack (530 bytes at most), for exempt images, the requested name (D179) and the policy match. `Policies::match_hash` hashes up to 16 matched policies on the stack with one-shot SHA-256; `Verdicts::identified` keeps up to 8 policy groups on the stack. Each metric handle is registered at its first label set (`telemetry::Handles`), and the answer is written into the connection's buffer.
  - **Guard:** `crates/agent/tests/allocations.rs` counts the allocations of its thread, where every task runs, through a counting global allocator (the test's own `unsafe`, under `#![expect(unsafe_code)]`). 256 requests after 64 warm ones, on each path (`annotation` with its prepare event seen), with the runtime's side, allocate exactly the 4 histogram blocks below.
  - **Exceptions:** `speculaire_gate_seconds` keeps samples until a scrape in blocks of 64 (metrics-util 0.20.4): one allocation per 64 requests, freed at the scrape. The `gate` audit event, off by default (D37), adds 8 allocations: its formatted fields and tracing's JSON layer.
  - **Checks:** `crates/nri/src/create/tests.rs` compares the reader with prost on 512 seeded messages with unknown fields and split parts, and on merges and groups. The fuzz target `nri_create` asserts that the reader agrees with prost (`testing::agrees`) and refuses nothing prost decodes but a group; its seeds are the recorded runtime requests. `nri_request` hands it each CreateContainer payload.
- **Because:**
  - prost decodes the whole container: environment, mounts, Linux resources and two string maps per message, about 130 allocations for a typical pod, all dropped unread. The gate reads 10 fields.
  - A hand-written reader of one message is about 400 lines besides tests (`wire.rs`, `create.rs`); a borrowed decoder crate (`quick-protobuf`, `micropb`) adds a code generator and a crate to vet for the same subset.
  - A kept verdict is the common case, and every container start waits on it. A task per request costs its allocation and a copy of the request, which the answer at once skips; each allocation left on the path is a lock in the allocator under a burst of starts.
  - Exact counts make a regression a failing test rather than a slower benchmark.
- **Measured (`cargo bench -p speculaire-agent --bench micro request`, 2000 samples, Apple M5, audit off):** from frame bytes to answer frame bytes, median, slowest and allocations per request; before, with the reader, answered at once, and with prepare events:
  - nri: 10.4 µs, 69.7 µs, 151; 8.5 µs, 93.6 µs, 17; 5.7 µs, 20.4 µs, 0.
  - image ID: 10.4 µs, 30.7 µs, 154; 8.0 µs, 89.7 µs, 16; 5.5 µs, 22.2 µs, 0.
  - annotation: 32.9 µs, 75.4 µs, 187; 27.1 µs, 710 µs, 56; 29.0 µs, 151.5 µs, 42; 6.4 µs, 25.7 µs, 0.
- **Cost:** a field the gate does not read is not validated: a request with a malformed environment, which prost refused, is decided. The runtime built it from its own state.
- **Revisit when:** the gate reads a field outside the 10, or NRI renumbers one; or containerd prepares the container's snapshot after NRI's CreateContainer; or a dependency on the path, the metrics recorder above all, starts allocating per call: the guard names it.

## D198: Once a pinned runtime ships NRI v0.12.4 or later, the agent answers `fail_request = true` in `enforce` (amends D9, D41, D54, D180)

- **Decision:**
  - The agent answers `Configure` with `ConfigureResponse.failure_policy.fail_request = true` (containerd/nri#329, v0.12.4 `pkg/api/api.proto:182-220`) when `gate.mode` is `enforce`, and leaves it false in `audit`. `keep_connected` stays false: a timed-out agent is closed and registers again (D41).
  - NRI reads the failure policy only at `Configure` (v0.12.4 `pkg/adaptation/plugin.go:502`), and `gate.mode` is live (D47): a reload that changes the mode makes the agent leave NRI and register again, so the runtime reads the new policy.
  - **Precondition:** before building, the NRI proto in `crates/nri`, today v0.12.3's, carries the field, and a runtime the e2e matrix pins (D63) ships NRI v0.12.4 or later.
  - A gate test stalls the agent past the runtime's request timeout and checks that the creation is rejected.
- **Because:**
  - Today a `CreateContainer` call that fails or times out on the plugin lets the container start, even with `required_plugins` (v0.12.3 `pkg/adaptation/plugin.go:757-763`). With `fail_request`, NRI returns the error for a closed connection, a protocol error or a timeout (v0.12.4 `pkg/adaptation/plugin.go:964-983`, `isFatalError` `:998-1010`), so the creation is rejected.
  - speculaire subscribes only to `CreateContainer`, so the policy changes nothing else.
  - containerd's `release/2.4` and CRI-O's `main` already carry NRI v0.12.5 (containerd/containerd#14477, cri-o/cri-o#10518), not in a release yet. Backports are asked in https://github.com/containerd/containerd/issues/14635 and https://github.com/cri-o/cri-o/issues/10604.
  - In `audit`, which allows every container (D54), a stalled agent must not reject what its own answer would have allowed (user, 2026-11-23).
- **Cost:** in `enforce`, an agent that stalls or crashes mid-call rejects that creation instead of letting it through; kubelet retries it. A mode change costs one NRI registration, during which creations pass ungated as at any agent restart (D180).
- **Revisit when:** NRI changes what `fail_request` covers, or reads the failure policy outside `Configure`.


## D209: A rebooted node under `required_plugins` starts the chart's agent pod, then its other pods, the CNI's included, which need no annotation (amends D44, D84)

- **Decision:**
  - The chart's tolerate annotation, `gate.tolerateAnnotation` on both its pods, is the only one a worker needs. It covers the `configure` init container too (`containerd/nri` v0.12.3 `pkg/plugin/annotations.go:40`). The CNI's pods, kube-proxy and every other pod wait for the agent: the validator rejects their containers until it registers, and the kubelet retries them.
  - Static pods: the control plane's carry the annotation, as `docs/operations.md` step 3 says. A worker's static pod waits like the others.
  - At boot, `configure` in the init container finds the runtime by its socket (D84), the runtime that created it. `unconfigure` still refuses while `required_plugins` names `speculaire`: the annotation brings the agent back after a reboot, not after its removal.
  - `e2e/tests/reboot.rs`, DaemonSet mode: on `<cluster>-worker2`, the validator requires `speculaire` and tolerates the chart's key, and a pod and a static pod without the annotation run. After `docker restart` of the node, the agent pod is ready within 180 s, then every container that ran before runs again within 120 s, none before the agent, and the runtime's config is back as it was.
- **Because:**
  - The agent pod is on the host network, so it needs no CNI. An annotated CNI pod would start ungated, for nothing.
  - The kubelet gets the agent pod from the API server. A control-plane node whose API server waited for the agent would start neither.
- **Measured (arm64, Docker, kind 0.33.0, chart 52396e5):** from `docker restart`: containerd 2.4, agent pod ready in 3.5 s and 7.9 s, the other pods at +12 to +14 s, each rejected once; CRI-O 1.37, agent pod ready in 5.8 s, the others at +15 to +19 s, rejected 2 or 3 times each. Red, with the chart's key set to another: on both runtimes the agent pod was not ready after 180 s, its events naming `required plugin "speculaire" not present` (16 on containerd, 15 on CRI-O), and the node's other pods were rejected too; the restored config let every pod run again.
- **Cost:** a rebooted worker runs its other pods about 10 s later, the kubelet's first back-off; the suite adds about 25 s to each DaemonSet leg.
- **Revisit when:** NRI exempts a plugin's own pod from validation, or the kubelet keeps a node's pods across a reboot.
