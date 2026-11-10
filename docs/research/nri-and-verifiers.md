# containerd NRI and image-verifier research

Read from code: containerd `f00f5261b` (main, v2.4.0-242), NRI `d817e4e` (main, v0.12.5). Paths `pkg/` or `plugins/default-validator` are in the nri repo; `internal/`, `core/`, `plugins/` are in containerd.

**Short answer:** use both. NRI at container creation is the enforceable gate; the pull-time verifier is an optional early filter.

## 1. NRI

## 1.1 Hooks a plugin can subscribe to
- Plugin service: `pkg/api/api.proto:79-146`. Event enum: `pkg/api/api.proto:401-418`.
- Lifecycle events: `RunPodSandbox`, `UpdatePodSandbox`, `PostUpdatePodSandbox`, `StopPodSandbox`, `RemovePodSandbox`, `CreateContainer`, `PostCreateContainer`, `StartContainer`, `PostStartContainer`, `UpdateContainer`, `PostUpdateContainer`, `StopContainer`, `RemoveContainer`, `ValidateContainerAdjustment`.
- Plus `Configure`, `Synchronize` and `Shutdown`, and `StateChange` as the generic event relay.
- The plugin calls into the runtime through `Runtime.RegisterPlugin` and `Runtime.UpdateContainers`. See `api.proto:27-31` and `:43-48`. The runtime ignores `UpdateContainersRequest.evict` (`pkg/adaptation/plugin.go:463-470`); a plugin evicts only through `evict` in a `CreateContainer` or `UpdateContainer` response (containerd `internal/nri/nri.go:290,374`).
- Subscription is a bitmask in `ConfigureResponse.events` (`api.proto:183-191`). If the mask is 0, the plugin gets every event (`pkg/adaptation/plugin.go:492-499`).
- **There is no image-pull hook, and nothing image-related at all.** NRI only covers pod and container lifecycle.

## 1.2 Which hooks can reject the operation (containerd CRI)
| Hook | Error effect | Ref |
|---|---|---|
| RunPodSandbox | **fails the pod** (`"NRI RunPodSandbox failed"`) | `internal/cri/server/sandbox_run.go:391-394` |
| CreateContainer | **fails CreateContainer**, called inside `NewContainer` opts | `internal/cri/server/container_create.go:409`, `internal/cri/nri/nri_api_linux.go:362-365` |
| ValidateContainerAdjustment | **fails creation** (transactional) | `pkg/adaptation/adaptation.go:525-559`, `docs/validation-plugins.md` |
| StartContainer | **fails start** | `internal/cri/server/container_start.go:181-185` |
| UpdateContainer | fails the resource update | `internal/cri/server/container_update_resources.go:53-56` |
| Post*, Stop*, Remove* | logged only | `container_create.go:460-463`, `container_start.go:206-209`, `sandbox_stop.go:101-104`, `container_remove.go:97-98` |

- An error returned by the plugin always fails the request. `handleRequestError` passes non-fatal errors straight through (`pkg/adaptation/plugin.go:961-964`).
- Plugins are called in index order, and the first error aborts the loop (`adaptation.go:357-370`).
- **Serialization:** `CreateContainer` holds the global `Adaptation` lock (`adaptation.go:340-341`) and the containerd-side lock (`internal/nri/nri.go:276-277`). A slow plugin therefore slows every container creation on the node. Answer from a cache and do the heavy work elsewhere.
- Validators, by contrast, run in parallel (`adaptation.go:538-549`).

## 1.3 Image info available in hooks
`Container.image` (`api.proto:467, 470-481`), added in NRI v0.12.2 and populated by **containerd ≥ v2.4.0** (commit 203578e2e, which vendors nri v0.12.3):
- Fields: `name` (image reference), `digest` (index or manifest digest, i.e. the image's target), `config_digest` (the image ID).
- Populated in `internal/cri/nri/nri_api_linux.go:973-988` from metadata set at `internal/cri/server/container_create.go:344-346`:
  ```go
  r.meta.ImageRef = r.imageID                                   // config digest
  r.meta.ImageDigest = (*r.containerdImage).Target().Digest.String()
  r.meta.ImageName = (*r.containerdImage).Name()                // = image.References[0] (internal/cri/server/helpers.go:175)
  ```
- `name` is whichever reference comes first, not necessarily the one the pod spec used. **Enforce on `digest`.**

Annotations (`api.proto:451`) contain spec annotations merged with CRI config annotations (`nri_api_linux.go:866-873`). This includes `io.kubernetes.cri.image-name` (`internal/cri/annotations/annotations.go:79, 131`), whose value is the pod spec's `UserSpecifiedImage` string, possibly a bare tag (`container_create.go:273-275`).
- **On containerd < 2.4 this annotation is the only image hint, and it has no digest.** The agent would have to resolve it itself, e.g. via CRI `ImageStatus` or containerd's images API, which is weaker.

Other data:
- `PodSandbox` has id, name, uid, namespace, labels, annotations and runtime_handler, but **no image**, so the pause image can't be checked through NRI (`api.proto:421-432`).
- `Synchronize` delivers every existing pod and container at connect time (`api.proto:217-230`). Use it to audit containers already running. `SynchronizeResponse` holds only `update` and `more` (`api.proto:226-231`), so it cannot evict.

## 1.4 Registration modes
- **Pre-installed (launched by containerd):** binaries named `<idx>-<name>` in `plugin_path` (default `/opt/nri/plugins`, `pkg/adaptation/adaptation.go:42`).
  - containerd starts them with a socketpair on fd 3 and env vars `NRI_PLUGIN_SOCKET=3`, `NRI_PLUGIN_NAME`, `NRI_PLUGIN_IDX` (`pkg/adaptation/plugin.go:103-172`, `pkg/api/plugin.go:28-33`).
  - Per-plugin config comes from `/etc/nri/conf.d/<idx>-<name>.conf` or `<name>.conf` and is passed as `ConfigureRequest.config` (`plugin.go:227-246`).
  - WASM plugins are also supported (`plugin.go:108-125`).
  - Started only at containerd startup (`adaptation.go:562-639`). **I found no restart logic: a plugin that crashes stays gone until containerd restarts.**
- **External:** connects to `socket_path` (default `/var/run/nri/nri.sock`, `pkg/api/plugin.go:27`), sends `RegisterPlugin{plugin_name, plugin_idx}`, then gets `Synchronize` (`adaptation.go:712-757`, `plugin.go:437-460`). It can reconnect whenever it wants. `disable_connections` turns this off.
- **Built-in:** the default validator (`adaptation.go:153-160`).

## 1.5 Timeouts and failure behaviour
- Defaults: registration 5s and request 2s (`pkg/api/timeouts.go:25,27`). Both are passed to the plugin in `ConfigureRequest` (`api.proto:167-180`). Every call is wrapped in `context.WithTimeout(getPluginRequestTimeout())`, e.g. `plugin.go:725`.
- Registration timeout: the plugin is closed and stopped (`plugin.go:337-349`).
- Fatal errors (`ttrpc.ErrClosed`, `ErrServerClosed`, `ErrProtocol`, `DeadlineExceeded`; `plugin.go:994-1006`) are handled by `handleRequestError` (`plugin.go:961-980`).
- **Default is fail-open:** the plugin is dropped and the request proceeds without it.
- **`FailurePolicy`** (`api.proto:193-215`), returned in `ConfigureResponse.failure_policy`:
  - `fail_request=true` → fail-closed on timeout or crash.
  - `keep_connected=true` → a timeout doesn't unregister the plugin.
  - It is in NRI v0.12.4+ (commit e4785d7). containerd main vendors v0.12.5 (`go.mod:26`), but **v2.4.0/2.4.1 ship v0.12.3, so no released containerd has it yet.**
- **Fail-closed on released containerd (≥ 2.2):** enable the built-in default validator with `required_plugins = ["<name>"]` (`plugins/default-validator/default-validator.go:62, 240-285`; `docs/validation-plugins.md`).
  - The required check looks at the list of consulted plugins.
  - Closed plugins are skipped before `AddPlugin` (`adaptation.go:357-363`), so a dead or dropped plugin means every creation is rejected.
  - `tolerate_missing_plugins_annotation` provides a per-pod escape hatch.
  - Deadlock risk: if the agent runs as a pod and is required, it can't start. Run it as a systemd unit or pre-installed plugin, or annotate its pod.

## 1.6 containerd config
`[plugins."io.containerd.nri.v1.nri"]` (`internal/nri/config.go:29-44`; `docs/NRI.md:73-87`). Keys: `disable` (default false, `config.go:50`), `socket_path`, `plugin_path`, `plugin_config_path`, `plugin_registration_timeout`, `plugin_request_timeout`, `disable_connections`, and `[...default_validator]` with `enable`, `required_plugins`, `tolerate_missing_plugins_annotation`, `reject_*`.

Requested enforcement config:
```toml
[plugins."io.containerd.nri.v1.nri"]
  plugin_request_timeout = "2s"
  [plugins."io.containerd.nri.v1.nri".default_validator]
    enable = true
    required_plugins = ["image-policy"]
    tolerate_missing_plugins_annotation = "tolerate-missing-nri-plugins.noderesource.dev"
```

## 1.7 Wire protocol and Rust
- One unix connection carrying **two ttrpc channels through NRI's own multiplexer** (`pkg/net/multiplex/mux.go`).
- Frame: 8-byte header = 4-byte big-endian ConnID + 4-byte big-endian payload length (`mux.go:136-141, 251-252, 323-324`). ConnID 0 is reserved.
- `PluginServiceConn=1`: the runtime is the client and the **plugin serves `nri.pkg.api.v1alpha1.Plugin`**.
- `RuntimeServiceConn=2`: the runtime serves and the **plugin is the client** calling `RegisterPlugin` and `UpdateContainers` (`pkg/net/multiplex/ttrpc.go:19-24`; runtime side at `pkg/adaptation/plugin.go:258-315`).
- Order: connect → RegisterPlugin (within 5s) → Configure → Synchronize (possibly in chunks, `more` flag) → events.
- Rust:
  - There is no Rust code in the nri repo, and I found no local crate. A community "nri" crate may exist on crates.io; I haven't verified it.
  - Plan: use `ttrpc-rust` (github.com/containerd/ttrpc-rust) plus `ttrpc-codegen` on `pkg/api/api.proto`, and write the mux yourself (about 150 lines).
  - Practical approach: demultiplex the trunk in a tokio task and bridge each ConnID to a local `socketpair`, then hand those fds to ttrpc-rust's server and client.

## 2. containerd image verifier plugins

## 2.1 Plugin system and the bindir contract
- Plugin type `io.containerd.image-verifier.v1` (`plugins/types.go:73`). Interface: `VerifyImage(ctx, name string, desc ocispec.Descriptor) (*Judgement{OK bool; Reason string}, error)` (`pkg/imageverifier/image_verifier.go`).
- The only implementation is `bindir` (`plugins/imageverifier/plugin.go`), added in commit ac1d556b9 and **first released in v2.0.0**.
  - Defaults: `bin_dir=/opt/containerd/image-verifier/bin` (`plugins/imageverifier/path_unix.go:21`), `max_verifiers=10`, `per_verifier_timeout=10s`.
  - Config section: `[plugins."io.containerd.image-verifier.v1.bindir"]` (`docs/image-verification.md`).
- **Invocation** (`pkg/imageverifier/bindir/bindir.go`):
  - Each file in `bin_dir` is run, sequentially and sorted by name (`:59-60, :80`), as `<bin> -name <ref> -digest <desc.Digest> -stdin-media-type application/vnd.oci.descriptor.v1+json` (`:118-122`).
  - stdin receives the JSON OCI descriptor of the resolved image: mediaType, digest and size, usually the **index** digest (`:180`).
  - Each run is bounded by `per_verifier_timeout` (`:114`) and runs in containerd's cgroup.
- **Output:** exit 0 allows; any other exit blocks, with stdout as the reason (`:94-99`). stdout and stderr are each capped at 32 KiB (`:38`); stderr is logged at debug.
- **Failure semantics:**
  - Exec failure or timeout → error → **pull blocked** (`bindir.go:90-92`; `core/transfer/local/pull.go:80-84`).
  - `bin_dir` missing or empty → **allowed** (`bindir.go:60-77`). A misconfiguration therefore fails open.
  - Entries past `max_verifiers` are skipped with a warning (`:81-84`).
- **Inputs the verifier does not get:** registry credentials, pod or namespace context, platform. It must fetch signatures, attestations and SBOMs itself (sigstore/OCI referrers) with its own credentials.

## 2.2 Where it's called
- Only in the transfer service's pull path: `core/transfer/local/pull.go:62-95`, after `ir.Resolve` and **before any fetch**.
- It runs on every transfer pull, even when the image is already present (`// TODO: Handle already exists`, `:97`).
- Wiring: `plugins/transfer/plugin.go:55, 75-82`.
- **Not called** for imports (`core/transfer/local/transfer.go:106`: `// TODO: verify imports with ImageVerifiers?`), `client.Pull`, `ctr i pull --local`, or `ctr i import`.

## 2.3 Whether CRI pulls go through it
- CRI uses the transfer service **by default from v2.1.0** (`docs/cri/config.md:175-177`; commit b694be29a). In v2.0, CRI used client pull, so **verifiers did not apply to kubelet pulls.**
- Selection: `internal/cri/server/images/image_pull.go:183-216`. Local pull is used, **bypassing verifiers**, if any of these holds:
  1. `use_local_image_pull = true` (`internal/cri/config/config.go:351`).
  2. Automatic fallback (`config.go:550-618`, called at `plugins/cri/images/plugin.go:89-91`) when any of these is set: legacy `registry.mirrors` / `configs` / `auths`, `max_concurrent_downloads != 3`, `discard_unpacked_layers`, `image_pull_with_sync_fs`, `ignore_descriptor_urls`, or `disable_snapshot_annotations=false`. On Linux the default is true (`internal/cri/config/config_unix.go:33`). This fallback only logs a warning.
  3. The transfer service can't unpack the runtime handler's platform/snapshotter combination per `unpack_config` (`image_pull.go:200-206`, `core/transfer/local/transfer.go:71-77`).
- The pause image goes through `ensurePauseImageExists` → `PullImage` only if it isn't present locally (`internal/cri/server/sandbox_run.go:444-466`). If the verifier rejects it, every pod fails.

## 3. Pull-time verifier vs NRI at creation

| | Verifier (pull) | NRI CreateContainer/Validate |
|---|---|---|
| Coverage | Only transfer-service pulls; silently bypassed by local-pull fallback, imports, `ctr --local`, images pulled before the policy, `IfNotPresent` with the image cached (kubelet never calls PullImage), pre-loaded or airgapped images | **Every CRI container creation** regardless of how the image arrived (also static pods) |
| Context | Ref and digest only; no pod or namespace, no credentials | Pod namespace, labels, annotations, container name, plus image name/digest/config digest (≥ 2.4) → per-namespace policy and exemptions possible |
| Failure mode | Fail-closed on exec error or timeout; fail-open if `bin_dir` missing | Default fail-open; fail-closed via `required_plugins` (≥ 2.2) or `FailurePolicy.fail_request` (unreleased). A request timeout closes the plugin and lets that request through, even with `required_plugins` (NRI v0.12.0 `pkg/adaptation/plugin.go:751-763`) |
| Latency budget | 10s per verifier, outside any global lock | 2s per request under a node-wide lock → needs a cache or precompute; verify asynchronously and decide synchronously |
| Process model | fork/exec per pull; Rust binary called per pull (stateless, needs its own cache) | Long-lived daemon over ttrpc, with state, cache and metrics |
| What's checked | Index digest **before download** (saves bandwidth and disk) | Digest of an image already in the content store; blocks use, not storage |
| Containers already running | No | Reported at `Synchronize`; eviction only from a later `CreateContainer`/`UpdateContainer` response |
| Errors seen by the user | `ErrImagePull` with reason | `CreateContainerError` with reason |

- **TOCTOU / digest pinning:**
  - Both check the digest, and content is addressed by digest, so tag mutation doesn't matter once you key on `digest`.
  - The pull verifier checks the resolved digest and the same descriptor is fetched (`pull.go:62-110`), so there's no gap.
  - With NRI, the digest comes from the containerd image record when the container is created, and the snapshot is built from that same image (`container_create.go:335, 344-346`). The only trust assumption is containerd's content store itself.
  - A policy change (key revoked) is enforced at the next creation by NRI, but never re-checked for cached images by the verifier.
- **Kubelet image GC and re-pull:** with the verifier, a GC'd image is checked again on re-pull, but cached images never are. NRI evaluates every container (re)start, including restartPolicy restarts after a crash, so caching per digest is required.
- **Platform subtlety:** `digest` is the **index** digest for multi-arch images. Signatures are usually on the index (cosign), but some attestations and SBOMs are per-platform manifest. To get the platform manifest, resolve it through the containerd content API (index → manifest whose config matches `config_digest`).
- **Recommendation:**
  - NRI plugin as the **enforcement point**: containerd ≥ 2.4 for `Container.image`, ≥ 2.2 for `required_plugins` fail-closed.
  - Optional bindir verifier as **early rejection and bandwidth saving**. It can be the same Rust binary in a CLI mode querying the daemon's cache.
  - Prefetch and verify asynchronously, e.g. watch containerd `/images/create|update` events, so NRI hooks only do cache lookups.

## 4. NRI mutation (brief)
- `CreateContainerResponse` can carry `adjust`, `update` (other containers' resources) and `evict` (`api.proto:279-286`).
- `ContainerAdjustment` covers annotations, mounts, env, OCI hooks, rlimits, CDI devices, args, and Linux devices/resources/cgroups path/oom/ioprio/seccomp/namespaces/sysctl/net devices/scheduler/RDT/memory policy (`api.proto:689-714`).
- Validators and the default validator can forbid some adjustments (`reject_oci_hook_adjustment` etc.).
- For this agent the possible use is `evict` of containers already running that break the policy, from a `CreateContainer` or `UpdateContainer` response; `Synchronize` and `UpdateContainers` cannot evict.