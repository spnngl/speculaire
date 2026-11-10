# Spegel research report for the Rust rewrite (repo HEAD 9f94baa)

Paths are relative to `spegel/` or `website/content/docs/`. I verified the claims below against the code. Two areas are not verifiable here and are flagged: containerd's own fall-through behaviour and the actual effect of the libp2p transport options.

## 1. End-to-end flow

**How containerd is pointed at Spegel**
- An init container named `configuration` runs `spegel configuration`. It only runs when `containerdMirrorAdd=true` (`charts/spegel/templates/daemonset.yaml:42-86`).
- It is called with `--mirror-targets http://$(NODE_IP):30020` plus any `additionalMirrorTargets` (`daemonset.yaml:63-69`).
- `NODE_IP` is `status.hostIP` unless overridden (`templates/_helpers.tpl:94-100`).
- The writer is `containerd.AddMirrorConfiguration(ctx, configPath, mirroredRegistries, mirrorTargets, resolveTags, prependExisting, userinfo)` in `pkg/oci/containerd/mirror.go:32-137`. It is called from `main.go:155-166`.
  - It backs up the existing config dir to `<configPath>/_backup` once (`mirror.go:183-210`), then clears the dir (`212-228`).
  - It writes one `<configPath>/<host>/hosts.toml` per mirrored registry (`121-133`). An empty list means all registries, written to `_default` (`pkg/oci/filter.go:12`).
- What `templateHosts` writes (`mirror.go:230-274`):
  - `server = '<registry>'`. `docker.io` is rewritten to `https://registry-1.docker.io`; `_default` gets no server line.
  - One `[host.'<target>']` per target, with `capabilities = ['pull']`, plus `'resolve'` when `resolveTags` is on (`60-63`), and `dial_timeout = '200ms'`.
  - An optional `[host.'…'.header] Authorization = 'Basic …'`.
- `--prepend-existing` keeps the old `[host]` tables after Spegel's. It copies cert files and drops hosts that conflict with the mirror targets (`mirror.go:69-118`, `276-342`).
- Cleanup: `CleanupMirrorConfiguration` restores `_backup` (`mirror.go:139-181`). It is run by the post-delete-hook DaemonSet (`cleanup --addr=:8080`) plus the `cleanup-wait` job.
- The registry Service is a NodePort (30020) with `trafficDistribution: PreferSameNode` (`templates/service.yaml:34-45`). containerd dials the node IP and kube-proxy prefers the local pod. The docs say to use the node IP, not localhost (`usage/node-configuration.md:14`).
- **Fallback:** containerd tries the hosts in order, then `server`. This is standard `hosts.toml` behaviour, not Spegel code. Spegel signals a miss with **404**. containerd moves on after a 404 and after most non-2xx responses, but retries 408 and 429 on the same host, and 500/503/504 only on the last host (containerd v2.3.0 `core/remotes/docker/resolver.go:753-791`).

**How a request is resolved** (`pkg/registry/registry.go:171-231`)
- Routes (`137-144`): `GET /readyz`, `GET /livez`, and `GET`+`HEAD /v2/`. `readyz` returns 200 when `router.Ready()` is true, else 500 (`150-163`).
- Order of checks:
  1. Basic auth, if configured; failure returns 401 with `WWW-Authenticate: Basic realm="Spegel"` (`175-179`).
  2. `/v2/` returns 200 (`182-186`).
  3. Path parsing (`pkg/oci/distribution.go:103-165`):
     - Paths are `/v2/<repo>/manifests/<ref>` and `/v2/<repo>/blobs/<digest>`.
     - The registry comes from the `?ns=` query parameter, which is required for tags.
     - A parse failure returns 404 (`191`).
  4. Registry filters (whitelist + regex); a match returns 404 (`198-201`).
  5. If the `X-Spegel-Mirrored` header (`registry.go:32`) is not `"true"`, it checks the local store first: `Resolve` for tags, `Descriptor` for digests. On a miss it goes to `mirrorHandler`; otherwise it serves locally (`204-216`).
  6. Requests from peers carry `X-Spegel-Mirrored: true` and are always served locally only. This is the loop prevention.
- `mirrorHandler` (`233-329`):
  - It records hit/miss metrics (`239-247`).
  - HEAD and manifest requests get a 3 s timeout (`250-254`).
  - It calls `router.Lookup(ctx, dist.Identifier(), resolveRetries)` (`257`); an error returns 500 (`259`).
  - A `raceFetch` failure returns **404** (`266-270`). This 404 is what makes containerd fall through to the next host or upstream.
- Status codes used:

| Code | Meaning |
|---|---|
| 200 | OK |
| 206 | Range response, with `Content-Range` (`292`) |
| 400 | Bad range on local blob (`554`) |
| 401 | Bad basic-auth credentials |
| 404 | Every miss, filter hit, parse error or bad mediatype (`487-580`) |
| 416 | Range not satisfiable when mirroring (`286`) |
| 500 | Router lookup error, local blob open/seek error, readyz |

  - Error bodies are distribution-spec JSON `{"errors":[{code,message,detail}]}` with `BLOB_UNKNOWN` / `MANIFEST_UNKNOWN` codes (`distribution.go:188-217`).
- Once headers are sent, `WriteError` does nothing (`pkg/httpx/response.go:74-111`).
- A blob copy that fails mid-stream resumes from the next peer with `Range` start advanced by the bytes already sent (`registry.go:310-320`). This works because the headers have already gone out.

## 2. Content access

**Reading content**
- Spegel uses the containerd Go client (gRPC over `/run/containerd/containerd.sock`) for metadata (`NewContainerd`, `pkg/oci/containerd/containerd.go:77-118`).
- Blob bytes are read **directly from the filesystem**: `Open` opens `<contentPath>/blobs/<alg>/<encoded>` (`containerd.go:260-270`).
  - The default content path is `/var/lib/containerd/io.containerd.content.v1.content`, mounted read-only.
  - If the flag is empty, the path is found by introspecting the content plugin's `root` export (`430-449`).
  - If that fails, it falls back to gRPC `ContentStore().ReaderAt` wrapped in a `SectionReader` (`271-284`).
- `Descriptor` (`219-257`):
  - Size comes from `ContentStore().Info`.
  - There is no stored mediatype, so it reads the blob and sniffs it with `oci.FingerprintMediaType` (`pkg/oci/oci.go:27-134`).
  - Blobs over `ManifestMaxSize` (4 MiB, `oci.go:18`) are typed `application/octet-stream`.
  - Results go in an LRU(100) cache.

**Serving content**
- Manifests (`registry.go:480-526`):
  - Must be one of 4 manifest mediatypes (`oci.go:136-146`).
  - Headers: `Content-Type`, `Content-Length`, `Docker-Content-Digest`, `OCI-Namespace`.
  - Body is written with `io.Copy`.
- Blobs (`registry.go:528-599`):
  - Manifest mediatypes are rejected on `/blobs` (`537-541`).
  - Ranges are served with `Seek` + `LimitReader` (`585-592`), then `io.Copy` (`594`).
  - `response.ReadFrom` delegates to the underlying writer (`response.go:125-132`). For a local `*os.File` this gives Go's sendfile path on Linux; the gRPC fallback copies in userspace.
- Range parsing (`pkg/httpx/range.go:22-62`): single range only (multiple ranges are rejected); suffix ranges (`-N`, N ≥ 1) are supported; `ContentRangeFromRange` normalises against the size (`124+`).
- Proxied responses use `io.CopyBuffer` with a pooled 32 KiB buffer (`registry.go:115-120`, `304`). No sendfile there.

**Discovering what is local** (`Watch`, `containerd.go:287-352`)
- Initial state: `ListImages` plus `ContentStore().Walk` (`304-319`).
  - `ListImages` uses `ImageService().List(name~="^.+/")` and deduplicates, preferring tagged images (`169-206`).
- Then it subscribes to the containerd EventService for `/images/create|update|delete`, `/content/create` and `/snapshot/remove` in namespace `k8s.io` (`292-297`).
- `handleEvent` (`354-428`):
  - Content create: add the digest.
  - Image create/update: re-`Get` the image.
  - Snapshot remove, or image delete by digest name: re-walk the content store and diff (`index.go:59-79`). Image delete by tag: remove that tag from the index (`398-414`).
- The events channel closes when containerd restarts (`340-349`).
- The in-memory index (`pkg/oci/containerd/index.go:24-37`) emits CREATE for a tag only the first time it sees it. A changed digest updates the map but emits no event.
- `routing.Sync` (`pkg/routing/sync.go:13-74`) maps CREATE to `Advertise` and DELETE to `Withdraw`.

**Tag → digest**
- `Resolve` is `ImageService().Get("<registry>/<repo>:<tag>").Target.Digest` (`containerd.go:208-217`).
- DHT keys (`pkg/oci/reference.go:50-55`):
  - Digest refs use the bare digest, so the key is not tied to a repo.
  - Tag refs use `registry/repo:tag`.
- Effect: a reused tag such as `latest` sticks to the first digest cluster-wide (`usage/resolving-tags.md:17`).

## 3. Routing

**libp2p DHT**
- `go-libp2p-kad-dht` with `ModeServer` and `ProtocolPrefix("/spegel")` (`pkg/routing/libp2p/libp2p.go:157-164`).
- Keys are turned into a CIDv1 (raw codec, sha256 of the key string) (`createCid`, `535-547`).
- Provider records:
  - `AdvertiseTTL` 15 min, `MaxReprovideDelay` 2 min (`106-109`).
  - `ProvideValidity` = TTL + 2×delay = 19 min; `ProviderAddrTTL` 1 h.
  - Re-provided by `provider.SweepingProvider` every 15 min, with a 30 s connectivity check (`171-198`).
- The docs say "TTL of 10 minutes" (`faq.md:11`). That is stale.

**Transport and identity**
- The host is built with `libp2p.NoTransports` + `libp2p.Transport(tcp.NewTCPTransport)` (TCP only, `libp2p.go:138-141`).
- But the listen addresses include `udp/quic-v1` (`478-520`) and the chart exposes a `router-quic` UDP port. Which transports actually run was not checked; treat this as unresolved.
- A custom resource manager removes per-subnet limits, because IPv6 pod /56 ranges would otherwise share one budget (`650-658`).
- Identify address discovery is disabled and loopback addresses are filtered.
- The peer identity is an Ed25519 key in `<data-dir>/private.key`, PEM PKCS8 (`660-714`). It persists on the host at `/var/lib/spegel`.

**Bootstrap** (`pkg/routing/libp2p/bootstrap.go`)
- Interface: `Bootstrapper.Get(ctx) ([]peer.AddrInfo, error)`.
- Three implementations:
  - Static (`34-67`).
  - DNS (`71-116`): resolves ip4+ip6, sorts, takes the first 3 of each.
  - HTTP (`121-178`): fetches JSON `[{ID,Addrs}]` with optional mTLS and takes the first 3.
- The chart uses DNS against a headless `<name>-bootstrap` Service with `publishNotReadyAddresses` (`daemonset.yaml:110-111`, `service.yaml:58-63`).
- **There is no leader election or k8s lease.** The FAQ's "elect a unique leader" (`faq.md:44`) is stale.
- For bare IPs with an unknown peer ID, it dials with a random ID and takes the real ID from `sec.ErrPeerIDMismatch` (`libp2p.go:596-615`).
- `Run` (`217-276`) re-bootstraps on connectivity loss (backoff 50 ms → 10 s) and every 30 min.
- `Ready()` means the routing table is non-empty and connectivity has been reached (`278-283`).

**Lookup** (`libp2p.go:285-340`)
- `FindProvidersAsync(ctx, cid, count=resolveRetries)`, skipping self.
- Results are deduplicated with singleflight and cached as iterators in an expirable LRU (`lookupCacheTTL` 5 s, `51`). A cached iterator is reused if it is younger than 2.5 s or already has `count` peers.
- **Peer registry port is assumed to equal the local `RegistryPort`**; it is not advertised.
- `Iterator.Acquire` picks the least-used peer not currently acquired (`pkg/routing/iterator.go:97-125`). Failed peers are `Remove`d.

**Racing and hedging** (`raceFetch`, `registry.go:346-478`; `fetchChannel`, `601-642`)
- The first fetch starts immediately.
- Hedged extra fetches fire at the p80/p85/p90 latency, or immediately on a failure. The hedger is `resilient.NewHedger([]float64{80,85,90}, 50*time.Millisecond)` (`registry.go:132`): an HDR histogram that uses 50 ms until it has data. Its bound is `int64(500*time.Millisecond)`, in nanoseconds, while it records milliseconds (`hedge.go:21,57`), so it is effectively unbounded (`internal/resilient/hedge.go:21-79`).
- At most 4 concurrent fetches.
- Two timeouts:
  - Idle timeout = `resolveTimeout` (20 ms) while nothing is in flight (`376`).
  - Race timeout = max(2×p90, 100 ms) (`380`).
- The first success wins and the others are cancelled.
- Each fetch to a peer goes through `httpx.HappyEyeballs[T]` (`pkg/httpx/race.go:19-115`): IPv6 first, a 15 ms stagger between dials, and the first `GotConn` cancels the rest.

**At scale**
- Each lookup is a Kademlia `FindProviders` (O(log N) hops).
- Every node is a DHT server and re-provides every key every 15 min, so provider load scales with images × layers × nodes.
- Bootstrap only needs about 3 seeds.
- A dead node keeps being advertised for up to about 19 min. Failed fetches remove the peer from the iterator, and hedging limits the latency cost.
- Multiple separate clusters: deploy with a unique `nodeSelector` and nodePort (`faq.md:42-49`).

## 4. Flags (all have UPPER_SNAKE env equivalents; `main.go:39-95`)
- Global `--log-level` (INFO): slog JSON to stderr.
- `version --format` (text).
- `configuration`:
  - `--containerd-registry-config-path` (`/etc/containerd/certs.d`): hosts.toml directory.
  - `--mirrored-registries`: registries to mirror; empty means `_default` (all).
  - `--mirror-targets` (required): Spegel or extra mirror URLs, in order.
  - `--resolve-tags` (true): add the `resolve` capability.
  - `--prepend-existing` (false): keep existing hosts after Spegel's.
- `registry`:
  - `--metrics-addr` `:9090`: metrics, pprof and debug web.
  - `--registry-addr` `:5000`: OCI read-only registry.
  - `--router-addr` `:5001`: libp2p listen address.
  - `--containerd-sock`: path to the containerd socket.
  - `--containerd-namespace` `k8s.io`.
  - `--containerd-registry-config-path`: used for validation.
  - `--containerd-content-path`: direct blob reads; empty means introspect.
  - `--data-dir`: persists the libp2p key.
  - `--mirrored-registries`: whitelist filter.
  - `--registry-filters` (regex list): deny matching `registry/repo[:tag]`.
  - `--mirror-resolve-timeout` 20 ms: idle wait for a peer.
  - `--mirror-resolve-retries` 3: provider count / max peers.
  - `--debug-web-enabled` (true).
  - Bootstrap flags (`main.go:51-57`): `--bootstrap-kind` (dns|http|static), `--dns-bootstrap-domain`, `--http-bootstrap-url`, `--http-bootstrap-cert-dir` (CA + client cert), `--static-bootstrap-peers`.
- `cleanup --addr` (required) and `--containerd-registry-config-path`: restore the backup and serve a probe.
- `cleanup-wait --probe-endpoint` (required), `--threshold` 3, `--period` 2s.
- Basic auth is read from files in `/etc/secrets/basic-auth` (`pkg/httpx/userinfo.go:18-63`, constant-time compare). It is used for the inbound registry check, the hosts.toml header and the outbound client.
- Preflight: inside Kubernetes the runtime must be Linux Distroless (`pkg/preflight/preflight.go:14-22`).
- Notable Helm values (`charts/spegel/values.yaml`): memory 128Mi request/limit (`73-77`), `priorityClassName: system-node-critical`, tolerate everything, `basicAuthSecretName`, `persistence`, `networkPolicy`, `serviceMonitor`, VPA, `extraInitContainers`. `GOMEMLIMIT` is derived from the memory limit.

## 5. Limitations, requirements, FAQ, security

**Containerd**
- Containerd only (`getting-started.md:84`).
- containerd ≥ 2.2 is enforced (`containerd.go:131-133`).
- On ≥ 2.4, the CRI images plugin is introspected and Spegel refuses to run if `discard_unpacked_layers` is on (`150`).
- **Bug:** the config-path check at `containerd.go:142` compares `registryConfigPath` with itself, so it can never fail.
- containerd must have `config_path` set and `discard_unpacked_layers=false`. Changing either needs a containerd restart, so Spegel cannot do it itself (`getting-started.md:85-95`).

**Per-distro notes** (`getting-started.md:99-342`)

| Distro | Notes |
|---|---|
| AKS, CKS, DigitalOcean, Minikube, Kapsule, NKP | Work out of the box (green) |
| EKS AL2023 | discard is on by default; fix via nodeadm |
| EKS Bottlerocket | Needs ≥ v1.56; configure via bootstrap container; `containerdMirrorAdd=false` |
| GKE | discard on and legacy mirror config by default. Needs a project-level startup-script writing `/etc/containerd/conf.d/spegel.toml`, a dummy `registry_hosts`, `containerdRegistryConfigPath: /etc/containerd/hosts.d` and `priorityClassName: ""`. Existing nodes are not fixed. |
| K0S | Different socket and content paths; config in `/etc/k0s/containerd.d` |
| K3S / RKE2 | Embed Spegel natively |
| Kind | Disable discard; `content_sharing_policy="isolated"` recommended |
| Talos | Disable discard; path `/etc/cri/conf.d/hosts`; PSA namespace must be `privileged` |
| VKE | Needs a custom `hostPort` |

**Behaviour limits**
- Tag resolution pins reused tags. Fixes: `resolveTags:false`, a `:latest$` filter, or k8s-digester. None of these help during a registry outage (`usage/resolving-tags.md`).
- Init-container bootstrap has a chicken-and-egg problem and a scheduling race. Alternatives: write hosts.toml in node user data (`_default`, node IP, `dial_timeout '200ms'`) or use the paid Kvick operator (`usage/node-configuration.md`).
- No GC of its own; relies on kubelet image GC (`faq.md:38-40`).
- The 128Mi limit exists because the page cache is charged to the container (`faq.md:51-53`).
- OCI volumes are supported (`faq.md:55-57`).
- `additionalMirrorTargets` can chain a second cache such as zot (`faq.md:27-36`).
- For local clusters the docs recommend Hall (`usage/local-cluster.md`).

**Security model**
- Private images: any node can pull any cached image without pull secrets. Mirror requests carry no credentials, and AlwaysPullImages is ineffective (`faq.md:15-25`, `usage/multi-tenant-credentials.md:6-14`). Suggested mitigation is admission policies (VAP, Gatekeeper, Kyverno) or Kvick `imageCredentials`.
- **Spegel never verifies digests** of bytes received from peers; the grep for a verifier found nothing (`pkg/oci/client.go` `Fetch` `284-364` only checks headers). Integrity relies on containerd checking the digest of fetched content against the requested descriptor. That is containerd behaviour and was not checked here.
- Tag→digest answers come from peers' containerd image stores. A malicious peer could answer a `resolve` with any digest it serves. The trust model is "all nodes trusted"; disable `resolve` to avoid this.
- Other controls: optional basic auth, an optional NetworkPolicy limiting libp2p to Spegel peers in the namespace, and optional mTLS only for HTTP bootstrap. libp2p connections are encrypted but there is no allowlist of peer IDs.

## 6. Metrics and debug

**Metrics** (`pkg/metrics/metrics.go:20-35`, `pkg/httpx/metrics.go:6-22`; documented in `metrics.md:7-15`)

| Metric | Type | Labels |
|---|---|---|
| `spegel_mirror_requests_total` | counter | `registry`, `cache=hit\|miss` |
| `spegel_mirror_last_success_timestamp_seconds` | gauge | none |
| `spegel_resolve_duration_seconds` | histogram | `router` |
| `spegel_advertised_keys` | gauge | none in code (docs claim `registry`) |
| `http_request_duration_seconds` | histogram | `handler`, `method`, `code` |
| `http_response_size_bytes` | histogram | `handler`, `method`, `code` |
| `http_requests_inflight` | gauge | `handler` |

- libp2p and DHT metrics are also registered (`libp2p.go:127`).
- Request logs are emitted at V(1); `readyz` and `livez` are not logged (`pkg/httpx/mux.go:65-108`).

**Endpoints on `:9090`** (`main.go:284-309`)
- `/metrics`, `/debug/pprof/*`.
- `/debug/web/` (embedded templates, `pkg/web/web.go:28-29`, `86-93`):
  - `metadata`: libp2p peer ID.
  - `stats`: local addresses, local images, DHT peers, last mirror success.
  - `measure?image=`: a 3 s DHT lookup plus a full pull through the local mirror, with timings per blob (`180-223`). The pull uses `Client.Pull`, which picks the platform from an index (`client.go:167-282`).
- The docs use "Last Mirror Success" on this page to check that Spegel is working (`getting-started.md:74-80`).

## 7. Signatures, referrers, attestations
- **Not supported.** There is no `/v2/<repo>/referrers/<digest>` route; only manifests, blobs and `/v2/` exist (`distribution.go:103-165`). Any other path returns 404 and containerd falls through upstream.
- Manifest mediatypes are limited to OCI index/manifest and Docker list/manifest v2 (`oci.go:136-146`). The sniffer returns a JSON document's own `mediaType` when `schemaVersion` is 2, and otherwise classifies it by its keys (`oci.go:27-134`). So a cosign `.sig` manifest (an OCI image manifest) is served as a manifest; only other manifest mediatypes, such as the deprecated `application/vnd.oci.artifact.manifest.v1+json`, are refused.
- Signatures pulled by digest work only incidentally: if the content is in the store, a digest lookup serves it, with a sniffed mediatype.
- Docker buildx attestation manifests inside an index are just descriptors; there is no special handling (only a testdata fixture contains `attestation-manifest`).
- The only cosign usage is signing Spegel's own release image and chart (`.github/workflows/release.yaml:23-75`).
- Spegel does no signature verification at all.

## Takeaways for the Rust rewrite
- Keep: the 404 miss semantics, the `X-Spegel-Mirrored` loop guard, digest keys not tied to a repo, the hedged race, resuming a failed copy via `Range`, and direct filesystem reads with sendfile.
- Fix:
  - Advertise each peer's registry port instead of assuming it matches the local one.
  - Make the config-path validation actually check something.
  - Decide whether to verify digests in flight.
  - Decide whether a reused tag should emit an event when its digest changes.
  - Decide whether to support referrers.
  - Settle the TCP vs QUIC transport mismatch.
- Docs are stale on the TTL, ReverseProxy and leader election.