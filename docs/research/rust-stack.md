# Rust stack for a P2P OCI distribution agent: research report

**Short answer:** build on plain tokio with hyper/axum, tonic and rustls. Don't use a separate io_uring runtime, and drop the DHT, because the reflectors already hold the full content-to-peer map. Read blobs straight from containerd's content directory and fall back to gRPC, which is what Spegel already does.

**Sources:** crates.io API and GitHub API (checked today); local clones of tokio, containerd/rust-extensions and dragonflyoss/client in /tmp; this Spegel checkout; raw source files from containerd, moby/profiles, systemd and rust-libp2p. Anything marked ⚠ comes from memory or secondary sources and is not verified.

---

## 1. io_uring

### Workload fit
- **Serving large immutable blobs to peers.** This is sequential reads, mostly from page cache, since recently pulled layers are hot. The network is the bottleneck: one core can push 10–25 GbE with 256 KiB–1 MiB `read()` + `write()` on epoll. io_uring saves syscalls and threadpool hops. That matters for many small random I/Os (NVMe, `O_DIRECT`, >100k IOPS), not for a few large streams.
- **Writing fetched blobs.** This is sequential write, then `fsync`, then rename into place. Blocking-pool writes with large buffers are enough.
- **Manifests.** Small, CPU- and latency-bound; io_uring doesn't matter.
- **Dragonfly's Rust dfdaemon shows the same thing.** It uses no io_uring, sendfile or splice (grep over the cloned repo). It relies on `tokio::fs` plus an fd cache, a buffer pool, `fadvise` and `fallocate` (`dragonfly-client-storage/src/content_linux.rs:17-35`).

### Runtime comparison

| Runtime | Latest release | Activity | Model | HTTP / hyper | TLS | Verdict |
|---|---|---|---|---|---|---|
| **tokio** 1.54.1 | 2026-10-21 | very active | multi-thread work-stealing; epoll for sockets; files on the blocking pool | hyper 1.12, axum 0.8.9, tonic 0.14.9, reqwest 0.13.5 are all native | tokio-rustls 0.26.6 | default |
| tokio `io-uring` feature | in 1.54 | active, **unstable** | needs `--cfg tokio_unstable` plus feature `io-uring` (`tokio/src/macros/cfg.rs:750-760`); **fs only**: open, read, write, `File` AsyncRead (1.52), rename, try_exists; sockets still use epoll | transparent: same `tokio::fs` API | n/a | the cheap way to try io_uring; since 1.49 it falls back to the threadpool on `EPERM` (CHANGELOG #7724), and since 1.54 when the runtime has no IO driver (#8165) |
| **tokio-uring** 0.5.0 | 2024-05-27 | last push 2025-07; stagnant | runtime per thread; owned-buffer API | no official hyper integration | DIY | avoid |
| **monoio** 0.2.4 | 2024-08-20 | repo pushed 2026-10; ByteDance (Monolake) | thread-per-core, no work stealing; io_uring with `legacy` epoll fallback; has `splice` and `zero-copy` features | own `monoio-http`; hyper only via `tokio-compat` / monoio-compat (adds copies) ⚠ | monoio-rustls | niche; releases are stale |
| **glommio** 0.9.0 | 2024-03-25 | low activity (push 2026-08) | thread-per-core, io_uring only (kernel ≥5.8) | none built in; hyper only through examples ⚠ | DIY | avoid |
| **compio** 0.19.2 | 2026-09-29 | active (~1.9k★) | completion-based: io_uring, IOCP, polling fallback; thread-per-core plus dispatcher | `cyper` 0.9.0 client is hyper-based with http2/http3; has `compat-tokio` and `h3`/`quic` (quinn-proto) ⚠ server story is thinner | rustls / native-tls features | the best of the io_uring runtimes, but still 0.x |

The key constraint is that **every crate this project needs is tokio-bound**: tonic (containerd-client), oci-client and reqwest, hyper/axum, quinn. A non-tokio runtime means compat layers or a second runtime.

### Zero-copy with plain tokio
- tokio has no `sendfile` API. You call `rustix::fs::sendfile` / `nix::sys::sendfile` (rustix 1.1.6, nix 0.31.3) inside `TcpStream::async_io(Interest::WRITABLE, …)`, or `splice` through a pipe.
- **hyper can't use sendfile.** Its body goes through user-space `Bytes`. A sendfile fast path needs a hand-written HTTP/1.1 response path for `GET /v2/*/blobs/sha256:*` on the raw socket. That is feasible because the response is a fixed header plus an fd range.
- sendfile blocks the calling thread on page-cache misses, even when the socket is non-blocking. So run it on the blocking pool, or only when the file is likely cached.
- TLS rules out sendfile unless you use kTLS. The `ktls` crate exists, but its maturity and maintenance are unverified ⚠.
- Gain: it removes one memcpy per byte, roughly 5–15% CPU at 10 GbE ⚠. It does not make the network faster.

### Security and availability
- **containerd default seccomp:** the allowlist has `io_setup`/`io_submit` but **no `io_uring_*`**, so they are blocked (`containerd/contrib/seccomp/seccomp_default.go`, main). The same is true of **moby's default.json** (`moby/profiles/seccomp/default.json`). K8s pods using `RuntimeDefault` (or kubelet `--seccomp-default`) therefore have no io_uring. A privileged or `Unconfined` DaemonSet would.
- **systemd:** `SystemCallFilter=@system-service` *includes* `@aio`, and `@aio` contains `io_uring_setup/enter/register` (`systemd/src/shared/seccomp-util.c:440-454, 953-957`). A hardened unit still allows io_uring unless `~@aio` is added.
- **Kernel:** the `kernel.io_uring_disabled` sysctl exists since 6.6. 0 = enabled; 1 = only CAP_SYS_ADMIN or members of `kernel.io_uring_group`; 2 = disabled. Some enterprise distros ship it disabled ⚠ (believed to include RHEL 9.x).
- **Google** (kCTF VRP blog, June 2023 ⚠): about 60% of kernel exploit submissions targeted io_uring. It was disabled on ChromeOS and production servers, restricted via seccomp on Android, and GKE Autopilot was "investigating" disabling it through the default seccomp ⚠. COS/GKE node defaults today are unverified.
- Practical rule: in the K8s phase, assume io_uring may be missing. Detect at runtime with `io_uring_setup` (ENOSYS/EPERM) and fall back.

### Recommendation
1. Use tokio multi-thread with hyper/axum.
2. Put storage behind a trait, roughly `trait BlobStore { async fn open(&self, d: &Digest, range: Option<Range<u64>>) -> Result<BlobReader>; async fn ingest(...) }`. Implement it with `spawn_blocking` or `tokio::fs` and 512 KiB–1 MiB reads, plus `posix_fadvise(SEQUENTIAL/WILLNEED)`.
3. Optional later: a cargo feature `sendfile` adding a plaintext HTTP/1.1 blob fast path, enabled only when benchmarks show CPU-bound serving (≥25 GbE NICs, many concurrent peers).
4. For io_uring, at most try tokio's unstable `io-uring` for fs, behind a feature. It pays off only at very high file-op concurrency, `O_DIRECT` cache-bypass writes, or 100 GbE seeders. Don't adopt monoio or glommio.

---

## 2. Peer discovery: libp2p vs reflectors

### rust-libp2p status (libp2p 0.57.1, 2026-10-15; repo active)
- **Mature pieces:** noise 0.47, yamux 0.48, tcp 0.45, quic 0.14 (on quinn), identify 0.48, gossipsub 0.50.1. Gossipsub carries Ethereum consensus (Lighthouse), so it is battle-tested.
- **kad 0.49.0** works, but the default `MemoryStore` has **`max_provided_keys: 1024`** and `max_providers_per_key: K_VALUE (20)` (`protocols/kad/src/record/store/memory.rs:66-69`). A node with more than 1024 blobs must override this.
  - Provider records need republishing. Lookups take several RTTs (tens to hundreds of ms per digest).
  - This is the same cost Spegel pays with go-libp2p: `dht.Mode(dht.ModeServer)`, `ProtocolPrefix("/spegel")` in `pkg/routing/libp2p/libp2p.go:157-165`.
- autonat 0.16 (v1+v2) and relay/dcutr target NAT traversal, which is useless inside a cluster.
- Ecosystem signal: Parity wrote `litep2p` as a lighter alternative for polkadot-sdk (that is, perf and complexity concerns) ⚠.

### Alternatives
- **iroh** 1.4.1 (1.x, very active): QUIC with hole punching plus relays. iroh-blobs 0.104 uses **BLAKE3** verified streaming, which doesn't match OCI sha256 digests. iroh-gossip 0.102. It is built for the WAN/NAT case, so overkill in-cluster.
- **quinn** 0.11.12: solid QUIC. Datacenter benefit over TCP+HTTP/2 is small. containerd talks HTTP/1.1 to mirrors anyway. h3 is still young.
- **SWIM / gossip membership:**
  - **foca** 2.0.0 (caio/foca, 2026-08, MPL-2.0): transport-agnostic, you supply UDP. Small and solid.
  - **chitchat** 0.14.0 (Quickwit): scuttlebutt key-value anti-entropy plus phi-accrual failure detector. Can carry small per-node state, not a full index.
  - **memberlist** 0.8.5: hashicorp port, low adoption (about 15k recent downloads).

### With reflectors, a DHT isn't needed
The reflectors hold the full content-to-peer map, so the DHT's only job (finding providers) is already done centrally. One lookup is 1 RTT instead of O(log n), and the reflector can rank peers by zone, load or recency. This is the same as Kraken's tracker and Dragonfly's scheduler.

**Proposed shape:**
- **Agent to reflector:** a tonic bidirectional stream `Announce(stream IndexUpdate) -> stream Control`.
  - First message is a full snapshot with a `generation` (agent boot ID); deltas follow with a monotonic `seq`.
  - On a gap, or when the reflector restarts, the reflector requests a resync.
  - State is **soft**: it can always be rebuilt from agents, so no consensus or persistence is needed.
  - HA: each agent pushes to all R reflectors (R = 3). Lookups go to any of them.
  - Liveness: HTTP/2 keepalive or stream EOF removes the node, so agents need no SWIM.
- **Lookup:** unary `FindPeers(digest|ref) -> [peer addr, …]`, with short-TTL caching on the agent.
- **Memory:** 10k nodes × 2k blobs = 20M pairs. An interned-digest map to a `roaring` bitmap of u32 node IDs is about ≤200 MB ⚠ (estimate).
- **Degraded mode:** if reflectors are unreachable, the agent returns 404 or "not found" fast, and containerd's mirror fallback goes to upstream. Add foca only if peer-to-peer fallback without reflectors is wanted, or for membership among the reflectors themselves.
- **Index source:** containerd events plus a startup walk (see §3). Send content digests and resolved image refs. Tag resolution is a security choice; Spegel gates it with resolve-tags.

---

## 3. Talking to containerd

### `containerd-client` 0.9.0 (2026-04-15; containerd/rust-extensions, active)
- Pure tonic 0.14 / prost 0.14 bindings, **client only** (`build_server(false)`). It generates code for content, events, images, leases, namespaces, introspection, transfer, snapshots, tasks, sandbox and version (`crates/client/build.rs`).
- Helpers: `connect(path)` over a UDS, `Client::from_path`, `with_namespace!` (inserts the `containerd-namespace` metadata; uses `.unwrap()`), `to_any`. There are no high-level wrappers; you write raw RPCs.
- Content RPCs: `Info`, `Update`, `List` (stream), `Delete`, **`Read(ReadContentRequest{digest, offset, size}) -> stream ReadContentResponse{offset, data}`**, `Status`, `ListStatuses`, `Write` (bidi), `Abort`.
- Event RPC: `Subscribe(filters) -> stream Envelope{timestamp, namespace, topic, event: Any}`. Event types: `ContentCreate{digest,size}`, `ContentDelete`, `ImageCreate/Update/Delete{name, labels}`.
- Leases RPCs: `Create`, `Delete`, `List`, `AddResource`, `DeleteResource`, `ListResources`. Use them if the agent writes into containerd's store, so GC doesn't collect in-progress content.
- **Build:** prost-build needs `protoc` at build time ⚠ (no bundled protoc since prost 0.11). This affects the cross-compile images.
- **Spegel's Watch logic to port** (`pkg/oci/containerd/containerd.go:290-427`):
  - Subscribe filters: `/images/create|/images/update`, `/images/delete`, `/content/create`, `/snapshot/remove` in the namespace.
  - Initial state: `ListImages` plus a content `Walk`.
  - On `SnapshotRemove`, or `ImageDelete` of a digest name, re-walk and diff; on `ImageDelete` of a tag, remove that tag.
  - Skip events whose image `UpdatedAt` is newer than the envelope timestamp.
  - Resubscribe when containerd restarts.

### Reading blobs from disk directly
Path: `<root>/blobs/sha256/<hex>`. Spegel discovers `root` through `IntrospectionService.PluginInfo("io.containerd.content.v1","content").Exports["root"]` and falls back to gRPC `ReaderAt` if it is missing or inaccessible (`containerd.go:259-287, 430-452`). Copy that.

- **For it:**
  - Zero-copy and sendfile become possible.
  - No protobuf framing or UDS copy overhead.
  - Range reads are just `pread`.
- **Against it:**
  - Needs root or read access to `/var/lib/containerd` (a hostPath `readOnly` in the DaemonSet).
  - The content store is **global across namespaces**. Namespace ownership lives in bbolt `meta.db`, which you must not open while containerd holds it. So keep using the API for "is this digest in namespace X".
  - GC can unlink a blob mid-serve. An already-open fd stays valid on Linux, so it is safe, but open-then-404 races remain.
  - `ingest/` holds partial writes; never serve from it.
  - The layout is an implementation detail, though stable for years.
  - Verify digests on the *fetching* side, never trust the peer.

---

## 4. OCI, HTTP and TLS crates

- **oci-spec** 0.10.0 (2026-05-27; youki-dev): features `image`, `distribution`, `runtime`. Provides typed `ImageManifest`, `ImageIndex`, `Descriptor`, `MediaType` and distribution error types. Use only `image` + `distribution`.
- **oci-client** 0.18.0 (2026-09-18; oras-project; renamed from `oci-distribution`, frozen at 0.11.0 in 2024-03):
  - Pull manifest, index and blob, with streaming blob pulls (`pull_blob_stream`, range support ⚠).
  - `RegistryAuth::{Anonymous, Basic, Bearer}` and the token-auth dance.
  - Built on reqwest; features `rustls-tls`, `rustls-tls-no-provider`, `native-tls`, `hickory-dns`. Dragonfly uses it (lock pins 0.17/0.18).
  - Alternative: the agent may only need to *proxy* containerd's own upstream request, with containerd's auth headers passed through. Spegel does no upstream pulls at all, and containerd falls back itself.
- **docker_credential** 1.4.0: reads `~/.docker/config.json`, `credHelpers` and `credsStore`, and runs `docker-credential-*`. On nodes, creds usually live in the kubelet credential provider or containerd's `hosts.toml`/CRI config, not in docker config ⚠.
- **Server:** axum 0.8.9 (http1, http2) on hyper 1.12 / hyper-util 0.1.21. Implement the OCI distribution read subset: `HEAD`/`GET /v2/<name>/manifests/<ref>` and `/blobs/<digest>`, with `Range`, `Docker-Content-Digest`, `Content-Length`, and fast 404.
- **TLS:**
  - rustls 0.23.46 with tokio-rustls.
  - Provider choice: **aws-lc-rs** 1.19.0 is rustls' default, faster, and has a FIPS option, but builds C via cmake/cc, which makes cross-compiling harder. **ring** 0.17 is simpler to cross-compile.
  - reqwest 0.13 has rustls and aws-lc-rs features (`__rustls-aws-lc-rs`, `rustls-no-provider`). The default is believed to be rustls ⚠.
  - Avoid native-tls: OpenSSL linkage complicates musl/static builds.
  - In-cluster peer traffic: digests give integrity. TLS is needed only for confidentiality of private layers; mTLS between agent and reflector is sensible.

---

## 5. systemd integration and packaging

- **sd-notify** 0.5.0 (2026-03; MSRV 1.82): `notify(&[NotifyState::Ready])`, `Watchdog`, `watchdog_enabled()`, `listen_fds()`; feature `fdstore` keeps listening sockets across restarts.
- **listenfd** 1.0.2 (2025-01): `take_tcp_listener(i)` from `LISTEN_FDS`. sd-notify's `listen_fds` already covers this; pick one.
- **tracing-journald** 0.3.2 (2025-11): native journal protocol, so `tracing` fields become structured journal fields. Enable it only when `JOURNAL_STREAM` is set; otherwise use tracing-subscriber 0.3.23 fmt/JSON to stderr for K8s. `systemd-journal-logger` 2.2.2 is the `log`-based equivalent.
- **Unit hardening:** `Type=notify`, `WatchdogSec=`, `ProtectSystem=strict`, `ReadOnlyPaths=/var/lib/containerd`, `ReadWritePaths=<own cache>`, `SystemCallFilter=@system-service` (allows io_uring; add `~@aio` to forbid it), `AmbientCapabilities=` none if UDS permissions allow. The containerd socket is root:root 0660 by default, so the agent likely needs to run as root or with a group ACL.
- **Binary choice:**
  - *static musl*: one artifact works on any distro and in `FROM scratch`/distroless-static. The musl malloc is slow under multi-thread load, so use `mimalloc` or `tikv-jemallocator`. No NSS (fine; use hickory-dns or a plain `/etc/hosts`-free resolver).
  - *glibc*: faster allocator and fully supported DNS. Pin a minimum glibc with **cargo-zigbuild** (`--target x86_64-unknown-linux-gnu.2.28`, `aarch64-unknown-linux-gnu.2.28`).
  - Recommended: musl static plus mimalloc for both the systemd package and the DaemonSet image.
- **Cross-compile:**
  - cargo-zigbuild: no Docker; handles cc for ring and aws-lc-sys. aws-lc-sys may still want cmake ⚠.
  - `cross`: Docker images, more hermetic, and easier to install `protoc` into.
  - Either way, install `protoc`, or pre-generate and commit the prost code with `tonic-prost-build`, or use the pure-Rust `protox` compiler ⚠.
  - Build an amd64+arm64 multi-arch image (`docker buildx` with prebuilt binaries copied in per `TARGETARCH`).
- **DaemonSet needs:** hostPath `/run/containerd/containerd.sock`, the content root (ro), and `/etc/containerd/certs.d` (rw, to write `hosts.toml` mirror entries, as Spegel does). Plus hostPort or hostNetwork so containerd can reach `localhost:<port>`.

---

## 6. Prior art

**Uber Kraken (Go; uber/kraken, active).**
- **Architecture:** *agent* on every host (Docker-registry-compatible endpoint plus a BitTorrent-like piece protocol); *origin* cluster (dedicated seeders, consistent-hash ring, backed by S3/HDFS/GCS); *tracker* (peers announce which blobs they have or want, tracker returns a bounded peer set, Redis peer store with TTL); *build-index* (tag to digest, replication); *proxy* (pushes).
- **Lesson:** this is the closest match to the reflector design. Use announce with TTL'd soft state and a bounded peer list per lookup. Swarm at piece level so a hot 1 GB layer fans out in a tree instead of everyone hitting one seeder. Keep the tag index separate from blob routing. Uber reported large-scale fan-out (thousands of hosts in tens of seconds) ⚠ exact figures unverified.

**Dragonfly2 (Go manager/scheduler; Rust client `dragonfly-client` 1.5.12, dragonflyoss/client, active).**
- **Architecture:** *manager* (cluster config, dynconfig); *scheduler* (central parent selection per piece, with an evaluator for load and locality); *seed peers* (dfdaemon in seed mode pulling from origin); *dfdaemon* on every node (HTTP proxy or registry mirror for containerd).
- Peers announce over a gRPC bidi stream (`dragonfly-client/src/announcer`, `grpc/scheduler.rs`). Pieces move over gRPC `dfdaemon_upload` or the custom **vortex-protocol** 0.2 over TCP/QUIC (`dragonfly-client-storage/src/{server,client}/{tcp,quic}.rs`).
- Storage: piece files plus **RocksDB** metadata. The Rust client uses tokio 1.54, tonic 0.14, axum 0.8.9, quinn 0.11.12, rustls 0.23 with aws-lc-rs, oci-client and oci-spec — essentially the stack recommended here.
- **Lesson:** the Rust/tokio stack is proven for this workload, with no io_uring needed. A central scheduler or reflector gives better parent selection than a DHT. Piece-level multi-parent downloads raise throughput. The operational cost of manager + scheduler + Redis/MySQL is high; reflectors with only soft state avoid most of it.

**Spegel (Go; this repo).**
- **Architecture:** stateless, with an identical agent on every node. It serves the OCI distribution read API, and containerd is pointed at it through `hosts.toml` mirrors, with fallback to upstream.
- The index comes from containerd events plus walk (`pkg/oci/containerd/containerd.go:289-427`). Digests and refs are advertised into a go-libp2p kad DHT (`pkg/routing/libp2p/libp2p.go:157-192`). Bootstrappers are static, DNS or HTTP (`pkg/routing/libp2p/bootstrap.go`). Blobs are served from the content dir when its root is discoverable (`containerd.go:259-268`). Each blob comes whole from one peer.
- **Lesson:** reuse the mirror integration, the event-driven index, direct-disk reads with gRPC fallback, and fast-fail so containerd falls back. Replace the DHT (provider churn, lookup latency, 1024-key-style limits) with reflectors.

**Nydus and eStargz (brief).**
- **Nydus** (dragonflyoss/nydus, Rust): RAFS format with chunk-level dedup. Lazily loaded by `nydusd` through FUSE, virtiofs or EROFS+fscache, via nydus-snapshotter. Integrates with Dragonfly as a P2P backend.
- **eStargz** (stargz-snapshotter, Go): a seekable tar.gz with a TOC, backwards-compatible with ordinary registries, pulled lazily with HTTP Range requests.
- **Lesson:** these are orthogonal to P2P. Support **`Range` GETs on blobs** and HEAD semantics properly, so lazy-pull snapshotters can use the agent as a mirror.

---

## Recommended crate set

| Concern | Crates |
|---|---|
| Runtime / HTTP | tokio 1.54, hyper 1.12, hyper-util 0.1.21, axum 0.8.9 |
| gRPC (containerd and reflector) | tonic 0.14.9, prost 0.14, containerd-client 0.9.0 |
| OCI | oci-spec 0.10 (`image`, `distribution`); oci-client 0.18 only if the agent pulls upstream itself |
| TLS | rustls 0.23 + tokio-rustls 0.26 (provider: aws-lc-rs, or ring for easier cross builds) |
| Membership (only if needed) | foca 2.0.0 or chitchat 0.14 |
| Peer-set index | `roaring` bitmaps |
| systemd / logging | sd-notify 0.5, tracing + tracing-journald 0.3.2 |
| Metrics | prometheus-client 0.25.2 |
| Zero-copy (later, feature-gated) | rustix 1.1 for sendfile |
| Avoid | libp2p, iroh, monoio, glommio, tokio-uring, native-tls |

Open uncertainties (⚠ above):
- Exact Docker and containerd versions that dropped io_uring from seccomp. Current main is confirmed to block it.
- Which distros default `io_uring_disabled` to non-zero.
- How mature hyper compatibility is in compio and monoio.
- Status of kTLS in Rust.
- Whether `protoc` is really required for containerd-client builds.