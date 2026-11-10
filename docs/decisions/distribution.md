# Decisions: distribution

Image content flow between containerd, the local mirror, peers and upstream. Index: `docs/decisions/README.md`.

## D3: Every agent announces its own peer address and port (amended by D36)

- **Because:** Spegel assumes every peer listens on the same port as the local one (`docs/research/spegel.md` §3), which breaks mixed configurations.
- **Revisit when:** —

## D5: Serve blobs from containerd's content directory

- **Decision:** read `/var/lib/containerd/io.containerd.content.v1.content/blobs/` directly (read-only), with a gRPC `Content.Read` fallback.
- **Because:** this is Spegel's proven path, and it is the cheapest one.
- **Revisit when:** —

## D6: Tag resolution is off by default

- **Decision:** the mirror host gets capability `pull` only, never `resolve`.
- **Because:** with `resolve`, a peer could answer a tag with any digest it serves. Without it, tags resolve upstream (a small request) and blobs, the bulk of the bytes, still go P2P.
- **Revisit when:** users need tag pulls to survive an upstream outage. Then expose `resolve_tags = true`, documented as "trust all nodes".

## D7: Verify blob digests in flight

- **Decision:** hash every full-blob response while streaming it; on mismatch, abort and report the peer.
- **Because:** it catches a bad peer early, so it can be reported. Otherwise the error only surfaces at containerd's commit.
- **Limit:** when containerd itself sends a `Range` request (resuming a download), the agent relays the range unhashed; containerd's commit check is then the only check.
- **Revisit when:** —

## D14: The mirror is TLS with client auth on loopback; the peer API is mTLS on the node IP (amended by D32)

- **Decision:**
  - The mirror listens on `127.0.0.1:7480` (configurable) with TLS and requires a client certificate.
  - `speculaire configure` generates a local CA, a server certificate for `127.0.0.1` and a client certificate for containerd, in `/var/lib/speculaire/mirror/` (root, mode 0600).
  - It writes their paths as `ca` and `client` in each `hosts.toml` mirror entry.
  - The mirror accepts only client certificates signed by that local CA.
  - The peer API listens on the node IP, port 7481, with mTLS (D16).
- **Because:**
  - A plain loopback mirror lets any local process, including any `hostNetwork` pod, read every cached private layer.
  - containerd's `hosts.toml` supports `ca` and a combined-PEM `client`, and reads them on every resolve (containerd v2.3.0 `core/remotes/docker/config/hosts.go:247-286`).
  - **The kubelet client certificate is not used here.** Before the node joins the cluster the file does not exist, and containerd then fails every pull for that registry with "unable to read CERT file". That would break `kubeadm join`'s own image pulls.
  - A root-only local key gives the same protection: an attacker with root can read the content directory anyway.
  - systemd uses host networking, so loopback works. That removes Spegel's NodePort hop and its init-container chicken-and-egg problem.
  - Ports avoid 5000, which local kind registries commonly use.
- **Revisit when:** a benchmark shows loopback TLS costing more than 10% of the agent's serving CPU.

## D17: Upstream access reuses containerd's registry config

- **Decision:**
  - Artifact discovery, referrers and prewarm resolution reuse containerd's *registry config*, in containerd's own formats.
  - The agent parses `/etc/containerd/config.toml` and its `imports`, then reads `registry.config_path`, `registry.configs."<host>".auth` (`username`, `password`, `auth`, `identitytoken`) and `registry.headers`. These live under `plugins."io.containerd.grpc.v1.cri".registry` (config version 2) or `plugins."io.containerd.cri.v1.images".registry` (version 3).
  - It reads each `hosts.toml` for `server`, hosts, `capabilities`, `ca`, `client`, `skip_verify`, `header` and `override_path`, and skips its own mirror entries.
  - The `oci` crate implements the registry Bearer token challenge.
  - `speculaire configure` adds its mirror host at the top of each `hosts.toml` and keeps the existing entries.
  - Images that are pullable only with pod `imagePullSecrets` get no upstream artifact fetch. They verify from peers, or end `Unverifiable("artifacts unreachable")` (D20).
- **Because:**
  - There is one source of truth for registry access: whatever containerd can reach, the agent can reach with the same TLS and credentials.
  - With `config_path` set, containerd still uses `configs."<host>".auth` as fallback credentials and passes `headers` to its registry authorizers (v2.3.0 `internal/cri/server/images/image_pull.go:105-114`, `:504-507`); setting `mirrors` as well is a startup error (`internal/cri/config/config.go:503-506`). So the agent reads both files, and `configure` edits only `hosts.toml`.
  - Pull secrets travel with each CRI request (`image_pull.go:105-114`) and never reach a file the agent could read.
- **Revisit when:** users need pull-secret-only images verified. Then add kubelet credential-provider support.

## D24: Peers apply backpressure

- **Decision:** the peer API serves at most `peer.max_uploads` concurrent blob bodies (default: 4 × CPUs). Beyond that it answers `503` at once, and the fetcher treats `503` as a fast failure and moves to the next peer.
- **Because:** in a flash crowd every node finds the same first seed; Spegel has no limit, so one node's uplink becomes the cluster bottleneck.
- **Revisit when:** a flash-crowd benchmark shows one seed peer saturating. Then add multi-peer `Range` swarming.


## D36: The peer address is the local side of the reflector connection (amends D3)

- **Decision:**
  - By default, an agent announces as its peer address the local IP of its `Announce` stream to a member, as returned by `getsockname`, and listens on that IP, port 7481. The address is fixed at startup from the first such stream; the peer API starts listening only then. The load-balancer connection is never used: on a control-plane node that holds the load balancer's virtual IP, its local IP would be that VIP, which moves.
  - `peer.address` overrides it, for nodes where peers must use another interface.
  - IPv4 and IPv6 work the same way; on a dual-stack node, the family is the one the reflector connection used.
- **Because:**
  - That IP is the one the cluster routes through to reach the control plane, which is the best guess on multi-NIC nodes without asking the admin.
  - Peers check each other by the node name in the certificate (D16), never by IP, so a wrong guess fails as an unreachable peer, which falls through, never as a trust problem.
- **Revisit when:** users report an interface the guess gets wrong on a common platform; then add that platform's rule.
