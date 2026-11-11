# Proposal: federation of swarms

Status: proposal, unscheduled; D1's "Revisit when" names its trigger. Written 2026-11-11, when the choices in § Settled were made. Nothing here is a decision yet: when the work starts, each settled choice becomes a decision in `docs/decisions/`, § Trust boundaries goes into `docs/security.md`, and this file shrinks to what is still open. Choices still open carry their default in brackets.

## Goal

Swarms in different clusters share public images directly, over links between their gateways, with no hub. A layer then leaves an upstream registry about once across all federated swarms, not once per cluster. A swarm shares only the repositories its config declares public, with their signatures, attestations and SBOMs, and nothing else of its cluster.

D1 names this trigger: "Revisit when: … multi-cluster sharing."

## Non-goals

- Private repositories (settled 13). Nothing pulled with credentials ever crosses a link.
- Tag resolution without upstream. The runtime resolves tags upstream (D6, D66), so federation serves only digest-addressed content. A pull by digest works with upstream unreachable, as long as some swarm holds the image.
- Sharing verdicts. Every node still verifies for itself (D26, `docs/security.md`).
- Transit routing. A swarm serves only what its own nodes hold; it never relays from a third swarm.
- Judging licences. Sharing an image with another organisation's swarm redistributes it, and some vendor images are public to pull but licensed against redistribution. Share rules are the admin's call on licensing too: the default list suits swarms of one organisation, and `docs/operations.md` says so beside `federation.share`.

## Settled (2026-11-11)

1. **Gateways are separate, unprivileged processes** (`speculaire gateway`), on nodes the admin picks (§ 3). Each swarm publishes one DNS name that points to an ingress, which passes TLS through to its gateways.
2. **Federation has its own PKI.** A cluster CA or a kubelet certificate never authenticates across swarms: any node of a cluster holds a certificate from its CA, so a compromised worker could pose as its swarm. Only gateways hold federation keys, and the CA key stays offline.
3. **A remote swarm comes before upstream**, when its share index lists the digest. This can be changed per swarm.
4. **Share indexes are synced** over the link, digests only, so a lookup never waits on the WAN.
5. **Re-sharing follows the holder's own config.** Swarm B serves swarm C what it got from swarm A only if B's own share rules match it.
6. **A swarms file names 64 swarms at most**, so the `swarm` metric label stays bounded.
7. **Share rules keep a public check, per image.** `federation.share` is the admin's declaration of what is public; an anonymous `HEAD` of each image's digest upstream still catches a rule that matches a private repository, or a private image retagged under a public name (§ 4).
8. **Phase 1 runs on plain HTTP, without the PKI** (§ 9). The federation CA and the `federation init`/`issue` commands wait for phase 2.
9. **Every gateway certificate carries the swarm's DNS name**, since one ingress serves every gateway of the swarm (phase 2).
10. **Each gateway links to every remote swarm**, as agents stream to every member in D2.
11. **A remote swarm reaches nothing Kubernetes-related or private**: no cluster identity, topology, credentials or unshared content crosses a link (§ 7).
12. **Signatures, attestations and SBOMs are shared** with the images they sign, from phase 1 (§ 6).
13. **No private repository is ever shared**: there are no grants. Phase 2's PKI decides which swarms may link at all.
14. **A remote swarm's index is untrusted**: it is capped, and a swarm that advertises digests it does not serve is denied (§ 8).
15. **A reflector never hosts a gateway**: the exposed node holds no index (§ 3).
16. **No database.** Federation state is soft state in memory, as the reflectors' index is (D2); only the public-check cache is saved, in `/run` (§ 10).

## Vocabulary (new words)

| Word | Meaning |
|---|---|
| *swarm* | The agents of one cluster, its reflectors and its gateways. |
| *gateway socket* | `/run/speculaire/gateway.sock`: the agent's four calls for the gateway on its node, the only way the gateway reaches its swarm (§ 3). |
| *federation* | The swarms linked to each other. Each pair agrees explicitly; there is no membership protocol. |
| *gateway* | The `speculaire gateway` process: an unprivileged systemd unit beside the agent of a node the admin picks. It holds the links to remote swarms and the federation key, and reaches its own swarm only through that agent's gateway socket (§ 3). |
| *link* | One connection between a gateway and a remote swarm's gateway, dialed by either side and used both ways: mTLS, or plain HTTP in phase 1. |
| *share rule* | A repository glob in `federation.share`: a repository its admin declares public. |
| *share index* | The digests a swarm serves to remote swarms: those reachable from the images its nodes hold under a name that a share rule matches and that passes the public check, with their signatures, attestations and SBOMs. |

## Design

### 1. Identity: a federation CA per swarm (phase 2)

- `speculaire federation init` creates the swarm's federation CA (an Ed25519 key and a self-signed certificate) on an admin machine, and prints its SPKI hash, `sha256:<hex>`. Its key never goes to a node.
- `speculaire federation issue --name <DNS name>` signs one key and certificate per gateway:
  - the DNS name goes in the SAN, and the EKU allows both server and client auth;
  - the lifetime is short [90 days, reissued by hand; renewal through cert-manager later];
  - the gateway reads them from `gateway.certificate` and `gateway.key` [`/etc/speculaire/gateway/`, owned by `speculaire-gateway`, mode 0600], and reloads them when the files change, as D16 does for kubelet certificates.
- A gateway accepts a peer only if its chain ends at a CA the swarms file pins for that swarm. As a client, it also checks the SAN against the DNS name it dialed.
- No revocation list. A leaked gateway key is valid until it expires; a leaked CA key means a new CA, which every linked swarm must pin. Pinning two hashes per swarm lets a CA rotate without an outage.
- `speculaire_federation_certificate_expiry_seconds` and an alert at 14 days left (`docs/operations.md`).
- What the PKI protects: the share index is public content, so authentication keeps unlisted swarms off the gateways' bandwidth, and keeps them from learning which public images a swarm runs.

Rejected: pinning the remote cluster CA (settled 2); pinning each gateway's key, as WireGuard does, because every rotation would edit every remote file.

### 2. The swarms file

The admin keeps one TOML file, the same on every gateway:

```toml
# /etc/speculaire/swarms.toml
[[swarm]]
# A local alias: the metrics label and the logs use it.
name = "fra"
# Their federation CA's SPKI hash, or two during a CA rotation. Phase 1 sets `transport = "http"` instead (§ 9).
ca = ["sha256:7b1e…"]
# Their DNS name. Leave it out when only they can dial us (we sit behind NAT).
address = "fed.fra.example.com:443"
# Ask them before upstream (settled 3), or after it ("upstream").
prefer = "federation"
```

- A link opens only when both files list each other: a gateway refuses a certificate whose CA no entry pins. Phase 1 cannot enforce this on inbound links (§ 9).
- `gateway.swarms_file` points to the file [`/etc/speculaire/swarms.toml`, live]. It reloads like the config, on SIGHUP and every `config.poll_interval` (D30). Removing a swarm closes its links.
- The parser refuses more than 64 entries, duplicate names and duplicate CA hashes (settled 6).

### 3. Gateways and transport

**Two processes on a gateway node** (settled 1). The process that parses input from other clusters holds nothing of this one:

- The **agent** runs as on any node, as root, with the kubelet certificate (D16) and the runtime's sockets. With `federation.gateway = true` [`false`, restart] it also opens the *gateway socket*, `/run/speculaire/gateway.sock` (mode 0660, group `speculaire-gateway`). It builds the share index (§ 4) and enforces it on every call.
- The **gateway**, `speculaire gateway`, is a unit of its own, `speculaire-gateway.service`, with these settings:
  - it runs as the unprivileged user `speculaire-gateway`, with no capability;
  - `InaccessiblePaths=` hides `/var/lib/kubelet`, `/etc/kubernetes`, `/var/lib/speculaire` and the runtime sockets;
  - it holds only the federation key and certificate (§ 1), the swarms file (§ 2), and `/etc/speculaire/gateway.toml`, its own config;
  - it reaches its swarm only through the gateway socket, never the peer API, a reflector or the Kubernetes API.
- **The gateway socket** offers four calls:
  - `ShareIndex`: the agent streams the share index to the gateway;
  - `Fetch(digest, offset)`: the agent serves a blob or an artifact, but only one in the share index;
  - `RemoteIndex`: the gateway streams each remote swarm's index to the agent, which announces it to its reflectors;
  - `RemoteFetch(swarm, digest, offset)`: the agent asks the gateway for a blob from a remote swarm.
- **What a compromised gateway can do:** read public content, and feed the agent remote entries, which are capped (§ 8) and checked against their digest. It gets no node credential.
- **A reflector never hosts a gateway** (settled 15): `federation.gateway = true` with `role = "reflector"` stops startup. The recommended gateway nodes are dedicated and tainted.

**Transport:**

- The gateway listens on `gateway.listen` [`[::]:7484`, restart]. The swarm's DNS name points to an ingress that routes by SNI and passes TLS through to that port on every gateway: ingress-nginx `ssl-passthrough`, or a Gateway API `TLSRoute`.
  - The gateways are systemd units, not pods, so the Service behind the ingress has no selector, and its EndpointSlice lists the gateway nodes. M8's DaemonSet replaces this with a selector.
  - An ingress that terminates TLS cannot carry the client certificate, and is not supported.
- Every gateway keeps one link to each remote swarm with an `address` (settled 10). A swarm without an address dials us, and its links land on any of our gateways through the ingress.
- A link opens with `Hello{protocol_version, swarm}`. A gateway accepts its own version and the previous one, and protobuf changes are additive only, so swarms upgrade one at a time, as D2 does for reflectors.
- The side that dials opens every gRPC stream, so a swarm behind NAT only needs outbound access:
  - `Index`: a bidi stream carrying each side's share index, as a snapshot and then deltas, like `Announce` (D2);
  - `Fetch(digest, offset)`: the dialer asks the remote side for a blob or an artifact; the offset resumes a stalled transfer, as `Range` does inside a swarm (D73);
  - `Referrers(subject)`: the dialer asks for the referrers of a subject digest (§ 6);
  - `Serve`: when the remote side wants a blob from the dialer, it asks on `Index`, and the dialer opens a `Serve` stream that uploads it.
- A link that drops degrades to *fall through*, as a reflector outage does (D1).

### 4. What a swarm shares

- `federation.share` lists the share rules [`["docker.io/**", "registry.k8s.io/**", "quay.io/**", "ghcr.io/**"]`, live], in the agent config of gateway nodes. Entries are globs on `registry/repository`.
- **Agents report image names.** `Announce` gains, for each image index or manifest digest a node holds, the names it holds it under: from containerd's image records, or the names in CRI-O's `images.json` (D65). Reflectors keep them beside the digest map.
  - containerd's `containerd.io/distribution.source.<registry>=<repo>` content labels (v2.4.2 `pkg/labels/labels.go:39-41`) cannot replace them: `core/remotes/docker/handler.go:60-66` stops adding to the label once it grows too long, which happens on the most widely shared layers.
- **The public check is per image** (settled 7). A share rule is a declaration: a glob as wide as `docker.io/**` also matches private repositories, and anyone with root on a node can retag a private image under a public name (`ctr image tag`). Before an image enters the share index, the agent sends an anonymous `HEAD /v2/<repo>/manifests/<digest>` upstream for its exact digest:
  - a `200` proves that this exact image is public under that name;
  - the answer is cached per digest for 1 h, negative answers too;
  - a private answer keeps the image out, logs a warning and counts it;
  - Docker Hub does not count `HEAD` against its rate limit.
  - A registry that asks for login even for public images, such as `registry.redhat.io`, fails the check, so nothing from it is shared. That is the safe side.
- **The agent of a gateway node builds the share index.** It reads the image names from its reflectors, keeps those that a share rule matches and that pass the public check, and walks each image down to its config and layers. It reads the manifests from peers; they are small and checked against their digest.
- **Only digests in the share index are served.** A request names the digest only, so a swarm that knows a private layer's digest gets a 404. A layer that is in both a public and a private image is served: the public image makes it public.

The requesting side sends no credentials, no image name and no list of what to fetch: it asks a swarm whose index holds the digest, and that swarm applies its own rules.

### 5. Pull flow

The local steps of ARCHITECTURE.md § Pull stay first. Federation comes in at step 2:

1. `Lookup` is unchanged: the digest only.
2. The agent of a gateway node announces each remote swarm's index, received through `RemoteIndex`, to its reflectors as remote entries tagged with the swarm. A reflector returns local holders first. Then, by the swarm's `prefer`, it returns the gateway nodes that can reach a swarm holding the digest. The lookup stays local, and no WAN round trip happens before the fetch.
3. The agent fetches from the gateway node's peer API. That node's agent calls `RemoteFetch`, the gateway streams from a remote gateway, and the remote gateway streams from its own agent's `Fetch`, which streams from one of its peers.
   - The agent of the gateway node coalesces concurrent requests for one digest into one remote fetch, and copies the stream to every waiting node. Each blob then crosses the WAN once per swarm.
   - Nothing is kept on the way. Once a node commits the blob, it announces it, and later lookups find that node first.
4. D7, D52 and D73 apply to remote swarms too:
   - The agent hashes in flight, and denies a gateway node that relays a wrong digest for `peer.deny_ttl`.
   - The gateway node's agent, which also hashes, denies the remote swarm that sent it.
   - A stall moves on after `peer.stall_timeout`, and the transfer resumes at its offset from another gateway if one can reach a holder.
5. On a miss, a link down, or no first byte within `federation.timeout` [`2s`, live], the agent falls through to upstream.

On CRI-O, the mirror falls through only on the manifest: once it serves one, CRI-O takes every blob of that image from it (D66). A blob no remote swarm serves is then fetched upstream by the agent itself, as D66 does for a blob no peer holds, and kept in the blob cache (D67).

### 6. Signatures, attestations and SBOMs

Shared from phase 1, under the same rules as images (settled 12):

- **What is shared:** every artifact in the artifact store whose subject digest is in the share index: Sigstore bundles, cosign signatures from the `.sig` tag, attestations and SBOMs found as referrers, and the referrers index listing them. BuildKit attestation manifests are part of the image index (D49), so the image walk of § 4 already covers them.
- **The share index carries them:** each subject digest lists its artifact digests, so a lookup stays local, as for blobs.
- **`Referrers(subject)`** returns the descriptors the remote artifact store holds for that subject. The artifacts themselves come through `Fetch`, by digest, hashed in flight.
- **Step 2 of the Verify flow gains "federated swarms"** between peers and upstream. A remote referrers index is a hint, as a peer's is: a swarm can withhold a signature, never forge one. Every artifact is checked against its digest and its signature (D8), and "try upstream once before a final `Rejected`" still holds.
- **Verdicts are never shared** (non-goals): each node verifies with its own policy and trust root.
- **Trust-root metadata:** TUF metadata authenticates itself and already travels between peers (D26); serving it on the link would let a swarm without internet verify. [Later, with an air-gap use case.]
- Prewarm across swarms is out of scope for v1.

### 7. Isolation

A remote swarm reaches nothing of the cluster but shared content (settled 11, 13):

- **One door, and an unprivileged one.** Only the gateway's port 7484 is exposed, and it serves `Index`, `Fetch`, `Referrers` and `Serve` only. The process behind it runs unprivileged, without any node credential, and reaches the swarm only through the gateway socket's four calls (§ 3). The mirror, the peer API, the reflector API, `/metrics` and the Kubernetes API stay out of its reach.
- **No cluster identity crosses.** Kubelet certificates, the cluster CA and node identities never authenticate to a remote swarm, nor are accepted from one (§ 1). A remote gateway never appears in the reflectors' membership or in a `Lookup` answer as a node.
- **No topology crosses.** The share index holds digests only: no image name, repository, node name, node address or holder count. Every stream is relayed, so a remote swarm never learns which node served a blob, and the response carries no header naming one.
- **No credentials cross, and none are used for a remote swarm.** A gateway serves only what its own swarm's nodes hold. It never pulls from upstream on a remote swarm's behalf, which would make it an open proxy holding the nodes' registry credentials (D17); the only upstream request is the agent's anonymous public check.
- **Nothing private crosses.** Images pulled with pull secrets, the pause image, and anything that no share rule matches or that fails the public check stay out of the share index. Kubernetes system images are shared only if a share rule names their registry, as the default `registry.k8s.io/**` does; they are public there.
- **What a swarm still learns:** which shared digests the other swarm holds, and which digests it asks for. Both concern public content only.

### 8. Limits and observability

Settings of the gateway's own config, `/etc/speculaire/gateway.toml`, all live:

- `gateway.max_uploads` caps the blob streams the gateway serves per remote swarm at once, and answers `503` beyond the cap, as D24 does [`8`].
- `gateway.max_rate` caps the bytes per second sent to one remote swarm, so a remote pull cannot fill the WAN link [`""`: no cap].
- **A remote index is untrusted** (settled 14):
  - `gateway.max_index_entries` caps the digests one remote swarm may announce [`200000`; a swarm sharing a few thousand images announces about 50 000]. `gateway.max_index_total` caps them across all swarms [`2000000`, about 128 MiB, § 10]. A swarm whose snapshot or delta would pass either cap loses its links, with an error naming it, and the agent forgets its entries. This bounds the gateway's and the reflectors' memory against a flooding swarm, and a swarm under its own cap still cannot crowd out the others past the total.
  - **Caps count per swarm, not per link.** Each of our gateways may hold a link to the same remote swarm, and each receives that swarm's index. The agent merges what arrives over every link of one swarm, so a digest counts once against the caps, whatever the number of gateways.
  - **A remote `404` says why.** `Fetch` answers `gone` for a digest its swarm held and no longer holds, and sends the removal on `Index` before that answer. Any other `404` on a digest the swarm announced is a *miss*: its index claimed a digest it does not serve. A `gone` is not a miss, so a busy swarm whose garbage collection runs ahead of its deltas is not denied.
  - **Denial follows the miss ratio.** A swarm whose misses are more than `gateway.max_miss_ratio` [`0.5`] of at least 20 fetches within `peer.deny_ttl` is denied for `peer.deny_ttl`: its entries leave the reflectors, and its links stay open for its own requests. Without this, a swarm announcing digests it does not serve would hold every pull for `federation.timeout`.

Metrics take a `swarm` label, bounded by the swarms file (settled 6). This amends D34's label rules:

- `speculaire_federation_link_up{swarm}`;
- `speculaire_federation_fetches_total{swarm,direction,result}`, where `direction` is `in` or `out`, and `result` adds `gone`, `miss`, `denied` and `over_cap` to D24's;
- `speculaire_federation_bytes_total{swarm,direction}`: with `direction="in"`, the bytes federation saved upstream, which shows what the feature is worth;
- `speculaire_federation_index_entries{swarm}`;
- `speculaire_federation_public_checks_total{result}`;
- `speculaire_federation_certificate_expiry_seconds`.

Logs: a request for a digest outside the share index is a warning naming the swarm and the digest, so a swarm probing for private digests shows up.

Alerts, for `docs/operations.md`:

| Alert | Meaning |
|---|---|
| `speculaire_federation_link_up == 0` for 10 min | A swarm is unreachable: its pulls fall through to upstream |
| A link dropped for a cap (log, and `result="over_cap"` rising) | A swarm announces more than `gateway.max_index_entries`, or the total passed `gateway.max_index_total` |
| `result="denied"` rising | A swarm was denied for its miss ratio, or for a wrong digest (D52) |
| `speculaire_federation_certificate_expiry_seconds` under 14 days | Reissue the gateway certificate with `federation issue` (phase 2) |
| `speculaire_federation_public_checks_total{result="private"}` rising | A share rule matches private images, or images retagged under a public name: narrow the rule, or look for the retag |

Fuzz targets (AGENTS.md): the swarms file, `gateway.toml`, and every message of the link (`Hello`, the `Index` snapshot and deltas, `Fetch`, `Referrers` answers, `Serve`) and of the gateway socket. They parse data from outside the cluster, or from the unprivileged side.

### 9. Phase 1: plain HTTP

Phase 1 tests the protocol, the share index and the pull flow without the PKI of § 1:

- The links are gRPC over plain HTTP/2 (h2c), only when the swarms file names `transport = "http"` for that swarm. The gateway warns at startup for each such swarm.
- The gateway accepts plain HTTP only while at least one swarm is `http`. It then accepts it only from the addresses the `address` entries of those swarms resolve to: this is weak, since an address can be spoofed or shared, but cheap until mTLS.
- Without identity, a client that passes that filter can read the share index and fetch from it. The share index holds only public content, so this exposes which public images the swarm holds, and costs bandwidth.
- *Withhold, never forge* still holds: every blob is hashed against its digest, so a forged answer is refused (D7).
- The test setup reaches gateways directly on the `kind` Docker network, without an ingress. An HTTP ingress would need gRPC over h2c, which ingress-nginx does not offer on its front end; phase 2's TLS passthrough has no such limit.
- Phase 2 adds § 1 and makes `transport = "mtls"` the default. `http` then stays a test mode.

### 10. State

No database (settled 16). Every federation structure is soft state: it lives in memory, and a restart rebuilds it from the agents' `Announce` streams and the links' `Index` snapshots, as D2 rebuilds the reflectors' map.

| Where | What | Structure |
|---|---|---|
| Reflector | Remote entries | D2's digest map, each digest stored once; a remote entry adds a `u64` mask of swarms, which the 64-swarm limit allows |
| Agent of a gateway node | Share index | A set built once, then swapped in whole through `ArcSwap` when images change: lookups take no lock |
| Agent of a gateway node | Public checks, misses, denials | A `HashMap` with an expiry time per entry and a periodic sweep: thousands of entries, so no eviction policy |
| Gateway | One digest set per remote swarm | Enforces the caps of § 8 and checks each delta against the snapshot |
| Other agents | Nothing new | The runtime's content store, or CRI-O's blob cache (D67), holds the content; the digests the agent holds are already in memory for its `Announce` snapshot |

- **Keyed hashing.** A remote swarm chooses the digests it announces, so it can choose colliding ones. Every map keyed by a digest uses std's randomly keyed `RandomState` or another randomly seeded hasher, never the digest's own bytes as the hash, as dedens keys its cache shards with SipHash (dedens D22).
- **Memory.** A digest set costs about 40 to 70 bytes per entry, so `gateway.max_index_total` bounds the gateway at about 128 MiB, and the reflectors' remote entries at about as much. The reflector load test (D33) gains remote entries at the total cap, and reports the RSS against the 1 GiB target.
- **The one saved cache.** The public-check cache is saved like the verdicts, in `/run/speculaire` with a format version and a checksum, and discarded on any mismatch (D31). A restart then does not send thousands of anonymous `HEAD`s upstream at once. It is cleared at reboot, when the checks are cheap to redo.
- **Standard nodes need no new state.** `Lookup` stays one hedged LAN round trip to a reflector (D2: p99 under 500 µs on the server side), and "do I hold it?" a set lookup well within M2's 5 ms for a 404.

## Trust boundaries (for `docs/security.md`)

These describe phase 2; § 9 states what phase 1 gives up.

- Remote swarms are authenticated by a pinned federation CA, never by a cluster CA. Only gateways hold federation keys, and the CA key stays offline.
- The process facing remote swarms runs unprivileged, with no node credential, and reaches its swarm only through four calls on the gateway socket. The agent enforces the share index on each of them.
- Remote swarms are untrusted for integrity, *withhold, never forge*, for blobs and for artifacts. They are also untrusted for availability: their index is capped, and a swarm announcing digests it does not serve is denied.
- A swarm serves remote swarms only its share index: images under a share rule whose exact digest passes the anonymous public check, and their artifacts. No private repository is shared.
- A request discloses only the digest asked for, and only to a swarm whose index lists it. Reflectors learn the image names of their own nodes. A remote swarm learns no name, node or credential (§ 7).
- The ingress and port 7484 are a new exposure. They accept only certificates from the CAs the swarms file pins.

## Rejected

- **A hub or registry in the middle** (Harbor replication, a pull-through cache per region): it adds a stateful service. A link between two swarms needs no third party.
- **libp2p or a DHT across swarms:** D1 already rejected them inside a swarm, and the swarms are few and named by hand.
- **Sharing private repositories** (settled 13), by per-swarm grants or by forwarding the requester's registry token as proof of access. A grant would hand the images to every workload of the other swarm, without pull secrets; a token would hand an upstream credential to another cluster.
- **The gateway inside the agent:** the root process holding the kubelet certificate would parse input from other clusters (settled 1).
- **A public check per repository:** a retag under a public name would pass it (§ 4).
- **Direct node-to-node fetches across swarms:** they need routable node networks between clusters, and would expose node identities and addresses (§ 7).
- **Serving by content labels alone:** containerd drops them on popular layers (§ 4).
- **A database for federation state** (settled 16):
  - CockroachDB is a distributed SQL server with Raft consensus and durable storage, the opposite of soft state, and its "CockroachDB Software License" is proprietary;
  - an embedded store (redb, fjall, RocksDB, SQLite, LMDB) writes to disk entries that a restart makes stale, since every link resends its snapshot.

## Milestone sketch (once scheduled)

Depends on M3 (reflector, peer API), M4 (artifact store, upstream access through the registry config) and M5 (walking the runtime's image store, D21); phase 2 also on M8 (the gateway behind an ingress as a pod).

Test setup: three kind clusters, A, B and C, on the shared `kind` Docker network, two nodes each: the control plane is the reflector, the worker the gateway node. That is six node containers and a `registry:2`, which fits a 4-CPU CI runner where three-node clusters would not.

**Phase 1 (plain HTTP):**

- Swarm B pulls an image swarm A holds from `docker.io`, with zero upstream blob GETs from B (the `registry:2` access log as the oracle, as in M3).
- B verifies a signed image A holds with A's signature and attestations, with no upstream referrers request from B. With A withholding the signature, B finds it upstream.
- B asking for a digest of a private layer A holds gets a 404, and A logs a warning naming B.
- A share rule matching a private Docker Hub repository keeps its images out of the share index, and logs the failed public check. So does a private image retagged on a node of A under a public name.
- C pulls from B an image B got from A when B's share rules match it, and gets nothing from B when they do not.
- From B, A's port 7484 answers only the federation services: the share index holds no name or node, and no response names a node of A.
- The gateway process runs without capability, cannot read the kubelet certificate, and `systemd-analyze security` lists its settings, as for the agent's unit (D53).
- `federation.gateway = true` on a reflector stops startup.
- A swarm announcing more than `gateway.max_index_entries` digests loses its link, and the reflectors drop its entries; so does a swarm whose announcement would pass `gateway.max_index_total`, while the swarms already linked keep theirs.
- `just load` with remote entries at `gateway.max_index_total` keeps a reflector within D33's targets, and reports the gateway's RSS.
- After the agent of a gateway node restarts, the public checks it saved are reused: no `HEAD` upstream for an image checked before the restart.
- A swarm that answers `404` for most digests it announced is denied once its miss ratio passes `gateway.max_miss_ratio`, and pulls then fall through without waiting `federation.timeout`.
- A swarm whose nodes garbage-collect shared images during a pull run answers `gone`, sends the removals first, and is not denied.
- With two gateways in B, each linked to A, A's digests count once against B's caps.
- On CRI-O, an image whose layers A holds all but one is pulled whole through B's mirror: the missing layer comes from upstream through B's agent, and lands in its blob cache.
- `speculaire_federation_bytes_total{direction="in"}` equals the blob bytes B did not fetch upstream, against the `registry:2` access log.
- A swarm sending a wrong digest is denied for `peer.deny_ttl`. One stalled by `tc netem` is left after `peer.stall_timeout`, and the transfer resumes at its offset.
- With A behind NAT (no `address` in B's file), B still fetches from A.
- A gateway at the previous protocol version links to one at the current version.
- Plain HTTP from an address no `http` swarm resolves to is refused.
- Every fuzz target of § 8 runs in the nightly `fuzz` workflow.

**Phase 2 (federation CA, ingress-nginx in passthrough mode):**

- B links to A through A's DNS name and ingress, and the phase 1 criteria pass again over mTLS.
- A gateway certificate from another CA, a kubelet certificate, an expired gateway certificate, or a swarm missing from the other side's file: the link is refused, and pulls fall through to upstream within `federation.timeout`.
