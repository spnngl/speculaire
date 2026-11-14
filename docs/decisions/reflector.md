# Decisions: reflector

The control-plane index of which nodes hold which digests. Index: `docs/decisions/README.md`.

## D1: Reflectors replace the DHT; no libp2p

- **Because:**
  - The reflectors hold the complete map, so a lookup is one RTT instead of O(log n).
  - The DHT has heavy re-provide churn, and rust-libp2p's kad `MemoryStore` defaults to 1024 keys.
  - A reflector outage degrades to *fall through*, never to a failed pull.
- **Revisit when:** we need clusters without a stable control plane, or multi-cluster sharing (`docs/proposals/federation.md`).

## D2: Reflector topology and protocol (amended by D33, D51, D97, D98)

- **Decision:**
  - **Placement:** reflectors are the agents on the control-plane nodes, with `role = "reflector"`. Every agent knows one URL, `reflector.url`: a load balancer in front of the control-plane nodes. It must be L4 TCP passthrough, because mTLS ends at the reflector.
  - **Membership:** each reflector has the same `reflector.members` list, of node names and addresses, in its config. An agent calls `Members` through the load balancer and checks that the answering certificate's node identity is in the returned list. It then talks to each member **directly**. It refreshes `Members` every 60 s and whenever a stream drops, and keeps the last list so it survives a load-balancer outage.
  - **Announce:** one tonic bidi stream per member. The agent sends `Hello{protocol_version, node identity, peer address}` and a `Snapshot`, then `Delta{seq}`. The reflector sends `Resync` and `Prewarm` (D51).
  - **Lookup:** sent to any member and hedged to a second.
  - **Versions:** `Hello` carries `protocol_version`. A reflector accepts its own version and the previous one, and protobuf changes are additive only, so mixed versions work during a rolling upgrade.
- **Because:**
  - A stream through the load balancer would land on one reflector only, leaving the others with partial maps. So the load balancer is used only for discovery.
  - Soft state means no persistence and no reflector-to-reflector protocol. Stream EOF is the liveness signal, so no SWIM is needed.
  - Memory is about 20M (digest, node) pairs for 10k nodes × 2k blobs, stored as interned digests → `roaring` bitmaps.
  - kubeadm clusters with several control-plane nodes already put a load balancer in front of them.
- **Revisit when:**
  - Reflector RSS exceeds 1 GiB.
  - Keeping `reflector.members` in sync by hand becomes painful. Then derive it from control-plane `Node` objects.

## D33: Reconnects are jittered, and reflector scale is load-tested (amends D2; amended by D98)

- **Decision:**
  - After a stream drops, the agent waits a random delay between 0 and 5 s, then retries with exponential backoff and full jitter, from 1 s up to 60 s.
  - `speculaire-loadgen` (crate `apps/loadgen` (D62), `publish = false`, never packaged) simulates agents. Each simulated agent has its own node certificate from a test CA, made with `rcgen`, and sends `Hello`, a `Snapshot`, `Delta`s and `Lookup`s.
  - **Targets** for one reflector with 10k simulated agents × 2k blobs (20M pairs), under 5k lookups/s and 1k deltas/s:
    - RSS, read by the load generator from `/proc/<pid>/status` (speculaire exports no process metrics, D34), at most 1 GiB. The goal is at most 256 MiB: the run reports it, but missing it does not fail the run;
    - server-side lookup p99 at most 500 µs;
    - every agent resynced within 60 s after the reflector restarts.
  - `just load` runs the test. The nightly `load` workflow (D27) runs it on amd64 and arm64, and a missed target fails the run.
- **Because:**
  - D2's memory figure is an estimate, and its revisit trigger (RSS above 1 GiB) needs a measurement.
  - Without jitter, 10k agents reconnect in the same second after a reflector restart, and send 10k snapshots at once.
  - The user set the 500 µs and 256 MiB figures and accepted the others.
- **Revisit when:** a target fails. Then revisit D2.

## D51: Every member picks the same prewarm seeds (amends D2)

- **Decision:**
  - For each image of `prewarm.images`, every member picks the same seeds: the `prewarm.seeds` agents (default 2, live) with the highest rendezvous hash of (image reference, node identity), among the agents streaming to it.
  - Each member sends `Prewarm` to the seeds first, then to the other agents once the seeds have announced the image's blobs.
  - An agent drops a `Prewarm` for an image it is already pulling or holds, so the copy from each other member is a no-op.
- **Because:**
  - Members share no protocol (D2), so they cannot agree by talking. Every agent streams to every member, so all members hash the same inputs and choose the same seeds without a message.
  - While an agent reconnects, members can disagree for a moment; the cost is one extra seed pulling from upstream.
- **Revisit when:** benchmarks show extra upstream pulls during prewarm.

## D97: The reflector's wire, index and limits (amends D2, D27, D76)

- **Decision:**
  - **Wire:** protobuf package `speculaire.reflect.v1`, in `crates/reflect/proto/`. `protocol_version` is an integer, 1 for now. Digests travel as their text, and the reflector parses each one as an OCI digest (sha256, sha384 or sha512).
  - **Stream:** the first message is `Hello`, and only the first. Its node must be the TLS peer's, and its peer address an IP literal with a port. A `Snapshot` comes in chunks of at most 10k digests (`SNAPSHOT_CHUNK`); the chunk marked `last` replaces what the reflector held for the agent and names the `seq` of the next `Delta`. A `Delta` out of sequence gets one `Resync`, and later deltas are ignored until the next snapshot ends. A node's new stream takes its entry over, and the old one ends with `ABORTED`. A stream's end withdraws everything it announced.
  - **Lookup:** unary, hedged by the agent to a second member. It answers at most 8 holders (`LOOKUP_PEERS`), from a random position among them, never the agent asking.
  - **Limits**, each refusing the stream and counted in `speculaire_reflector_announce_rejected_total{reason}`: a TLS handshake longer than 5 s (closed, not counted: no stream exists yet), a message over 4 MiB (`size`), more than 100k digests for one node (`digests`), a peer address that is not `ip:port` (`address`), a `Hello` naming another node (`identity`), a version outside the reflector's and the previous one (`version`), anything else unparsable (`malformed`).
  - **Index:** one lock over an interned digest table, one `roaring` bitmap of node slots per digest and one of digest ids per node. Its lock comes from `crate::sync`, Shuttle's under `--cfg shuttle`, so Shuttle explores concurrent snapshots, deltas and stream ends: `just shuttle` runs 2000 random schedules, and so does the `shuttle` job of `deep.yml`, informational like `careful` (D76).
  - **Server:** handshakes run in their own tasks, so a stalled one delays no other. HTTP/2 pings every 30 s, and a connection silent 10 s after one is closed. A stopping reflector ends every stream with `UNAVAILABLE` (D39).
- **Because:**
  - 10k sha512 digests encode to about 1.4 MB, so a chunk stays well under 4 MiB, and a whole snapshot of 2k blobs is one message.
  - 100k digests is 50 times the 2k blobs a node holds in D2's estimate: no honest node reaches it, and one bad node holds at most 100k pairs.
  - A random start spreads the load of a popular blob over its holders; 8 is enough for the fetcher to skip slow or failed peers without a second lookup.
  - A unary call is cancelled and hedged cleanly, which a stream is not.
  - An IP literal needs no DNS on the fetching side and cannot point at a name the node does not own.
  - Withdrawing on a stream's end is D2's liveness signal; taking over on a new stream lets a restarted agent replace its entry before the old connection's keepalive times out.
- **Revisit when:** D33's load test misses a target, or a node legitimately holds more than 100k digests.


## D98: The agent's reflector client (amends D2, D33; amended by D102)

- **Decision:**
  - **Members:** the agent dials `reflector.url` itself, accepting any node of the cluster (`Credentials::client_any`), and reads the node of the certificate that answered. A `Members` answer whose node is not in its own list is ignored, like a failed call: the agent keeps the last list and retries with D33's backoff. The channel is never dialled again behind the agent's back, so every answer comes from the checked connection.
  - **Streams:** one per member, dialled at the member's address and expecting the member's node. Each stream starts with `Hello` and a whole `Snapshot`; so does the answer to a `Resync`, and so does a stream that fell more than 1024 changes behind. Changes made while no stream is up are dropped: the next stream's snapshot carries them. Deltas send removals before additions.
  - **Peer address:** `peer.address`, else the local IP of the first stream that opens, on port 7481 (D36). It stays the same for the agent's life.
  - **Reconnects:** a stream that ran 5 s or more and ended is a drop: the agent refreshes `Members` and waits D33's 0 to 5 s, and its backoff starts again. A stream that ended sooner, or never opened, is a failed attempt: D33's backoff, 1 s doubling to 60 s with full jitter. `speculaire_reflector_reconnects_total{member}` counts every retry. A failure logs at `info` until the member, or the load balancer, has failed for 60 s, then at `warn`.
  - **Lookup:** to a random member whose stream is up, hedged to a second after 20 ms; the first answer wins, and a failed first call goes to the second at once. Each call gives up after 5 s. With no stream up, the lookup fails and the fetcher goes upstream.
  - **Stop:** the agent closes every stream at shutdown, D39's step 3, so each reflector withdraws it at once.
- **Because:**
  - tonic hides the peer certificate and redials on its own; dialling the TCP and TLS by hand is the only way to know which reflector answered `Members` (D16).
  - A snapshot replaces what the reflector held, so changes queued while disconnected would only be sent again.
  - D33's 0 to 5 s delay is for a reflector restart; a reflector that refuses each stream at once would otherwise get a retry every 2.5 s from each agent.
  - A rollout restarts every reflector, and an agent starts before its own: failures shorter than that are expected, and D37's default `warn` level is for what needs the operator.
  - D33's target puts the server's lookup p99 at 500 µs; with a LAN round trip, 20 ms is far past the normal answer, so the hedge fires only for a slow or gone member.
- **Revisit when:** D33's load test shows snapshots at reconnect dominate, or the agents' `speculaire_lookup_seconds` p99 exceeds 20 ms without a member down.
