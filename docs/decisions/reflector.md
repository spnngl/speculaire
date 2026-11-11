# Decisions: reflector

The control-plane index of which nodes hold which digests. Index: `docs/decisions/README.md`.

## D1: Reflectors replace the DHT; no libp2p

- **Because:**
  - The reflectors hold the complete map, so a lookup is one RTT instead of O(log n).
  - The DHT has heavy re-provide churn, and rust-libp2p's kad `MemoryStore` defaults to 1024 keys.
  - A reflector outage degrades to *fall through*, never to a failed pull.
- **Revisit when:** we need clusters without a stable control plane, or multi-cluster sharing (`docs/proposals/federation.md`).

## D2: Reflector topology and protocol (amended by D33, D51)

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

## D33: Reconnects are jittered, and reflector scale is load-tested (amends D2)

- **Decision:**
  - After a stream drops, the agent waits a random delay between 0 and 5 s, then retries with exponential backoff and full jitter, from 1 s up to 60 s.
  - `speculaire-loadgen` (crate `crates/loadgen`, `publish = false`, never packaged) simulates agents. Each simulated agent has its own node certificate from a test CA, made with `rcgen`, and sends `Hello`, a `Snapshot`, `Delta`s and `Lookup`s.
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
