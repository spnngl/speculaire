# Decisions: reflector

The control-plane index of which nodes hold which digests. Index: `docs/decisions/README.md`.

## D1: Reflectors replace the DHT; no libp2p

- **Because:**
  - The reflectors hold the complete map, so a lookup is one RTT instead of O(log n).
  - The DHT has heavy re-provide churn, and rust-libp2p's kad `MemoryStore` defaults to 1024 keys.
  - A reflector outage degrades to *fall through*, never to a failed pull.
- **Revisit when:** we need clusters without a stable control plane, or multi-cluster sharing (`docs/proposals/federation.md`).

## D2: Reflector topology and protocol (amended by D33, D51, D97, D98, D105, D184)

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

## D33: Reconnects are jittered, and reflector scale is load-tested (amends D2; amended by D98, D104)

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

## D51: Every member picks the same prewarm seeds (amends D2; amended by D181, D185, D186, D188)

- **Decision:**
  - For each image of `prewarm.images`, every member picks the same seeds: the `prewarm.seeds` agents (default 2, live) with the highest rendezvous hash of (image reference, node identity), among the agents streaming to it.
  - Each member sends `Prewarm` to the seeds first, then to the other agents once the seeds have announced the image's blobs.
  - An agent drops a `Prewarm` for an image it is already pulling or holds, so the copy from each other member is a no-op.
- **Because:**
  - Members share no protocol (D2), so they cannot agree by talking. Every agent streams to every member, so all members hash the same inputs and choose the same seeds without a message.
  - While an agent reconnects, members can disagree for a moment; the cost is one extra seed pulling from upstream.
- **Revisit when:** benchmarks show extra upstream pulls during prewarm.

## D97: The reflector's wire, index and limits (amends D2, D27, D76; amended by D104, D105, D184)

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


## D98: The agent's reflector client (amends D2, D33; amended by D102, D103, D105, D132)

- **Decision:**
  - **Members:** the agent dials `reflector.url` itself, accepting any node of the cluster (`Credentials::client_any`), and reads the node of the certificate that answered. A `Members` answer whose node is not in its own list is ignored, like a failed call: the agent keeps the last list and retries with D33's backoff. The channel is never dialled again behind the agent's back, so every answer comes from the checked connection.
  - **Streams:** one per member, dialled at the member's address and expecting the member's node. Each stream starts with `Hello` and a whole `Snapshot`; so does the answer to a `Resync`, and so does a stream that fell more than 1024 changes behind. Changes made while no stream is up are dropped: the next stream's snapshot carries them. Deltas send removals before additions.
  - **Peer address:** `peer.address`, else the local IP of the first stream that opens, on port 7481 (D36). It stays the same for the agent's life.
  - **Reconnects:** a stream that ran 5 s or more and ended is a drop: the agent refreshes `Members` and waits D33's 0 to 5 s, and its backoff starts again. So is a stream its reflector ended because it stops, however short (D132). A stream that ended sooner, or never opened, is a failed attempt: D33's backoff, 1 s doubling to 60 s with full jitter. `speculaire_reflector_reconnects_total{member}` counts every retry. A failure logs at `info` until the member, or the load balancer, has failed for 60 s, then at `warn`.
  - **Lookup:** to a random member whose stream is up, hedged to a second after 20 ms; the first answer wins, and a failed first call goes to the second at once. Each call gives up after 5 s. With no stream up, the lookup fails and the fetcher goes upstream.
  - **Stop:** the agent closes every stream at shutdown, D39's step 3, so each reflector withdraws it at once.
- **Because:**
  - tonic hides the peer certificate and redials on its own; dialling the TCP and TLS by hand is the only way to know which reflector answered `Members` (D16).
  - A snapshot replaces what the reflector held, so changes queued while disconnected would only be sent again.
  - D33's 0 to 5 s delay is for a reflector restart; a reflector that refuses each stream at once would otherwise get a retry every 2.5 s from each agent.
  - A rollout restarts every reflector, and an agent starts before its own: failures shorter than that are expected, and D37's default `warn` level is for what needs the operator.
  - D33's target puts the server's lookup p99 at 500 µs; with a LAN round trip, 20 ms is far past the normal answer, so the hedge fires only for a slow or gone member.
- **Revisit when:** D33's load test shows snapshots at reconnect dominate, or the agents' `speculaire_lookup_seconds` p99 exceeds 20 ms without a member down.

## D103: Outages fall through, counted, and a stopping agent sends what it started (amends D39, D98, D100, D102; amended by D177)

- **Decision:**
  - **Counted:** a lookup made while no stream is up asks nobody and counts in `speculaire_lookup_seconds` with `result="no_reflector"`; D102 counted none.
  - **Restart:** a restarted reflector sends no `Resync`: its index starts empty, and each agent's next stream opens with a whole snapshot (D98).
  - **Stop:** the client stops while it waits on the load balancer, instead of after the call's timeouts.
  - **Drain (D39 step 4):** the mirror's and the peer API's listeners close, and each connection is shut down gracefully: an idle one closes at once, a busy one once hyper has flushed its response and closed TLS. The drain waits for the connections, up to `shutdown.drain_timeout`, where it waited for the peer bodies.
  - **Alerts:** `docs/operations.md` § Metrics to alert on adds `no_reflector` lookups, and a share of `miss` that rises while every stream is up.
- **Because:**
  - In an outage every pull falls through. Without the count, the agent's metrics show only the fall-throughs, not their cause; counting it as `error` would mix a reflector that failed with none to ask.
  - A load balancer that hangs held the stop for 5 s to dial and 5 s to call, the half of `TimeoutStopSec` that D39 leaves after the drain.
  - hyper drops a body once it has buffered its end, before it has written it: a drain that waited for bodies let the agent exit with the end of a blob unsent, and the peer's pull went upstream.
- **Measured (M3 step 06):** `e2e/tests/outage.rs` passes on containerd 2.4 and CRI-O 1.37 in 33 s. After a reflector restarts, its lookups find every holder 0.6 to 5.3 s after it is ready: the agents' 0 to 5 s wait after a drop (D33). An agent started with both reflectors down opens its peer API 0.6 to 3.9 s after one is ready, and 9.4 to 9.5 s after its certificate appears (`config.poll_interval`, 10 s). Stopping an agent that serves a 16 MiB layer at 32 Mbit/s takes it out of lookups in 160 to 350 ms, and the unit stops in 3.1 to 3.8 s while the peer's pull completes from it. Before the drain change, that pull went upstream.
- **Revisit when:** a reflector keeps its index across restarts.

## D104: The load scenario is a library under `speculaire-loadgen`, and the reflector bounds what each agent costs it (amends D27, D33, D97; amended by D105, D116)

- **Decision:**
  - **Place:** `apps/loadgen`, the package `speculaire-loadgen`, parses arguments and prints the report (D62). The library `crates/load`, `speculaire-load`, holds the scenario. It makes a test CA with `speculaire-pki`'s `testing` feature, starts the reflector as a child `speculaire agent` with `role = "reflector"` on a fake containerd, and runs one `crates/reflect` client per simulated agent, each with its own node certificate.
  - **Scenario (D33):** 10k agents each hold 2k digests drawn from a pool of 200k, so a digest has about 100 holders. They connect evenly over 30 s. Once the reflector holds every pair, 10 s of warm-up, then a measured minute of 5k lookups/s, each of a random digest by a random agent, and 1k deltas/s, one per digest removed or added. Then the reflector gets SIGTERM and starts again, and the agents' own reconnects refill it.
  - **Measures:** RSS is the largest `VmHWM` in `/proc/<pid>/status` over the reflector's two runs. The lookup p99 is the upper bound of its bucket in `speculaire_reflector_lookup_seconds`, a native histogram scraped as protobuf before and after the measured minute. Resync runs from the restart until the gauges `speculaire_reflector_agents` and `speculaire_reflector_pairs` are back at 10k and 20M. Lookups and deltas must each reach 95 % of their rate. A missed target or rate exits 1, unless `--measure-only`. The Markdown report also gives the CPU count and the open-files limit.
  - **Running:** `just load` runs both musl binaries in the build image, with the open-files limit at 1048576 and local ports from 1024 to 65535. Its arguments go to `speculaire-loadgen`. `load.yml` runs it nightly and on dispatch, whose `args` input it passes on, on `ubuntu-26.04` and `ubuntu-26.04-arm`, and puts the report in the job summary.
  - **What an agent costs the reflector:** a `Snapshot` chunk holds at most 25 digests (`SNAPSHOT_CHUNK`, D97), about 1.8 KB of sha256 text. The API's codec, `crates/reflect/src/codec.rs`, sends each message on its own, from a 1 KiB buffer, and receives into 4 KiB, which two such chunks fit. An agent may send 8 KiB on its stream, and HTTP/2's default of 64 KiB on its connection, before the reflector reads them. The index keys a digest by its bytes, inline (`Key`), made outside its lock; a snapshot costs one map access a digest. Until its last chunk, a snapshot is a bitmap of digest numbers in the agent's entry (`Index::stage`), which the last chunk swaps in (`Index::commit`).
  - **Restart:** a stopping reflector empties its index at once (`Index::close`), before its streams end.
  - **Micro-benchmarks:** divan, in `benches/micro.rs` of `crates/reflect` (index lookup in D33's fleet) and of `crates/mirror` (blob hashing, D7). A `bench` feature exposes the private index and hash to them. `just bench-micro` runs them, never CI.
  - **Valgrind:** `just valgrind` runs the glibc build of the reflector under 100 agents, in memcheck, where a definite leak fails it, then in DHAT. `deep`'s `valgrind` job runs it on each pull request, informational like `careful` (D76), and keeps DHAT's profiles.
  - **Mutants (D74):** cargo-mutants skips `apps/loadgen/`, flags over `run` that the `load` workflow runs, and `crates/reflect/src/bench.rs`, benchmark support. `.cargo/mutants.toml` gives each generator change it skips its reason.
- **Because:**
  - D62 leaves binaries only argument parsing. As a library, the scenario also runs small in `apps/speculaire/tests/load.rs`, against the built binary, in every `just check` on Linux.
  - A separate process is what `/proc` measures, with the agent's own config, TLS and metrics; in the generator's process, the agents would count in its RSS.
  - The rate floor: a generator short of CPU sends fewer lookups, and a less loaded reflector answers faster.
  - tonic keeps each stream's receive buffer at its largest message (tonic 0.14.9 `src/codec/decode.rs:223`). With 10k-digest chunks, a 2k-blob snapshot is one 150 KB message whose buffer stays for the stream's life. tonic's encoder also batches ready messages up to 32 KiB (`src/codec/encode.rs:144`), so chunks arrived in full 16 KiB frames and DHAT found each stream's buffer at 64 KiB. With 100-digest chunks, an 8 KiB buffer still doubled to 16 KiB on most streams.
  - hyper's 1 MiB windows (hyper 1.12.0 `src/proto/h2/server.rs:37`) let every reconnecting agent park its whole snapshot in the reflector while the index is busy. 8 KiB is four chunks in flight.
  - After a restart, all 10k agents send their snapshots at once. Staged as sets of keys, 270 KB each, they took the reflector out of 8 GB.
  - A stopping reflector that withdrew each agent's 2k digests as its stream ended took 16.5 s to exit. The agents it refused meanwhile climbed their failure backoff (D98), and the last one was back 72 s after the restart. Emptied at once, the index lets it exit in 0.3 s, and every agent is back within 17 s.
  - A `Digest` is two heap strings, which each map access reads. Filling 1k agents × 2k digests held the index's lock 1.1 s on an M-series core with `Digest` keys and two accesses a digest, 0.32 s with `Key` and one.
  - Divan over criterion, and DHAT over the `dhat` crate: `docs/research/checkers.md`. Valgrind cannot follow mimalloc in the static musl binary (D46).
- **Measured (M3 step 07):** on GitHub's runners, 4 CPUs, the reflector's peak RSS still misses D33's 1 GiB; every other target is met. On 2026-11-15 the user chose to replace gRPC between agents and reflectors with our own framing, length-prefixed protobuf over the rustls connection, projected at a 593–627 MiB peak (`docs/research/reflector-transport.md`). D105 makes that change and turns the nightly run back on; its run 43694940333 meets every target, at a 494–496 MiB peak.
  - With D46's allocator, runs 43654431900 and 43656035441 of the throwaway branch `m3/07-load-try`: peak 1147–1181 MiB on x86_64 and aarch64, 1083–1104 MiB at the end of the steady phase, lookup p99 28–56 µs, resync 31.8–40.4 s, no failed lookup.
  - With mimalloc's padding off (`-DMI_PADDING=0`), runs 43658675208 and 43659875449: peak 1036 and 1051 MiB on x86_64, 963 and 973 MiB on aarch64, 924–944 MiB at the end of the steady phase, resync 36.9–50.9 s.
  - The peak is the restarted reflector's. Its 10k agents reconnect within 28 s while it fills, on the 4 CPUs the generator also uses, and it holds 40–110 MB more than in the steady phase.
  - Locally, Docker on an M-series Mac with 4 CPUs, aarch64: peak 950–1007 MiB with D46's allocator, 815 MiB with padding off, 842 MiB with mimalloc's non-secure build.
  - DHAT with 1k agents puts the index at about 170 MB for 10k agents, and each connection at about 50 KiB of h2, tonic and rustls buffers. mimalloc's padding, on from `MI_SECURE` 3 (mimalloc v3 `include/mimalloc/types.h:96`), moves each of these power-of-two buffers to the next size class.
  - `just valgrind`, locally on aarch64: memcheck finds no error and no definite leak in either run.
- **Revisit when:** a target is missed. In DHAT's profile, each agent's connection costs the reflector about 50 KiB of h2, tonic and rustls buffers, which comes before the index (D2). 24 KiB of it are h2's write buffer and its 8 KiB read buffer, which no setting changes (h2 0.4.20 `src/codec/framed_write.rs:67`).

## D105: Agents and reflectors speak length-prefixed protobuf over TLS, not gRPC (amends D2, D13, D97, D98, D104; amended by D117, D183)

- **Decision:**
  - **Wire:** a TLS connection with the ALPN protocol `speculaire-reflect/1` (`frame::ALPN`). Each frame is a 4-byte big-endian length, then that many bytes of one protobuf message: an `AgentMessage` from the agent, a `ReflectorMessage` from the reflector (`crates/reflect/proto/`). There is no gRPC service; `protocol_version` stays 1.
  - **Connections:** `Members` is a connection of its own through the load balancer, closed after the answer. Each member gets one connection per agent, the `Announce` stream: `Hello`, snapshots, deltas, lookups and pings, with `Resync` and `Prewarm` back.
  - **Order:** the reflector handles one frame at a time and writes each reply before it reads the next frame. A `LookupRequest` carries a number that its `LookupResponse` repeats, so the agent finds the lookup an answer is for among those it sent between announcements. `Lookup` and `Members` need no `Hello` first.
  - **Size:** the reader checks a frame's length against 4 MiB before it allocates, then reads it into the connection's buffer (D117). The writer encodes into a buffer of the message's length and refuses one over the limit.
  - **Liveness:** the agent sends `Ping` every 30 s and the reflector answers `Pong`. Either side closes a connection silent for 40 s.
  - **Refusals:** `Refused{reason, message}`, then TLS `close_notify`. Its `Reason` is D97's limit (`identity`, `version`, `size`, `digests`, `address`, `malformed`), counted as before, or `superseded`, sent to the older connection of a node that opened another, or `stopping`. A frame that does not decode is `malformed`, and so is a lookup of an unparsable digest. A stopping reflector refuses each connection with `stopping` and waits for each, at most 1 s for the farewell (D103).
  - **Crate:** `crates/reflect` reads and writes frames in `frame.rs`, and compiles the messages with `prost-build`. D104's codec and HTTP/2 windows go with gRPC; its 25-digest chunks stay. tonic stays only for `containerd-client` (D13).
- **Because:**
  - Over gRPC, each connection held 54.8 KB of the reflector's heap, 9.2 KB over a length-prefixed prototype (`docs/research/reflector-transport.md`); at 10k agents, that is the 1 GiB peak D104 missed. Most of it is h2's buffers, which no setting changes (D104).
  - D98 dials TCP and TLS by hand already, so tonic's channel brought only HTTP/2.
  - A lookup waits behind at most one frame's handling, a snapshot chunk of 25 digests (D104). Answering in order needs no writer task or queue per connection; numbered lookups let the agent keep sending them meanwhile.
  - TCP's window bounds what an agent sends before the reflector reads it, as HTTP/2's 8 KiB stream window did.
  - A ping every 30 s and a 40 s silence keep D97's HTTP/2 timings: a gone agent is withdrawn as soon as before.
  - A client of another protocol fails at the TLS handshake on ALPN, not on a garbled frame.
  - No release carries the gRPC API, so this drops no protocol version (D40), and there is no period with both.
- **Measured (M3 step 07):** run 43694940333 of `load.yml`, on GitHub's runners, 4 CPUs, meets every target of D33 on x86_64 and aarch64, with D46's allocator:
  - peak RSS 496 and 494 MiB, against 1147–1181 MiB over gRPC (D104), and 490 and 493 MiB at the end of the steady phase;
  - lookup p99 72.6 and 111.9 µs, resync 45.1 and 43.6 s, 5000 lookups and 1000 deltas a second, no failed lookup;
  - the goal of 256 MiB is still missed: the index holds about 170 MB of it (D104).
- **Revisit when:** a target of D33 is missed, or the reflector sends agents enough unasked messages (D51's `Prewarm`) that they need a queue of their own.

## D117: A frame reader keeps one buffer per connection, up to 1 KiB (amends D105)

- **Decision:** `frame::Reader`, on both ends, reads each frame's body into one buffer, kept between frames and grown to the largest frame read. After a frame over 1 KiB (`frame::KEEP`), it frees the buffer instead.
- **Because:**
  - D107 has a reader keep one read buffer for its connection. D105 allocated each frame's body and dropped it after decoding.
  - The steady frames fit in 1 KiB and reuse the buffer: a lookup, its answer with D97's 8 peers, a delta of a few digests.
  - A snapshot chunk of 25 digests (D104), 1.8 KB, comes only at connect and resync. Kept, it would pin about 2 KiB on each of 10k idle connections; past 1 KiB it is freed, so a connection holds what D105's did. A 4 MiB frame cannot stay pinned either.
- **Measured:**
  - `just bench-micro`, `speculaire-reflect`'s `read` (100 lookups through one reader): 101 allocations and 7.2 KB, against 200 and 14.8 KB; median 3.2 µs, against 4.5 µs.
  - `just load` (D104), locally, 10 CPUs, two runs each: peak RSS 466 and 464 MiB, against 464 and 465 MiB; lookup p99 145 and 56 µs, against 188 and 158 µs. A 4 KiB `KEEP` that kept snapshot chunks peaked at 484 and 485 MiB.
- **Revisit when:** a steady frame grows past 1 KiB, or snapshot chunks grow.

## D132: A stream its reflector ends because it stops is a drop, however short (amends D98)

- **Decision:** a stream that opened and ended with `Refused` and reason `STOPPING` (D105) is a drop whatever it ran: the agent refreshes `Members`, waits D33''s 0 to 5 s, and its backoff starts again. A `STOPPING` refusal of a stream that never opened stays a failed attempt.
- **Because:**
  - A reflector sends `STOPPING` only at its own stop (`server.rs` `stopping()`), and a restart is what D33''s 0 to 5 s is for (D98).
  - Counted as failed attempts, the short streams of a reflector restarted every few seconds doubled the backoff towards 60 s, and only a stream that ran 5 s reset it. The sparse retries then fell into restarts: on PR #181''s run 44007778956 (CRI-O 1.37), the control plane retried the worker''s reflector after 9, 18 and 55 s and warned "no stream to the reflector", though that reflector was up most of the time.
  - A reflector that refuses every new stream while it stops still gets D33''s backoff, so the drop cannot spin.
- **Measured:** the relay suite, which restarts the worker''s agent several times a test, 4 runs each on a local CRI-O 1.36 cluster. Before: the control plane''s retries towards the worker reached 58 s, its stream was up 4 to 38 % of each run, and the longest stretch without one was 19 to 66 s. After: retries stayed within 5.3 s except while that reflector was down for 21 s or more, the stream was up 34 to 60 %, and the longest stretch without one was 5 to 41 s.
- **Revisit when:** a reflector sends `STOPPING` for anything other than its own stop.

## D181: A seed's rank is a SHA-256 of the image reference as written and the node identity (amends D51)

- **Decision:**
  - A node's rank for an image is the first 8 bytes, big-endian, of SHA-256 over `image ‖ 0x00 ‖ node identity`. The `prewarm.seeds` highest are the seeds, best first; a tie goes to the smaller node name. `speculaire_reflect::seeds` computes it, and its test pins three cases computed with `shasum`.
  - `image` is the reference exactly as `prewarm.images` writes it, once D60's parse accepts it, with no normalisation: `busybox` and `docker.io/library/busybox:latest` rank apart.
  - The protocol fixes both: changing either is a breaking change (D40).
- **Because:**
  - Members of two versions run side by side during a rolling upgrade (D2); they pick the same seeds only if they hash the same bytes the same way. std's `RandomState` is seeded per process, so it cannot.
  - aws-lc-rs is already in the build (D88). Over 10k nodes, two 8-byte ranks tie with odds near 3·10⁻¹², and the name order settles a tie anyway.
  - Normalising would put a reference parser's version into the protocol; the string as written gives every member the same bytes from the same list.
  - Neither a reference nor a node name holds a 0x00, so the separator keeps `ab`, `c` apart from `a`, `bc`.
- **Measured:** `just bench-micro`, `speculaire-reflect`'s `seed`, 2 seeds among 10k nodes, on an Apple M5: median 459 µs (46 ns a node), one allocation of 48 B, the result.
- **Revisit when:** the choice shows in a reflector's profile at a wave's start.

## D183: A reflector queues what it pushes in one outbox per stream, which drops nothing (amends D105)

- **Decision:**
  - **Outbox:** each `Announce` stream that takes pushes (D184) has one, from its `Hello` on: the latest `PrewarmList` and the images waiting for a `Prewarm`, in the order queued. A newer list replaces the waiting one, and an image queued again while it waits is kept once. With 64 images waiting (`push::LIST_CAP`), a 65th is refused to its caller with `PushError::Full`. Nothing in an outbox is ever dropped, so there is no drop metric.
  - **Handle:** `Reflector::pushes` returns `Pushes`, whose `prewarm` and `list` queue for one node's stream, or fail with `PushError::NoStream`. A node's later stream takes its pushes over, as it takes its entry over (D97).
  - **Loop:** the connection's one task waits for the agent's next frame or a queued push, the frame first when both are ready. After each wake, it writes the frame's reply, if any, then the list, then the images. A reply goes out before anything queued after its request arrived, and a request waits behind at most one outbox. Pushes do not move the 40 s silence deadline, which only the agent's frames do (D105).
  - **Check:** Shuttle explores the loop and the outbox (`server::schedules`, `just shuttle`); a lost wake deadlocks it.
- **Because:**
  - One task and no channel per connection keep D105's memory and its answers in order. Its revisit, unasked messages that need a queue, arrives with M7's pushes.
  - What a reflector pushes is bounded: one list of at most 64 images (`prewarm.images`), and a `Prewarm` of a listed image. 64 images and one list bound an outbox, and the agent only needs a member's latest list.
  - Dropping a `Prewarm` would leave the node cold with no sign of it; a caller told `Full` knows what was not queued.
- **Revisit when:** a reflector pushes anything else, or an outbox's writes show in D33's lookup p99.

## D184: Only a member pushes, to an agent of protocol version 2 (amends D2, D97; amended by D188)

- **Decision:**
  - **Version:** protocol version 2 takes `Prewarm` and `PrewarmList`. A reflector sends them only on a stream whose `Hello` says 2 or later, and still accepts version 1 (D2).
  - **Trust:** the agent takes pushes only on its `Announce` streams, each dialled to a member of the `Members` list expecting the member's node (D98). A push on the `Members` connection is ignored.
  - **Client:** `Client::spawn` takes a channel; each push, parsed into `push::Push` (an image `PullImage` would take, as containerd's CRI plugin parses it, or a list of at most 64), goes to it with the member's node, as `Pushed`. A push that does not parse is logged and dropped, and the stream stays. A full channel holds the stream, lookups' answers included, so the agent reads it at once. The agent's prewarm worker reads it (D188).
- **Because:**
  - A push makes the node pull. Only a member, a control-plane node whose certificate the agent checked (`docs/security.md`), may ask for that.
  - A version 1 agent drops a `Prewarm` and does not know `PrewarmList`. The version tells the reflector whom a push reaches, and queueing nothing for the others costs nothing.
  - Reflectors upgrade first (D40), so a reflector of version 2 meets agents of 1 and 2, and an agent of 2 never meets a reflector of 1.
- **Revisit when:** something other than a member must push, or a third protocol version drops version 1.


## D185: A wave is released in rounds, each once the one before announced the image or `prewarm.seed_timeout` passed (amends D51)

- **Decision:**
  - **Resolution:** a member resolves each `prewarm.images` entry through the *registry config* (D17), its own mirror left out, to the image's platform manifests and their layer digests. An index gives its image manifests, at most 32; a nested index is an error. The member checks each manifest's digest, and nothing else: the agents verify what they pull (D26).
  - **Announced:** an agent has announced an image once it announced every layer of one of its platform manifests. A `Hello` names no platform, so any one counts.
  - **Rounds:** a wave sends `Prewarm` to the seeds (D51, D181) first. Once every agent of the last round announced the image, or `prewarm.seed_timeout` (default `300` s, live) passed since it was sent, the member releases the next round: up to 4 agents for each agent sent the image so far, picked by D181's rank among the agents not sent it yet. With 2 seeds, rounds hold 8, 40, 200 and so on, until every agent streaming was sent it. An agent of a round whose stream closed no longer holds the round. The factor 4 is a constant, not a setting.
  - **Metrics:** `speculaire_reflector_prewarm_rounds_total{release}` counts rounds ended, `announced` or `timeout`; `speculaire_reflector_prewarm_sent_total{stage}` counts `Prewarm`s queued, `seed` or `release` (D34).
- **Because:**
  - A member knows only the image reference; layers are what agents announce (D97), and a platform manifest names the layers one node pulls.
  - A peer that holds a blob serves at most `peer.max_uploads` at once and answers `503` past it, and the pull then falls through to upstream (D102, `crates/mirror/src/fetch.rs:595`). Releasing every agent at once on 2 seeds would send most of them upstream; growing by 4 per holder keeps each holder's load near its upload limit, and reaches 10k nodes in 6 rounds.
  - The rank and the rounds depend only on the stream set and the list, so members with the same stream set send the same `Prewarm`s and an agent drops the copies (D51).
  - A silent seed or round, a node that cannot pull, would otherwise hold the wave forever.
- **Revisit when:** benchmarks show a round of 4 per holder slower than upstream, or holders refusing uploads during a wave.

## D186: A wave starts on a list change, on a moved tag, and a minute after a member starts; a late agent gets released images at once (amends D34, D51)

- **Decision:**
  - **Start:** a new `prewarm.images` entry starts its wave at once. The list a member starts with waits 60 s, so agents reconnect and resync first (D33). The wave's first resolution starts it, and its seeds are picked once some agent streams.
  - **Refresh:** a tag is resolved again every `prewarm.refresh` (default `3600` s, live), with a `HEAD` first; a tag whose platform manifests changed starts a new wave. An entry by digest is never resolved again.
  - **Failures:** a failed resolution is tried again after 10 s, doubled at each failure in a row up to 300 s; the warning log names the reference.
  - **Late agents:** once a wave sent to every agent streaming, an agent whose stream opens later gets its `Prewarm` after its `Hello`. One that opens mid-wave joins a later round. Every stream gets the member's `PrewarmList` after its `Hello` and at each list change. An entry removed from the list is no longer sent.
  - **Metrics:** `speculaire_reflector_prewarm_waves_total{cause}`, `list`, `refresh` or `start`, and `speculaire_reflector_prewarm_resolve_failures_total` (D34). A member reads its waves once a second, and never as it answers a `Lookup` (D107).
- **Because:**
  - Right after a member starts, few agents stream to it, so its seeds would be picked among a few and differ from the other members'.
  - Docker Hub counts manifest `GET`s against its pull limit, and not `HEAD`s; a tag that moved upstream would otherwise stay cold until the list changed.
- **Revisit when:** a list grows past what one resolution a second per entry can follow, or an agent's restart mid-wave shows in upstream pulls.

## D188: An agent pulls what members push through its runtime's CRI, one image at a time, below a disk limit (amends D34, D39, D47, D51, D90, D184)

- **Decision:**
  - **Pull:** the agent pulls a pushed image with CRI `PullImage` on the runtime's socket, the same call on containerd and CRI-O, behind the `Pull` trait a `Node` hands out (D90). The request carries no credentials: a registry that needs them is prewarmed only where the registry config holds them (D17). A pull is cut after 30 minutes.
  - **Drop:** a `Prewarm` of an image `Images` lists, or that is queued, pulling, waiting for a retry, or pulled in the last 60 s, counts `dropped` (D51).
  - **Order:** one pull at a time, in the order the pushes came, ahead of any retry. The worker reads the channel while it pulls, so a push never holds a stream (D184).
  - **Retry:** a failed or skipped pull is tried again after 30 s, doubling up to 10 minutes, while some member's latest `PrewarmList` names the image. A new `PrewarmList` makes those retries due at once and forgets the images no list names.
  - **Disk:** before each pull, the agent reads the usage of the image filesystem: `statvfs` on the mount point of `ImageFsInfo`'s first entry, asked once, counted as the kubelet counts it. Above `prewarm.max_disk_percent` (default 80, live) the pull is skipped and counts `no_space`, with one warning until a pull goes through. When the usage cannot be read, the agent warns and pulls.
  - **Metric:** `speculaire_prewarm_pulls_total{result}`, `result` one of `ok`, `failed`, `dropped`, `no_space`, each series at zero from startup.
  - **Stop:** the worker stops before the client closes its streams (D39 step 3). The pull in flight is cut, and the runtime cancels it with the call.
- **Because:**
  - `PullImage` is the kubelet's own call, so the image lands where the kubelet looks, through the mirror and the registry config like any other pull.
  - One pull at a time leaves the link and the disk to the pods' own pulls. Pushes come in the order the member's waves reach the agent (D185).
  - The runtime's image list shows a pull only at its next event or relist, up to 60 s later (D121). Without the window, the same image pushed by the second member after the pull would be pulled again.
  - The kubelet's image garbage collection starts at 85 % by default (kubernetes v1.37.0 `pkg/kubelet/apis/config/v1beta1/defaults.go:157`, usage as `pkg/kubelet/images/image_gc_manager.go:392`). Stopping at 80 % keeps prewarm from making it delete images that pods use.
  - CRI-O walks its image store to answer `ImageFsInfo` (cri-o v1.37.2 `server/image_fs_info.go:15`), and the mount point does not move; `statvfs` reads the usage at no cost. containerd's kubelet-facing first entry is its snapshotter's (containerd v2.4.2 `internal/cri/server/images/imagefs_info.go:55`).
  - CRI-O sets no pull progress timeout (cri-o v1.37.2 `pkg/config/config.go:1192`), so a stalled pull would hold the worker; 30 minutes covers a large image on a slow link.
- **Revisit when:** prewarm pulls slow the pods' own pulls, or nodes need a registry credential that only the kubelet holds.