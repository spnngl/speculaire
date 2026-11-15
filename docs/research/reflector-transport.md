# What an agent connection costs the reflector, over gRPC and over our own framing

**Short answer:** one agent connection holds 54.8 KB of the reflector's heap over gRPC, 38.8 KB with h2's buffers cut to 4 KiB, and 9.2 KB over a length-prefixed protobuf framing on rustls. At 10,000 agents, the framing would take the M3 step 07 reflector from 1150–1180 MiB to about 600 MiB, and the h2 patch to about 970 MiB. The framing must rebuild lookup numbering, keepalive, the stop, and refusal reasons. It saves no dependency, because the containerd client keeps tonic in the binary.

**Outcome:** D105 adopted the framing, with no dual-ALPN period.

**Sources:** the prototype on branch `research/reflector-transport-prototype` (`apps/transport-bench`, deleted after D105), built on main at b687617. Step 07's measurements come from branch `m3/07-load`. Upstream is cited from the crates.io sources of h2 0.4.20, tokio-util 0.7.20, tonic 0.14.9 and rustls 0.23.46.

## Method

- **Server:** one process, 2 tokio worker threads, mimalloc with `secure` (D46), behind a global allocator that counts live bytes and their peak. It accepts connections as `crates/reflect/src/server.rs` does: TLS 1.3, node certificates, one handshake task each. It parses every digest like the real reflector, then drops it, so the index stays out of the numbers. A lookup answers 8 made-up holders.
- **Variants:**
  - `grpc`: main's tonic server and hand-dialled client (D98), with step 07's 8 KiB stream window, 64 KiB connection window and 1 KiB/4 KiB codec buffers.
  - `h2small`: `grpc` built on h2 with `h2-small-buffers.patch`. The write buffer goes from 16 KiB (`src/codec/framed_write.rs:67`) to 4 KiB, and the frame read buffer from 8 KiB (tokio-util `src/codec/framed_impl.rs:25`) to 4 KiB (`src/codec/mod.rs:45-50`).
  - `framed`: each message is a 4-byte length, then an `Up` or `Down` envelope (`proto/speculaire/reflect/v1/framed.proto`), with ALPN `speculaire-reflect/1`. The reflector runs one task per connection. A message's buffer exists only while that message is in flight.
- **Load:** step 07's agents (D33) in a second process, 500 connections a second. Each agent sends `Hello`, then 2,000 digests in `Snapshot` chunks of 25, a lookup every 2 s and a `Delta` every 10 s. At 10,000 agents, that is 5,000 lookups and 1,000 deltas a second.
- **Readings:** *rest* is read 10 s after every snapshot has arrived. *Peak* is the allocator's peak while a tenth of the agents send their whole snapshot again. Per connection means (reading − reading before any connection) ÷ connections. RSS comes from `ps`.
- **Platform:** Apple M5 with 10 cores and 24 GB, macOS 27.2.1, loopback, 10,000 connections, none failed. At 1,000 connections the numbers are within 4% of these.
- **Rerun:** on the prototype branch, `cargo run --release -p speculaire-transport-bench -- drive --variant framed --agents 10000 --dir <scratch> --port <free port>`. `drive` starts the server as a child process and prints the readings.

## Results

| Variant | Heap at rest | Heap at peak | RSS | Server RSS at 10,000 |
|---|---|---|---|---|
| `grpc` | 54,756 B | 54,890 B | 76,708 B | 737 MiB |
| `h2small` | 38,755 B | 38,969 B | 56,521 B | 545 MiB |
| `framed` | 9,176 B | 9,179 B | 18,682 B | 184 MiB |

- The peak sits within 0.2 KB of rest in every variant. A 25-digest chunk is 1.8 KB, and the 8 KiB stream window keeps one or two in flight. Step 07's peak exceeds its steady state because of the index, which this bench leaves out.
- `h2small` saves 16 KB per connection, exactly the 12 KiB and 4 KiB the patch cuts. h2 still grows a buffer when a frame needs more.
- In `framed`, what remains is the TLS session (the 4 KiB rustls read buffer, about 1.2 KiB of AEAD keys) and the task holding it. gRPC adds to that the h2 buffers, the hpack tables, the stream slabs, the tonic connection task and the codec buffers (the step 07 heap profiles list them).
- `grpc` here costs 54.8 KB per connection, against step 07's 49 KB estimate from DHAT on Linux. The bench counts every allocation request, and runs on macOS.

## Projected reflector RSS at 10,000 agents

Step 07 measured 950 MiB on this machine, in Docker, and 1150–1180 MiB at peak on GitHub's runners. Each figure below swaps `grpc`'s 737 MiB of connections for the variant's own, keeping the index (about 170 MB of heap) and step 07's allocator overhead. The target is 1 GiB and the goal 256 MiB.

| Option | This machine | GitHub runners |
|---|---|---|
| Keep gRPC | 950 MiB | 1150–1180 MiB |
| Patch h2 | 757 MiB | 955–989 MiB |
| Own framing | 396 MiB | 593–627 MiB |
| Short requests with leases | about 213 MiB, plus the connections open at any time | about 413–443 MiB, plus the same |

No option reaches 256 MiB while the index and the allocator take what they take now.

## What the framing must rebuild

- **Lookup beside the stream.** gRPC runs each `Lookup` on its own HTTP/2 stream, in its own task. A framed `Ask` carries an id and its `Answer` carries it back, so the agent needs a table from id to waiter, with D98's 5 s call timeout. The prototype handles an agent's messages in order, so a lookup waits behind that agent's earlier chunks. Parsing a chunk takes microseconds; applying one to the real index takes longer. Spawning a task per `Ask` would remove that wait, and the connection would then need a writer task fed by a bounded queue. Both transports share one TCP connection, so a lost segment stalls everything on it either way. Hedging to a second member after 20 ms (D98) works the same.
- **Keepalive.** HTTP/2 pings every 30 s, and a connection silent 10 s after a ping is closed (D97). The prototype has the agent send `Ping` every 30 s, the reflector answer `Pong`, and either side close after 40 s of silence: about 20 lines.
- **Graceful stop.** Today a stopping reflector ends every stream with `UNAVAILABLE` (D39, D97), and hyper sends GOAWAY. The framing needs a stop signal per connection task, a `Refused` with `REASON_STOPPING`, then a TLS close. D103's drain waits for each connection to close: that becomes waiting for the connection tasks.
- **Refusal reasons.** D97 maps each reason to a `Status` code (`permission_denied`, `failed_precondition`, `resource_exhausted`, `invalid_argument`, `aborted`, `unavailable`). The framing sends a `Refused` message with a `Reason` enum instead. The agent only logs the code, so nothing there depends on gRPC's codes.
- **Message limits.** tonic refuses a message over `max_decoding_message_size`. The framing checks the length prefix against 4 MiB before allocating, and the sender checks too. The frame reader is a new parser of outside data, so it needs a fuzz target beside `fuzz/fuzz_targets/reflect.rs`.
- **Flow control.** HTTP/2 windows bound what each stream may have unread. The framing reads one message at a time and writes its replies inline, so a reflector holds at most one message per connection, and TCP backpressure stops an agent that sends faster than it is read. A `Prewarm` push (D51) would need a bounded queue per connection.
- **Tooling.** grpcurl, tonic's interceptors and tower layers, and HTTP/2 dissectors stop applying. Every byte is inside mTLS with node certificates, so they help little today, and the load balancer is L4 (D2). A debug client becomes our own code.
- **Migration.** An agent and a reflector of different versions must still talk while a cluster rolls out. A reflector serves both ALPNs, `h2` and `speculaire-reflect/1`, for one minor. The agent offers the new one first. Both share the index and the `Session`. Dropping `h2` afterwards drops a protocol version, a breaking change under D40.

## What each option costs in code

- **Keep gRPC:** nothing. It stays above the 1 GiB target on GitHub.
- **Patch h2:** a 10-line patch (`h2-small-buffers.patch`), carried as a `[patch.crates-io]` git fork with a `just vet` audit (D71) and rebased on every h2 release, until h2 makes the buffer sizes configurable upstream. The protocol does not change.
- **Own framing:** the prototype's `framed.rs` takes 207 lines for the server loop, the frame reader and writer, and a client. Production adds the lookup waiters, the stop, metrics, the fuzz target and the dual-ALPN period, maybe 400 lines in total. It removes `server.rs`'s tonic glue and `client.rs`'s `Channel` dial. tonic, h2 and hyper stay in the binary for containerd's API (`crates/runtime`), so the build gets no lighter.
- **Short requests with leases:** a different protocol, not a different transport. Agents would renew their holdings on a lease instead of keeping a stream. A holder would then leave the index when its lease expires, where today it leaves when its stream drops (D39 step 3). An agent that dies stays in lookups for up to one lease period. Lookups at 5,000 a second still need pooled connections, or a TLS handshake per request. D2, D33, D97, D98 and D103 would all change. Not prototyped.
