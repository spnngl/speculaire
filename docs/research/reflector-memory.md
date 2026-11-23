# Reflector memory at 10,000 agents

What one reflector's peak RSS is made of in D33's load (10k agents × 2k digests from a pool of 200k), measured on 2026-11-23, and what each allocator and change costs. It backs D202.

## Method

- **Heap by owner:** DHAT (`just valgrind`'s glibc build) on the reflector under 1k agents and a pool of 20k, one tenth of D33's load, scaled by ten. The index alone at full scale: divan's `AllocProfiler` over `fill` in `crates/reflect/benches/micro.rs` (`just bench-micro`), its "max alloc" less the benchmark's own 13 MB of keys: 156 MB, 134 MB with D202.
- **RSS and allocator:** `load.yml`'s one-reflector scenario on GitHub's 4-CPU runners, with `MIMALLOC_SHOW_STATS=1` for mimalloc's committed peak. Throwaway branches `wip/mem-*`; a run's peak varies by about 10 MiB, its resync by up to 15 s.

## Heap by owner (raw, before allocator overhead)

| Owner | At 10k agents | Note |
|---|---|---|
| Index: digest numbers of each agent | 65 MB → 42 MB | roaring array containers grow by doubling; D202 fits them |
| Index: holders of each digest, and the tables | 92 MB | `Holders` slots, 104 B each in a `Vec` of 2^18 (27 MB), and a bitmap of about 100 node numbers each (cap 128, 256 B) |
| Connection: rustls's read buffer | 45 MB | `DeframerVecBuffer` keeps 4 KiB per connection, never less (rustls 0.23.46 `src/msgs/deframer/buffers.rs:214-251`) |
| Connection: serve task | 23 MB | the future of `server::serve`, about 2.3 KB |
| Connection: rustls keys and state | 27 MB | |
| Connection: tokio, tokio-rustls, outbox | 10 MB | |
| **Total** | **about 262 MB → 239 MB with D202** | |

## Peak RSS by allocator

Peak RSS, lookup p99 and resync, x86_64 / aarch64.

| Allocator | Before D202 | With D202 |
|---|---|---|
| mimalloc, `MI_SECURE=4` (D46) | 460 / 453 MiB, 79 / 94 µs, 61.1 / 41.5 s | 396 / 392 MiB, 79 / 103 µs, 44.1 / 43.3 s |
| same, THP off | 423 / 421 MiB | 366 / 363 MiB, 103 / 103 µs, 52.2 / 42.3 s |
| mimalloc, not secure | 369 / 361 MiB | |
| same, THP off | 345 / 343 MiB | |
| musl's mallocng | 313 / 312 MiB, 67 / 112 µs, 42.4 / 43.6 s | 279 / 275 MiB, 103 / 158 µs, **91.7** / 57.4 s |

- **Secure mode** costs about 90 MiB over plain mimalloc: its 8 B of padding a block (mimalloc v3 `include/mimalloc/types.h:96`) moves each power-of-two buffer to the next size class (4096 → 5120, 256 → 320).
- **THP:** mimalloc v3 `madvise(MADV_HUGEPAGE)`s its arenas (`src/prim/unix/prim.c:412`), and the kernel backs them with 2 MiB pages over memory never touched: about 30 MiB. `MIMALLOC_ALLOW_THP=0` and the crate's `no_thp` feature gave the same on the runners (THP `madvise`); only the first holds under THP `always` (`prim.c:223-230`).
- **mimalloc v2**, secure: 413 MiB on aarch64, no better than v3 with THP off. Purging at once (`MIMALLOC_PURGE_DELAY=0`, `MIMALLOC_PAGE_FULL_RETAIN=0`) changed nothing beyond THP off.
- **mallocng** is the leanest, and the only allocator near 256 MiB, but its resync missed D33's 60 s once in two runs.

## What is left

- rustls's 4 KiB read buffer per connection, 45 MB raw and 50 MiB under secure mode: only rustls's unbuffered API, or kernel TLS, reads without it.
- `Key` is 65 B inline in each `Holders`: boxing the rare sha384 and sha512 keys saves about 16 MB.
- Each digest's holders bitmap keeps about 25 % slack; fitting it on each change costs a copy per pair during a snapshot.
