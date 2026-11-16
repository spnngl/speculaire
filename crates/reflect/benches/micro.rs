//! The reflector's index lookup in D33's fleet, 10k agents × 2k blobs (D104), and its reading and parsing of a
//! message: `just bench-micro`.

use std::pin::pin;
use std::sync::LazyLock;
use std::task::{Context, Poll, Waker};

use divan::Bencher;
use prost::Message as _;
use speculaire_reflect::SNAPSHOT_CHUNK;
use speculaire_reflect::bench::Filled;
use speculaire_reflect::frame::{self, Reader};
use speculaire_reflect::message::Request;
use speculaire_reflect::proto::{AgentMessage, LookupRequest, Snapshot, agent_message};

/// Counts each benchmark''s allocations, which D107 asks a hot path to avoid.
#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

/// D33's fleet, from a pool where each digest has about 100 holders, as `speculaire-loadgen` draws it.
static FLEET: LazyLock<Filled> = LazyLock::new(|| {
    Filled::new(10_000, 2_000, 200_000, 33)
        .expect("2k digests a node are within the reflector's limit")
});

fn main() {
    divan::main();
}

#[divan::bench]
fn lookup(bencher: Bencher<'_, '_>) {
    let fleet = &*FLEET;
    let mut n = 0;
    bencher.bench_local(|| {
        n += 1;
        fleet.lookup(n)
    });
}

/// The whole fleet announcing to an empty index, as after the reflector restarts: the index takes it under one lock.
#[divan::bench(sample_count = 3, sample_size = 1)]
fn fill() -> Option<Filled> {
    Filled::new(10_000, 2_000, 200_000, 33)
}

/// 100 lookups read off one connection, as the reflector reads them in D33's steady phase: per lookup, the
/// allocations beyond its digest's string are the reader's.
#[divan::bench]
fn read(bencher: Bencher<'_, '_>) {
    let mut frames = Vec::new();
    for id in 0..100 {
        let lookup = AgentMessage {
            message: Some(agent_message::Message::Lookup(LookupRequest {
                digest: format!("sha256:{id:064x}"),
                id,
            })),
        };
        let body = lookup.encode_to_vec();
        let length = u32::try_from(body.len()).expect("a lookup is a few bytes");
        frames.extend(length.to_be_bytes());
        frames.extend(body);
    }
    bencher.bench_local(|| {
        let mut reader = Reader::<AgentMessage>::new(frame::LIMIT);
        let mut io = frames.as_slice();
        // A slice never waits.
        while let Poll::Ready(Some(message)) = pin!(reader.next(&mut io))
            .poll(&mut Context::from_waker(Waker::noop()))
            .map(|next| next.expect("the frames were written whole"))
        {
            divan::black_box(message);
        }
    });
}

/// One full `Snapshot` chunk of sha256 digests, parsed as the reflector reads it.
#[divan::bench]
fn parse(bencher: Bencher<'_, '_>) {
    let snapshot = Snapshot {
        digests: (0..SNAPSHOT_CHUNK)
            .map(|n| format!("sha256:{n:064x}"))
            .collect(),
        last: true,
        seq: 0,
    };
    let message = AgentMessage {
        message: Some(agent_message::Message::Snapshot(snapshot)),
    };
    bencher
        .with_inputs(|| message.clone())
        .bench_values(Request::try_from);
}
