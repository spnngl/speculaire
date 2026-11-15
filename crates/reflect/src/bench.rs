//! The index as `just bench-micro` measures it (D104), behind the `bench` feature: the index is private otherwise.

use std::net::{Ipv4Addr, SocketAddr};

use speculaire_oci::reference::Digest;

use crate::LOOKUP_PEERS;
use crate::index::Index;
use crate::server::Limits;

/// An index holding a fleet's digests.
#[derive(Debug)]
pub struct Filled {
    index: Index,
    pool: Vec<Digest>,
}

impl Filled {
    /// `agents` nodes holding up to `blobs` digests each, drawn with `seed` from a pool of `pool` digests; `None` when
    /// a node would hold more than the reflector takes, or the pool is empty.
    #[must_use]
    pub fn new(agents: usize, blobs: usize, pool: usize, seed: u64) -> Option<Self> {
        if pool == 0 {
            return None;
        }
        let pool: Vec<Digest> = (0..pool)
            .map(|number| Digest::parse(&format!("sha256:{number:064x}")).ok())
            .collect::<Option<_>>()?;
        let mut rng = fastrand::Rng::with_seed(seed);
        let index = Index::default();
        for agent in 0..agents {
            let stream = index.join(
                &format!("agent-{agent}"),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
            );
            let held: Vec<Digest> =
                std::iter::repeat_with(|| pool[rng.usize(..pool.len())].clone())
                    .take(blobs)
                    .collect();
            index
                .stage(&stream, &held, Limits::default().digests)
                .ok()?;
            index.commit(&stream).ok()?;
        }
        Some(Self { index, pool })
    }

    /// Looks up the `n`th digest of the pool, cycling, as the reflector answers an agent: how many holders it gives.
    #[must_use]
    pub fn lookup(&self, n: usize) -> usize {
        let digest = &self.pool[n % self.pool.len()];
        self.index.lookup(digest, "asking", LOOKUP_PEERS).len()
    }
}

#[cfg(test)]
mod tests {
    use super::Filled;

    #[test]
    fn a_filled_index_answers_its_digests() {
        // 500 draws from 4 digests: every agent holds them all, so every lookup answers its most.
        let filled = Filled::new(20, 500, 4, 1).expect("4 digests are within the limit");
        assert!((0..8).all(|n| filled.lookup(n) == crate::LOOKUP_PEERS));
    }

    #[test]
    fn an_empty_pool_fills_nothing() {
        assert!(Filled::new(1, 0, 0, 1).is_none());
    }
}
