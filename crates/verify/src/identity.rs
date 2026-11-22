//! The verdict of a container's image, from the identity the gate reads in its `CreateContainer` (D65, D169, D170).

use speculaire_runtime::identity::{Identified, MISMATCH, NOT_CONFIG};
use tokio::time::Instant;

use crate::engine::{Key, Lookup, Verdict, Verdicts, match_hash};
use crate::{MatchHash, Policies, RootHash};

impl Verdicts {
    /// The verdict of `identified` under `policies`; none when no name of it matches a policy. A name no policy matches
    /// never lightens another's verdict (D179).
    ///
    /// Each listed manifest of the image passes when its verdict under each policy group of the names passes (D151).
    /// The image is allowed when one of its manifests is; otherwise it has the most hopeful of their verdicts, and
    /// `Unverifiable` when it has no listed manifest or no identity (D65). A container whose snapshot is not its
    /// image's is `Rejected`, whatever its names (D170).
    #[must_use]
    pub fn identified(
        &self,
        identified: &Identified<'_>,
        policies: &Policies,
        root: Option<RootHash>,
    ) -> Option<Lookup> {
        match identified {
            Identified::Unknown(reason) => return Some(unverifiable(reason)),
            Identified::Unlisted => return Some(Lookup::PENDING),
            Identified::Mismatched => {
                return Some(Lookup {
                    verdict: Verdict::Rejected {
                        reason: MISMATCH.into(),
                    },
                    stale: false,
                });
            }
            Identified::Listed { .. } | Identified::Unconfirmed { .. } | Identified::Image(_) => {}
        }
        let mut groups = Groups::new();
        for hash in identified
            .names()
            .filter_map(|name| match_hash(policies, name))
        {
            groups.insert(hash);
        }
        if groups.is_empty() {
            return None;
        }
        let manifest = |image| {
            let lookups = groups.iter().map(|policies| {
                self.get(Key {
                    image,
                    policies,
                    root,
                })
            });
            lookups.reduce(|worst, lookup| Lookup {
                stale: worst.stale || lookup.stale,
                verdict: if failure(&lookup.verdict) > failure(&worst.verdict) {
                    lookup.verdict
                } else {
                    worst.verdict
                },
            })
        };
        // CRI-O's manifests stand for the image ID whose config they name (D65, D172).
        let id = if let Identified::Image(image) = identified {
            Some(&image.id)
        } else {
            None
        };
        let best = identified
            .digests()
            .filter(|digest| id.is_none_or(|id| self.builds(digest, id)))
            .filter_map(manifest)
            .max_by_key(|lookup| hope(&lookup.verdict));
        Some(best.unwrap_or_else(|| unverifiable(NOT_CONFIG)))
    }
}

fn unverifiable(reason: &str) -> Lookup {
    Lookup {
        verdict: Verdict::Unverifiable {
            reason: reason.into(),
            retry_at: Instant::now(),
        },
        stale: false,
    }
}

/// How far a verdict is from passing: a manifest has the worst of its groups'.
fn failure(verdict: &Verdict) -> u8 {
    match verdict {
        Verdict::Allow => 0,
        Verdict::Pending => 1,
        Verdict::Unverifiable { .. } => 2,
        Verdict::Rejected { .. } => 3,
    }
}

/// How close a verdict is to passing, or to its reason: an image has the most hopeful of its manifests'. A rejection,
/// final, tells its reason before an unverifiable verdict's (D20).
fn hope(verdict: &Verdict) -> u8 {
    match verdict {
        Verdict::Unverifiable { .. } => 0,
        Verdict::Rejected { .. } => 1,
        Verdict::Pending => 2,
        Verdict::Allow => 3,
    }
}

/// The most policy groups [`Groups`] holds on the stack.
const STACKED: usize = 8;

/// The distinct policy groups of a container's names, the first eight on the stack (D107, D189).
struct Groups {
    stacked: [MatchHash; STACKED],
    len: usize,
    spilled: Vec<MatchHash>,
}

impl Groups {
    fn new() -> Self {
        Self {
            stacked: [MatchHash([0; 32]); STACKED],
            len: 0,
            spilled: Vec::new(),
        }
    }

    /// Adds `hash` unless it is already held.
    fn insert(&mut self, hash: MatchHash) {
        if self.iter().any(|held| held == hash) {
            return;
        }
        match self.stacked.get_mut(self.len) {
            Some(slot) => {
                *slot = hash;
                self.len += 1;
            }
            None => self.spilled.push(hash),
        }
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn iter(&self) -> impl Iterator<Item = MatchHash> {
        self.stacked[..self.len]
            .iter()
            .chain(&self.spilled)
            .copied()
    }
}

#[cfg(test)]
mod tests;
