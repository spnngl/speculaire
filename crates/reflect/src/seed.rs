//! The seeds of a prewarm image: the agents that pull it from upstream before the others (D51, D181).

use std::cmp::Reverse;
use std::num::NonZeroU32;

use aws_lc_rs::digest::{Context, SHA256};

/// The `count` seeds of `image` among the node identities `nodes`, best first; all of them when `nodes` names fewer.
///
/// Every member streaming with the same nodes picks the same seeds, whatever their order (D51). `image` is the
/// reference as `prewarm.images` writes it. A node ranks by the first 8 bytes, big-endian, of SHA-256 over
/// `image ‖ 0x00 ‖ node`, highest first, a tie going to the smaller node name: the protocol fixes this, so changing it
/// is a breaking change (D181). A node named twice counts once. It allocates only its result.
pub fn seeds<'a, I>(
    image: &str,
    nodes: I,
    count: NonZeroU32,
) -> impl ExactSizeIterator<Item = &'a str> + use<'a, I>
where
    I: IntoIterator<Item = &'a str>,
{
    let count = usize::try_from(count.get()).unwrap_or(usize::MAX);
    let nodes = nodes.into_iter();
    let (fewest, most) = nodes.size_hint();
    // Best first: sorted on the rank, which `Reverse` makes ascending.
    let mut ranked: Vec<(Reverse<u64>, &str)> =
        Vec::with_capacity(count.min(most.unwrap_or(fewest)));
    for node in nodes {
        let rank = (Reverse(score(image, node)), node);
        if let Err(at) = ranked.binary_search(&rank)
            && at < count
        {
            ranked.truncate(count - 1);
            ranked.insert(at, rank);
        }
    }
    ranked.into_iter().map(|(_, node)| node)
}

/// The first 8 bytes, big-endian, of SHA-256 over `image ‖ 0x00 ‖ node`.
fn score(image: &str, node: &str) -> u64 {
    let mut context = Context::new(&SHA256);
    context.update(image.as_bytes());
    context.update(&[0]);
    context.update(node.as_bytes());
    let digest = context.finish();
    u64::from_be_bytes(
        *digest
            .as_ref()
            .first_chunk()
            .expect("a SHA-256 digest is 32 bytes"),
    )
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use super::{score, seeds};

    fn chosen<'a>(image: &str, nodes: &[&'a str], count: u32) -> Vec<&'a str> {
        let count = NonZeroU32::new(count).expect("a test asks for at least one seed");
        seeds(image, nodes.iter().copied(), count).collect()
    }

    /// Scores are the first 8 bytes of `printf '%s\0%s' <image> <node> | shasum -a 256`, computed outside the crate: a
    /// change of hash fails here, and D181 forbids one.
    #[test]
    fn the_hash_is_the_protocols() {
        let image = "registry.example/app:1.0";
        assert_eq!(score(image, "kind-worker2"), 0xd6f9_c4eb_48d2_8578);
        assert_eq!(score(image, "kind-control-plane"), 0x7681_26e0_ba56_0efc);
        assert_eq!(score(image, "kind-worker"), 0x22e6_3aad_2f7a_811e);
        let kind = ["kind-control-plane", "kind-worker", "kind-worker2"];
        assert_eq!(
            chosen("registry.example/app:1.0", &kind, 2),
            ["kind-worker2", "kind-control-plane"]
        );
        // Scores: node-3 0xfb42…, node-1 0xf448…, node-6 0xe591…, node-7 0xb55f…
        let ten: Vec<String> = (0..10).map(|n| format!("node-{n}")).collect();
        let ten: Vec<&str> = ten.iter().map(String::as_str).collect();
        assert_eq!(
            chosen("mirror.gcr.io/library/busybox:1.37", &ten, 3),
            ["node-3", "node-1", "node-6"]
        );
        // Scores: b 0xc430…, a 0x519b…: fewer nodes than seeds makes every node a seed, still ranked.
        assert_eq!(
            chosen("ghcr.io/spnngl/speculaire:0.1.0", &["a", "b"], 5),
            ["b", "a"]
        );
    }

    #[test]
    fn the_order_of_the_nodes_changes_nothing() {
        let names: Vec<String> = (0..50).map(|n| format!("node-{n}")).collect();
        let mut nodes: Vec<&str> = names.iter().map(String::as_str).collect();
        let first = chosen("app:1", &nodes, 3);
        assert_eq!(first.len(), 3);
        let mut rng = fastrand::Rng::with_seed(51);
        for _ in 0..64 {
            rng.shuffle(&mut nodes);
            assert_eq!(chosen("app:1", &nodes, 3), first, "nodes {nodes:?}");
        }
    }

    #[test]
    fn a_node_named_twice_counts_once() {
        let once = chosen("app:1", &["a", "b", "c"], 3);
        assert_eq!(chosen("app:1", &["a", "b", "a", "c", "b"], 3), once);
        assert_eq!(chosen("app:1", &[], 2), Vec::<&str>::new());
    }

    /// Rendezvous hashing: a node leaving moves no seed but its own, so a reconnect changes at most one seed.
    #[test]
    fn a_leaving_node_replaces_only_itself() {
        for case in 0..512 {
            let mut rng = fastrand::Rng::with_seed(case);
            let image = format!("registry.example/app:{}", rng.u16(..));
            let names: Vec<String> = (0..rng.usize(1..40))
                .map(|n| format!("node-{n}-{}", rng.u32(..)))
                .collect();
            let mut nodes: Vec<&str> = names.iter().map(String::as_str).collect();
            let count = rng.u32(1..6);
            let before = chosen(&image, &nodes, count);
            let gone = nodes.swap_remove(rng.usize(..nodes.len()));
            let after = chosen(&image, &nodes, count);
            let kept: Vec<&str> = before.iter().copied().filter(|&n| n != gone).collect();
            let expected = nodes
                .len()
                .min(usize::try_from(count).expect("a u32 fits a usize"));
            assert_eq!(after.len(), expected, "case {case}");
            assert_eq!(after[..kept.len()], kept, "case {case}: {gone} left");
            if kept.len() == before.len() {
                assert_eq!(after, before, "case {case}: {gone}, not a seed, left");
            }
        }
    }
}
