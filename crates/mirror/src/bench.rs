//! Blob hashing as `just bench-micro` measures it (D7, D104), behind the `bench` feature: the hash is private otherwise.

use speculaire_oci::reference::Digest;

use crate::hash::{self, Hash};

/// The digest of `content` under `algorithm`, `None` for one the mirror does not hash.
#[must_use]
pub fn digest(algorithm: &str, content: &[u8]) -> Option<Digest> {
    hash::of(algorithm, content)
}

/// Hashes `content` in pieces of `piece` bytes, as a blob arrives, against `expected`: whether it matches, `None` for
/// an algorithm the mirror does not hash.
#[must_use]
pub fn arrive(expected: &Digest, content: &[u8], piece: usize) -> Option<bool> {
    let mut hash = Hash::new(expected)?;
    for data in content.chunks(piece.max(1)) {
        hash.update(data);
    }
    Some(hash.matches())
}

#[cfg(test)]
mod tests {
    use super::{arrive, digest};

    #[test]
    fn content_arriving_in_pieces_matches_its_digest() {
        let content = b"a blob".repeat(100);
        let expected = digest("sha512", &content).expect("the mirror hashes sha512");
        assert_eq!(arrive(&expected, &content, 7), Some(true));
        assert_eq!(arrive(&expected, &content[1..], 7), Some(false));
        assert_eq!(digest("md5", &content), None);
    }
}
