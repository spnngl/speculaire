//! A digest as the reflector parses it from a message and its index keeps it (D104, D107).

use std::fmt;

use speculaire_oci::reference::Digest;

/// A digest's hash in bytes, inline: parsing one allocates nothing, and comparing two reads no other memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Key {
    /// A `sha256:` digest.
    Sha256([u8; 32]),
    /// A `sha384:` digest.
    Sha384([u8; 48]),
    /// A `sha512:` digest.
    Sha512([u8; 64]),
}

impl Key {
    /// The digest `text` spells, on the terms of [`Digest::parse`]; `None` when it spells none.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (algorithm, hex) = text.split_once(':')?;
        Self::of(algorithm, hex)
    }

    fn of(algorithm: &str, hex: &str) -> Option<Self> {
        match algorithm {
            "sha256" => decode(hex).map(Self::Sha256),
            "sha384" => decode(hex).map(Self::Sha384),
            "sha512" => decode(hex).map(Self::Sha512),
            _ => None,
        }
    }
}

impl From<&Digest> for Key {
    fn from(digest: &Digest) -> Self {
        Self::of(digest.algorithm(), digest.encoded())
            .expect("Digest::parse admits only the lower-case hex of sha256, sha384 and sha512")
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (algorithm, bytes): (&str, &[u8]) = match self {
            Self::Sha256(bytes) => ("sha256", bytes),
            Self::Sha384(bytes) => ("sha384", bytes),
            Self::Sha512(bytes) => ("sha512", bytes),
        };
        write!(f, "{algorithm}:")?;
        bytes.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// The `N` bytes lower-case `hex` spells; `None` when it spells another length or is not lower-case hex.
fn decode<const N: usize>(hex: &str) -> Option<[u8; N]> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    if hex.len() != 2 * N {
        return None;
    }
    let mut bytes = [0; N];
    for (byte, [high, low]) in bytes.iter_mut().zip(hex.as_bytes().as_chunks().0) {
        *byte = 16 * nibble(*high)? + nibble(*low)?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_spells_its_digest_back() {
        for text in [
            format!("sha256:{}", "0a".repeat(32)),
            format!("sha384:{}", "f9".repeat(48)),
            format!("sha512:{}", "7c".repeat(64)),
        ] {
            let digest = Digest::parse(&text).unwrap();
            assert_eq!(Key::parse(&text), Some(Key::from(&digest)));
            assert_eq!(Key::from(&digest).to_string(), text);
        }
    }

    #[test]
    fn a_key_parses_what_a_digest_parses() {
        let hex = "0a".repeat(32);
        for text in [
            String::new(),
            ":".to_owned(),
            format!("sha256:{hex}"),
            format!("sha256:{}", hex.to_uppercase()),
            format!("sha256:{hex}0a"),
            format!("sha384:{hex}"),
            format!("md5:{hex}"),
            format!("sha256:{hex}:"),
            format!(":{hex}"),
            "sha256:".to_owned(),
        ] {
            let digest = Digest::parse(&text).ok();
            assert_eq!(Key::parse(&text), digest.as_ref().map(Key::from), "{text}");
        }
    }

    #[test]
    fn decoding_takes_only_lower_case_hex_of_the_length() {
        assert_eq!(decode::<2>("0aff"), Some([0x0a, 0xff]));
        for hex in ["0aFF", "0afg", "0af", "0aff00"] {
            assert_eq!(decode::<2>(hex), None, "{hex}");
        }
    }
}
