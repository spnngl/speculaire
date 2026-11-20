//! Hashing content as it arrives, against the digest that names it (D7), with aws-lc-rs (D88): the mirror and the
//! artifact store hash with it.

use aws_lc_rs::digest::{self, Context};

use crate::reference::Digest;

/// What has arrived of the content of `expected`, hashed.
#[derive(Clone)]
pub struct Hash {
    context: Context,
    expected: Digest,
}

impl Hash {
    /// A hash of nothing yet, or `None` when `expected` is not sha256, sha384 or sha512.
    #[must_use]
    pub fn new(expected: &Digest) -> Option<Self> {
        Some(Self {
            context: Context::new(algorithm(expected.algorithm())?),
            expected: expected.clone(),
        })
    }

    /// Adds `data` to what has arrived.
    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    /// Whether what has arrived is the content of the digest.
    #[must_use]
    pub fn matches(&self) -> bool {
        Digest::from_hash(
            self.expected.algorithm(),
            self.context.clone().finish().as_ref(),
        )
        .as_ref()
            == Some(&self.expected)
    }
}

fn algorithm(name: &str) -> Option<&'static digest::Algorithm> {
    match name {
        "sha256" => Some(&digest::SHA256),
        "sha384" => Some(&digest::SHA384),
        "sha512" => Some(&digest::SHA512),
        _ => None,
    }
}

/// The digest of `bytes` under the algorithm `name`.
#[must_use]
pub fn of(name: &str, bytes: &[u8]) -> Option<Digest> {
    of_parts(name, &[bytes])
}

/// The digest of `parts`, one after the other, under the algorithm `name`.
pub(crate) fn of_parts(name: &str, parts: &[&[u8]]) -> Option<Digest> {
    let mut context = Context::new(algorithm(name)?);
    for part in parts {
        context.update(part);
    }
    Digest::from_hash(name, context.finish().as_ref())
}

#[cfg(test)]
mod tests;
