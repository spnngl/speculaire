//! OCI image references and platforms, as containerd reads them (D81): a [`reference::Reference`] can only be made by
//! parsing, and a platform is matched as containerd's `platforms.Only` matches it. [`manifest::children`] reads what a
//! manifest points to (D88). [`referrers`] reads OCI 1.1 referrers and [`index`] an image index's platform and
//! attestation manifests, for artifact discovery (D43, D49).

pub mod index;
pub mod manifest;
pub mod platform;
pub mod reference;
pub mod referrers;

/// Go's `strings.ToLower`: each character's simple lower case, so `İ` is `i` and `Σ` always `σ`, where
/// `str::to_lowercase` gives `i̇` and, at the end of a word, `ς`.
fn go_lower(text: &str) -> String {
    text.chars().map(lower).collect()
}

/// Whether [`go_lower`] changes `text`, without building its result.
fn has_upper(text: &str) -> bool {
    text.chars().any(|c| lower(c) != c)
}

fn lower(c: char) -> char {
    // The full lower case of a character starts with its simple one; only `İ` has more than one character.
    c.to_lowercase().next().unwrap_or(c)
}
