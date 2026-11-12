//! Case-insensitive keys: go-toml, which containerd reads TOML with, matches the key of a struct field in any case
//! (`Server`, `CA` and `Skip_Verify` are `server`, `ca` and `skip_verify`; `unmarshaler.go:2165` in go-toml v2.4.3), and
//! so does BurntSushi/toml, which CRI-O's image library reads `registries.conf` with. Map keys, such as host names and
//! plugin names, stay exact.
//!
//! serde matches exactly, so the keys of a document that name a field are renamed before it is read. When two
//! spellings of a field meet, go-toml sets the field once for each: tables merge into one, and of two other values
//! the one set last stays.

use std::borrow::Cow;

use toml::de::{DeTable, DeValue};
use toml::{Spanned, Table, Value};

/// Whether `key` names `field`, a name in ASCII lower case, as go-toml matches them: by `strings.ToLower`, which also
/// lowers K (U+212A) to k and İ (U+0130) to i.
pub(crate) fn go_toml(key: &str, field: &str) -> bool {
    folds_to(key, field, |c, n| {
        matches!((c, n), ('\u{212a}', 'k') | ('\u{130}', 'i'))
    })
}

/// Whether `key` names `field`, a name in ASCII lower case, as BurntSushi/toml matches them: by `strings.EqualFold`,
/// which also folds K (U+212A) to k and ſ (U+017F) to s.
pub(crate) fn equal_fold(key: &str, field: &str) -> bool {
    folds_to(key, field, |c, n| {
        matches!((c, n), ('\u{212a}', 'k') | ('\u{17f}', 's'))
    })
}

/// Whether each character of `key` is that of `field` in any ASCII case, or a non-ASCII one that `folds` to it.
fn folds_to(key: &str, field: &str, folds: impl Fn(char, char) -> bool) -> bool {
    let mut chars = key.chars();
    field.chars().all(|n| {
        chars
            .next()
            .is_some_and(|c| c.eq_ignore_ascii_case(&n) || folds(c, n))
    }) && chars.next().is_none()
}

/// Renames the keys of `table` that name one of `fields` in another case, as `names` matches them, merging two
/// spellings of one field.
pub(crate) fn fold_fields(
    table: &mut DeTable<'_>,
    fields: &[&'static str],
    names: fn(&str, &str) -> bool,
) {
    let renames: Vec<(Spanned<Cow<'_, str>>, &'static str)> = table
        .keys()
        .filter_map(|key| {
            fields
                .iter()
                .find(|field| **field != key.as_ref() && names(key.as_ref(), field))
                .map(|field| (key.clone(), *field))
        })
        .collect();
    for (key, field) in renames {
        if let Some(value) = table.remove(&key) {
            match table.get_mut(field) {
                Some(existing) => merge(existing, value),
                None => {
                    table.insert(Spanned::new(key.span(), Cow::Borrowed(field)), value);
                }
            }
        }
    }
}

/// Sets `value` over `existing` as go-toml does: it reads a document in order, so the later of two values stays.
fn merge<'i>(existing: &mut Spanned<DeValue<'i>>, value: Spanned<DeValue<'i>>) {
    let span = value.span();
    let later = existing.span().start.cmp(&span.start).is_lt();
    match (existing.get_mut(), value.into_inner()) {
        (DeValue::Table(into), DeValue::Table(from)) => {
            for (key, value) in from {
                match into.get_mut(key.as_ref().as_ref()) {
                    Some(existing) => merge(existing, value),
                    None => {
                        into.insert(key, value);
                    }
                }
            }
        }
        (_, value) if later => *existing = Spanned::new(span, value),
        _ => {}
    }
}

/// The table under `key` of `table`, if it is one.
pub(crate) fn table_at<'a, 'i>(
    table: &'a mut DeTable<'i>,
    key: &str,
) -> Option<&'a mut DeTable<'i>> {
    match table.get_mut(key)?.as_mut() {
        DeValue::Table(inner) => Some(inner),
        _ => None,
    }
}

/// Every table that is a value of `table`.
pub(crate) fn tables_in<'a, 'i>(
    table: &'a mut DeTable<'i>,
) -> impl Iterator<Item = &'a mut DeTable<'i>> {
    table
        .iter_mut()
        .filter_map(|(_, value)| match value.as_mut() {
            DeValue::Table(inner) => Some(inner),
            _ => None,
        })
}

/// [`fold_fields`] for a table without positions.
pub(crate) fn fold_value_fields(table: &mut Table, fields: &[&'static str]) {
    for field in fields {
        // go-toml sees the keys in byte order, which is the order of the map: the last spelling is set last.
        let spellings: Vec<String> = table
            .keys()
            .filter(|key| go_toml(key, field))
            .cloned()
            .collect();
        let merged = spellings
            .iter()
            .filter_map(|key| table.remove(key))
            .reduce(merge_value);
        if let Some(value) = merged {
            table.insert((*field).to_owned(), value);
        }
    }
}

/// [`merge`] for values without positions: `later` is set after `earlier`.
fn merge_value(earlier: Value, later: Value) -> Value {
    match (earlier, later) {
        (Value::Table(mut into), Value::Table(from)) => {
            for (key, value) in from {
                let value = match into.remove(&key) {
                    Some(existing) => merge_value(existing, value),
                    None => value,
                };
                into.insert(key, value);
            }
            Value::Table(into)
        }
        (_, later) => later,
    }
}

/// The table under `key` of `table`, if it is one.
pub(crate) fn value_table_at<'a>(table: &'a mut Table, key: &str) -> Option<&'a mut Table> {
    match table.get_mut(key)? {
        Value::Table(inner) => Some(inner),
        _ => None,
    }
}

/// Every table that is a value of `table`.
pub(crate) fn value_tables_in(table: &mut Table) -> impl Iterator<Item = &mut Table> {
    table.iter_mut().filter_map(|(_, value)| match value {
        Value::Table(inner) => Some(inner),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::{equal_fold, go_toml};

    #[test]
    fn a_key_names_a_field_as_each_library_folds_it() {
        for key in [
            "skip_verify",
            "Skip_Verify",
            "s\u{212a}ip_verify",
            "s\u{212a}\u{130}p_verify",
        ] {
            assert!(go_toml(key, "skip_verify"), "{key}");
        }
        for key in [
            "\u{17f}kip_verify",
            "skip_verif",
            "skip_verifyy",
            "skip-verify",
        ] {
            assert!(!go_toml(key, "skip_verify"), "{key}");
        }
        for key in ["insecure", "INSECURE", "in\u{17f}ecure", "bloc\u{212a}ed"] {
            assert!(
                equal_fold(key, "insecure") || equal_fold(key, "blocked"),
                "{key}"
            );
        }
        for key in ["\u{130}nsecure", "insecur", "insecures"] {
            assert!(!equal_fold(key, "insecure"), "{key}");
        }
    }
}
