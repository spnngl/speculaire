//! Case-insensitive keys: go-toml, which containerd reads TOML with, matches the key of a struct field in any case
//! (`Server`, `CA` and `Skip_Verify` are `server`, `ca` and `skip_verify`; `unmarshaler.go:2165` in go-toml v2.4.3).
//! Map keys, such as host names and plugin names, stay exact.
//!
//! serde matches exactly, so the keys of a document that name a field are renamed before it is read.

use std::borrow::Cow;

use toml::de::{DeTable, DeValue};
use toml::{Spanned, Table, Value};

/// Renames the keys of `table` that name one of `fields` in another case.
pub(crate) fn fold_fields(table: &mut DeTable<'_>, fields: &[&'static str]) {
    let renames: Vec<(Spanned<Cow<'_, str>>, &'static str)> = table
        .keys()
        .filter_map(|key| {
            let lower = key.as_ref().to_lowercase();
            fields
                .iter()
                .find(|field| **field == lower && **field != key.as_ref())
                .map(|field| (key.clone(), *field))
        })
        .collect();
    for (key, field) in renames {
        if let Some(value) = table.remove(&key) {
            table.insert(Spanned::new(key.span(), Cow::Borrowed(field)), value);
        }
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
    let renames: Vec<(String, &'static str)> = table
        .keys()
        .filter_map(|key| {
            let lower = key.to_lowercase();
            fields
                .iter()
                .find(|field| **field == lower && **field != key.as_str())
                .map(|field| (key.clone(), *field))
        })
        .collect();
    for (key, field) in renames {
        if let Some(value) = table.remove(&key) {
            table.insert(field.to_owned(), value);
        }
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
