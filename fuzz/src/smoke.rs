//! Each target on its seeds, their truncations and single-bit flips, on stable: what `just check` runs.

use std::fs;
use std::path::Path;

use crate::{TARGETS, values};

/// The seeds of `target`: the files of `seeds/<target>/`, and for `config` the reference file uncommented.
fn seeds(target: &str) -> Vec<Vec<u8>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("seeds")
        .join(target);
    let mut seeds: Vec<Vec<u8>> = fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("{}: {err}", dir.display()))
        .map(|entry| {
            fs::read(entry.expect("a readable seed directory").path()).expect("a readable seed")
        })
        .collect();
    if target == "config" {
        seeds.push(reference().into_bytes());
    }
    seeds
}

/// `packaging/config.toml` with its keys uncommented, as `just fuzz-seeds` writes it for libFuzzer.
fn reference() -> String {
    include_str!("../../packaging/config.toml")
        .lines()
        .map(|line| match line.strip_prefix('#') {
            Some(key) if key.starts_with(|c: char| c.is_ascii_lowercase()) => key,
            _ => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every prefix, and every single-bit flip of the first 256 bytes.
fn variants(seed: &[u8]) -> impl Iterator<Item = Vec<u8>> {
    let prefixes = (0..seed.len()).map(|end| seed[..end].to_vec());
    let flips = (0..seed.len().min(256)).flat_map(move |i| {
        (0..8).map(move |bit| {
            let mut flipped = seed.to_vec();
            flipped[i] ^= 1 << bit;
            flipped
        })
    });
    prefixes.chain(flips)
}

#[test]
fn every_target_survives_its_seeds_and_their_variants() {
    for (name, entry) in TARGETS {
        let seeds = seeds(name);
        assert!(!seeds.is_empty(), "{name} has no seed");
        for seed in seeds {
            entry(&seed);
            variants(&seed).for_each(|variant| entry(&variant));
        }
    }
}

#[test]
fn the_reference_seed_parses() {
    speculaire_agent::config::parse(&reference()).expect("the uncommented reference file parses");
}

#[test]
fn targets_match_the_shims() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz_targets");
    let mut shims: Vec<String> = fs::read_dir(&dir)
        .expect("fuzz_targets/ is readable")
        .map(|entry| {
            let path = entry.expect("a readable fuzz_targets/ entry").path();
            path.file_stem()
                .expect("a shim file name")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    shims.sort();
    let mut names: Vec<&str> = TARGETS.iter().map(|(name, _)| *name).collect();
    names.sort_unstable();
    assert_eq!(shims, names);
}

/// The dotted names of the keys under `table`, tables themselves left out.
fn leaves(prefix: &str, table: &toml::Table, names: &mut Vec<String>) {
    for (key, value) in table {
        let name = format!("{prefix}{key}");
        match value {
            toml::Value::Table(inner) => leaves(&format!("{name}."), inner, names),
            _ => names.push(name),
        }
    }
}

#[test]
fn config_values_draws_every_key_of_the_reference() {
    let table: toml::Table = reference()
        .parse()
        .expect("the uncommented reference file is TOML");
    let mut keys = Vec::new();
    leaves("", &table, &mut keys);
    keys.sort();
    let mut drawn: Vec<&str> = values::KEYS.iter().map(|(key, _)| *key).collect();
    drawn.sort_unstable();
    assert_eq!(
        keys, drawn,
        "a key was added to or removed from packaging/config.toml"
    );
}

#[test]
fn the_first_literal_of_every_key_parses() {
    let text: String = values::KEYS
        .iter()
        .flat_map(|(key, literals)| [*key, " = ", literals.first().expect("a literal"), "\n"])
        .collect();
    speculaire_agent::config::parse(&text).expect("the first literals form a valid config");
}
