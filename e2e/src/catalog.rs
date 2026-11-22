//! The rows of `docs/metrics.md` (D34): each metric, the runtime whose agents emit it, and whether it is built yet
//! (D109, D182).

use crate::Runtime;

/// The catalog, as this build of the suites read it.
const CATALOG: &str = include_str!("../../docs/metrics.md");

/// A metric of the catalog.
#[derive(Debug)]
pub struct Row {
    /// Its name, such as `speculaire_mirror_requests_total`.
    pub name: &'static str,
    /// The runtime whose agents alone emit it; `None` for both.
    runtime: Option<Runtime>,
    /// Whether its `Planned` cell names a milestone: no code emits it yet (D109).
    planned: bool,
}

impl Row {
    /// Whether an agent on `runtime` may emit it.
    #[must_use]
    pub fn on(&self, runtime: Runtime) -> bool {
        self.runtime.is_none_or(|only| only == runtime)
    }

    /// Whether the suites on `runtime` must emit it: it is built, and on that runtime (D182).
    #[must_use]
    pub fn required(&self, runtime: Runtime) -> bool {
        !self.planned && self.on(runtime)
    }
}

/// Every row of the catalog.
///
/// # Errors
///
/// When a table's fourth column is not `Runtime`, or a row's `Runtime` cell is not `both`, `containerd` or `CRI-O`.
pub fn rows() -> Result<Vec<Row>, String> {
    parse(CATALOG)
}

fn parse(catalog: &'static str) -> Result<Vec<Row>, String> {
    let mut rows = Vec::new();
    for line in catalog.lines() {
        let cells = cells(line);
        if cells.first() == Some(&"Metric") && cells.get(3) != Some(&"Runtime") {
            return Err(format!("the fourth column of {line:?} is not Runtime"));
        }
        let Some(name) = cells
            .first()
            .and_then(|cell| cell.strip_prefix('`')?.strip_suffix('`'))
        else {
            continue;
        };
        let runtime = match cells.get(3) {
            Some(&"both") => None,
            Some(&"containerd") => Some(Runtime::Containerd),
            Some(&"CRI-O") => Some(Runtime::Crio),
            other => {
                return Err(format!(
                    "{name}: Runtime is {other:?}, not both, containerd or CRI-O"
                ));
            }
        };
        let planned = cells.last().is_some_and(|cell| {
            cell.strip_prefix('M')
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        });
        rows.push(Row {
            name,
            runtime,
            planned,
        });
    }
    Ok(rows)
}

/// The trimmed cells of a table line, split at each `|` that `\` does not escape; empty for any other line.
fn cells(line: &str) -> Vec<&str> {
    let Some(inner) = line.strip_prefix('|').and_then(|l| l.strip_suffix('|')) else {
        return Vec::new();
    };
    let mut cells = Vec::new();
    let mut start = 0;
    let mut escaped = false;
    for (at, c) in inner.char_indices() {
        if c == '|' && !escaped {
            cells.push(inner[start..at].trim());
            start = at + 1;
        }
        escaped = c == '\\';
    }
    cells.push(inner[start..].trim());
    cells
}

#[cfg(test)]
mod tests {
    use super::{parse, rows};
    use crate::Runtime;

    #[test]
    fn a_row_names_its_runtime_and_a_planned_one_is_not_required() {
        let rows = parse(
            "| Metric | Type | Labels | Runtime | Meaning | Planned |\n\
             |---|---|---|---|---|---|\n\
             | `a` | counter | `kind` = `x`\\|`y` | both | A \\| B | |\n\
             | `b` | gauge | — | CRI-O | B | |\n\
             | `c` | gauge | — | containerd | C | M9 |\n",
        )
        .unwrap();
        let required = |runtime| {
            rows.iter()
                .filter(|row| row.required(runtime))
                .map(|row| row.name)
                .collect::<Vec<_>>()
        };
        assert_eq!(required(Runtime::Crio), ["a", "b"]);
        assert_eq!(required(Runtime::Containerd), ["a"]);
        assert!(rows[2].on(Runtime::Containerd) && !rows[2].on(Runtime::Crio));
    }

    #[test]
    fn a_table_without_the_runtime_column_or_a_row_with_another_runtime_is_refused() {
        assert!(parse("| Metric | Type | Labels | Meaning |\n").is_err());
        assert!(parse("| `a` | counter | — | docker | A |\n").is_err());
    }

    #[test]
    fn the_catalog_parses() {
        assert!(rows().unwrap().len() > 30);
    }
}
