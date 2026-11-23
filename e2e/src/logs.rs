//! The agent's log entries, read alike from the journal and from its JSON lines (D200).
//!
//! Under systemd the agent logs to the journal, whose fields name its own `F_<FIELD>`; elsewhere it writes JSON lines,
//! whose fields are `fields.<field>`. Its stdout and stderr, such as its span timings and its exit error, are lines in
//! both. An [`Entry`] holds either the same way.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, SystemTime};

use serde_json::Value;

/// How severe an entry is, least first: `level >= Some(Level::Warn)` keeps warnings and errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// `TRACE`, journal priority 7.
    Trace,
    /// `DEBUG`, journal priority 6.
    Debug,
    /// `INFO`, journal priority 5.
    Info,
    /// `WARN`, journal priority 4.
    Warn,
    /// `ERROR`, journal priority 3 or less.
    Error,
}

impl Level {
    /// The level of a journal `PRIORITY`, as `tracing-journald` maps it.
    fn from_priority(priority: &str) -> Option<Self> {
        Some(match priority {
            "0" | "1" | "2" | "3" => Self::Error,
            "4" => Self::Warn,
            "5" => Self::Info,
            "6" => Self::Debug,
            "7" => Self::Trace,
            _ => return None,
        })
    }

    /// The level of a JSON line's `level`, as `tracing-subscriber` writes it.
    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "ERROR" => Self::Error,
            "WARN" => Self::Warn,
            "INFO" => Self::Info,
            "DEBUG" => Self::Debug,
            "TRACE" => Self::Trace,
            _ => return None,
        })
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        })
    }
}

/// One entry of the agent's logs: an event it logged, or a line it wrote outside them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// When the log received it, on the node's clock.
    pub at: SystemTime,
    /// `None` for a line outside the agent's logs, such as its exit error.
    pub level: Option<Level>,
    /// The event's message, or the whole line.
    pub message: String,
    /// The event's fields and its spans', by name in lower case with `.` as `_`, such as `image_name`; an event's
    /// field wins over its spans' of the same name.
    pub fields: BTreeMap<String, String>,
}

impl Entry {
    /// The field `name`, such as `image_name`.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    /// Parses a record of the journal's JSON export: the agent's event when it has a `TARGET`, otherwise a line of its
    /// stdout or stderr.
    ///
    /// # Errors
    ///
    /// When the record is no JSON object, or has no `__REALTIME_TIMESTAMP`.
    pub(crate) fn from_journal(record: &str) -> Result<Self, String> {
        let Ok(Value::Object(record)) = serde_json::from_str::<Value>(record) else {
            return Err(format!("no JSON object: {record}"));
        };
        let at = record
            .get("__REALTIME_TIMESTAMP")
            .and_then(text)
            .and_then(|micros| micros.parse().ok())
            .map(|micros| SystemTime::UNIX_EPOCH + Duration::from_micros(micros))
            .ok_or_else(|| format!("no __REALTIME_TIMESTAMP in {record:?}"))?;
        let message = record.get("MESSAGE").and_then(text).unwrap_or_default();
        if !record.contains_key("TARGET") {
            return Ok(Self::from_line(at, &message));
        }
        let fields = record
            .iter()
            .filter_map(|(name, value)| {
                Some((name.strip_prefix("F_")?.to_lowercase(), text(value)?))
            })
            .collect();
        Ok(Self {
            at,
            level: record
                .get("PRIORITY")
                .and_then(text)
                .and_then(|priority| Level::from_priority(&priority)),
            message,
            fields,
        })
    }

    /// Parses a line the agent wrote at `at`: an event when it is one of its JSON lines, otherwise the line itself.
    pub(crate) fn from_line(at: SystemTime, line: &str) -> Self {
        let event = serde_json::from_str::<Value>(line).ok().and_then(|value| {
            let Value::Object(mut event) = value else {
                return None;
            };
            let level = event
                .get("level")
                .and_then(Value::as_str)
                .and_then(Level::from_name)?;
            let Some(Value::Object(mut own)) = event.remove("fields") else {
                return None;
            };
            let message = own
                .remove("message")
                .as_ref()
                .and_then(text)
                .unwrap_or_default();
            // `spans` runs from the root to the current span, as the journal records them before the event's own.
            let mut fields = BTreeMap::new();
            if let Some(Value::Array(spans)) = event.get("spans") {
                for span in spans.iter().filter_map(Value::as_object) {
                    add(&mut fields, span.iter().filter(|(name, _)| *name != "name"));
                }
            }
            add(&mut fields, own.iter());
            Some(Self {
                at,
                level: Some(level),
                message,
                fields,
            })
        });
        event.unwrap_or_else(|| Self {
            at,
            level: None,
            message: line.to_owned(),
            fields: BTreeMap::new(),
        })
    }
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(level) = self.level {
            write!(f, "{level} ")?;
        }
        f.write_str(&self.message)?;
        self.fields
            .iter()
            .try_for_each(|(name, value)| write!(f, " {name}={value}"))
    }
}

/// The last `count` of `entries`, one a line, for a failure's message.
#[must_use]
pub fn tail(entries: &[Entry], count: usize) -> String {
    let skip = entries.len().saturating_sub(count);
    entries
        .iter()
        .skip(skip)
        .map(Entry::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Adds a JSON line's `fields` under the names the journal gives them, lower-cased.
fn add<'a>(
    into: &mut BTreeMap<String, String>,
    fields: impl Iterator<Item = (&'a String, &'a Value)>,
) {
    for (name, value) in fields {
        if let Some(value) = text(value) {
            into.insert(journal_name(name), value);
        }
    }
}

/// `name` as `tracing-journald` sanitizes it, `.` as `_` without leading `_`, in lower case.
fn journal_name(name: &str) -> String {
    name.chars()
        .map(|c| if c == '.' { '_' } else { c })
        .skip_while(|&c| c == '_')
        .filter(|&c| c == '_' || c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// A field's value as text: a journal field given several times, an array, has its last value, the event's.
fn text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Array(values) => values.last().and_then(text),
        Value::Null | Value::Object(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AT: u64 = 1_795_000_000_123_456;

    fn at() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_micros(AT)
    }

    fn fields(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    /// The warning of `crates/mirror/src/relay.rs` as the journal and as the JSON lines give it, inside a span.
    #[test]
    fn an_event_reads_the_same_from_the_journal_and_from_a_json_line() {
        let journal = Entry::from_journal(&format!(
            r#"{{"__REALTIME_TIMESTAMP":"{AT}","PRIORITY":"4","TARGET":"speculaire_mirror::relay",
               "SYSLOG_IDENTIFIER":"speculaire","SPAN_NAME":"pull","F_IMAGE_NAME":"app/web",
               "MESSAGE":"upstream limits the relay: CRI-O gets a 429","F_STATUS":"429","F_HOST":"limit.e2e.test"}}"#
        ))
        .unwrap();
        let line = Entry::from_line(
            at(),
            r#"{"timestamp":"2026-11-19T08:13:20.123456Z","level":"WARN","fields":{"message":"upstream limits the relay: CRI-O gets a 429","status":429,"host":"limit.e2e.test"},"target":"speculaire_mirror::relay","span":{"image.name":"app/web","name":"pull"},"spans":[{"image.name":"app/web","name":"pull"}]}"#,
        );
        let expected = Entry {
            at: at(),
            level: Some(Level::Warn),
            message: "upstream limits the relay: CRI-O gets a 429".to_owned(),
            fields: fields(&[
                ("host", "limit.e2e.test"),
                ("image_name", "app/web"),
                ("status", "429"),
            ]),
        };
        assert_eq!(journal, expected);
        assert_eq!(line, expected);
        assert_eq!(
            expected.to_string(),
            "WARN upstream limits the relay: CRI-O gets a 429 host=limit.e2e.test image_name=app/web status=429"
        );
    }

    #[test]
    fn an_event_field_wins_over_its_span_field_of_the_same_name() {
        let journal = Entry::from_journal(&format!(
            r#"{{"__REALTIME_TIMESTAMP":"{AT}","PRIORITY":"6","TARGET":"t","MESSAGE":"m","F_POD":["span","event"]}}"#
        ))
        .unwrap();
        let line = Entry::from_line(
            at(),
            r#"{"level":"DEBUG","fields":{"message":"m","pod":"event"},"target":"t","spans":[{"name":"s","pod":"span"}]}"#,
        );
        assert_eq!(journal.field("pod"), Some("event"));
        assert_eq!(line, journal);
    }

    /// The agent's stderr in the journal: a span timing, a JSON line, and its exit error.
    #[test]
    fn a_line_of_stderr_in_the_journal_reads_as_the_line_itself() {
        let timing = r#"{"timestamp":"t","level":"INFO","fields":{"message":"close","time.busy":"1.2ms"},"target":"speculaire_agent","span":{"name":"verify"}}"#;
        let record = serde_json::json!({
            "__REALTIME_TIMESTAMP": AT.to_string(),
            "PRIORITY": "6",
            "SYSLOG_IDENTIFIER": "speculaire",
            "MESSAGE": timing,
        });
        let journal = Entry::from_journal(&record.to_string()).unwrap();
        assert_eq!(journal, Entry::from_line(at(), timing));
        assert_eq!(journal.level, Some(Level::Info));
        assert_eq!(journal.field("time_busy"), Some("1.2ms"));

        let error = "error: the policy file /etc/speculaire/policy.yaml: document 1";
        let record = serde_json::json!({"__REALTIME_TIMESTAMP": AT.to_string(), "PRIORITY": "6", "MESSAGE": error});
        let journal = Entry::from_journal(&record.to_string()).unwrap();
        assert_eq!(
            journal,
            Entry {
                at: at(),
                level: None,
                message: error.to_owned(),
                fields: BTreeMap::new(),
            }
        );
        assert_eq!(journal.to_string(), error);
    }

    #[test]
    fn a_record_without_its_time_is_refused() {
        assert!(Entry::from_journal(r#"{"MESSAGE":"m"}"#).is_err());
        assert!(Entry::from_journal("not json").is_err());
    }

    #[test]
    fn levels_order_by_severity() {
        assert!(Some(Level::Error) > Some(Level::Warn));
        assert!(Some(Level::Info) < Some(Level::Warn));
        assert!(None < Some(Level::Trace));
    }
}
