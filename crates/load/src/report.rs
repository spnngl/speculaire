//! The outcome of a load run: what was measured, against D33's targets.

use std::fmt::Write as _;
use std::time::Duration;

use crate::{Scenario, Targets};

/// What a run measured. A `None` was not measured: the run never got that far, or the value never came.
#[derive(Clone, Debug, Default)]
pub struct Measured {
    /// The reflector's peak resident set, `VmHWM` of `/proc/<pid>/status` before each stop, in bytes.
    pub peak_rss: Option<u64>,
    /// The resident set at the end of the steady phase, `VmRSS`, in bytes.
    pub steady_rss: Option<u64>,
    /// The p99 of `speculaire_reflector_lookup_seconds` over the steady phase: its bucket's upper bound.
    pub lookup_p99: Option<Duration>,
    /// The lookups the reflector answered per second over the steady phase.
    pub lookups_per_second: Option<f64>,
    /// The deltas the agents sent per second over the steady phase.
    pub deltas_per_second: Option<f64>,
    /// Lookups that failed over the steady phase, at the agents.
    pub failed_lookups: Option<u64>,
    /// From the first agent's start to the reflector holding every agent's digests.
    pub first_fill: Option<Duration>,
    /// From the reflector's restart to it holding every agent's digests again.
    pub resync: Option<Duration>,
}

/// A run's scenario, targets and measures; the targets missed are what fails it.
#[derive(Clone, Debug)]
pub struct Report {
    /// The load applied.
    pub scenario: Scenario,
    /// What it must meet.
    pub targets: Targets,
    /// What came out.
    pub measured: Measured,
    /// The CPUs this machine has, which the reflector and the agents share.
    pub cpus: usize,
}

/// How a measure fares against its target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Met,
    Missed,
    /// A goal, reported and never failing (D33).
    Goal(bool),
}

/// The share of the scenario's rates the run must reach for its other measures to hold.
const RATE_FLOOR: f64 = 0.95;

impl Report {
    /// Whether every target was met; goals do not count.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.rows().iter().all(|row| row.verdict != Verdict::Missed)
    }

    fn rows(&self) -> Vec<Row> {
        let (scenario, targets, measured) = (&self.scenario, &self.targets, &self.measured);
        let mib = |bytes: Option<u64>| bytes.map(|b| format!("{} MiB", b >> 20));
        let duration = |d: Option<Duration>| d.map(|d| format!("{d:.1?}"));
        let rate = |r: Option<f64>| r.map(|r| format!("{r:.0}/s"));
        let at_most = |value: Option<Duration>, target: Duration| {
            verdict(value.is_some_and(|value| value <= target))
        };
        let floor = |value: Option<f64>, target: u32| {
            verdict(value.is_some_and(|value| value >= f64::from(target) * RATE_FLOOR))
        };
        vec![
            Row {
                measure: "Reflector peak RSS",
                value: mib(measured.peak_rss),
                target: format!("≤ {} MiB", targets.rss >> 20),
                verdict: verdict(measured.peak_rss.is_some_and(|rss| rss <= targets.rss)),
            },
            Row {
                measure: "Reflector peak RSS, goal",
                value: mib(measured.peak_rss),
                target: format!("≤ {} MiB", targets.rss_goal >> 20),
                verdict: Verdict::Goal(
                    measured.peak_rss.is_some_and(|rss| rss <= targets.rss_goal),
                ),
            },
            Row {
                measure: "Lookup p99, server side",
                value: duration(measured.lookup_p99),
                target: format!("≤ {:?}", targets.lookup_p99),
                verdict: at_most(measured.lookup_p99, targets.lookup_p99),
            },
            Row {
                measure: "Resync after a reflector restart",
                value: duration(measured.resync),
                target: format!("≤ {:?}", targets.resync),
                verdict: at_most(measured.resync, targets.resync),
            },
            Row {
                measure: "Lookups answered",
                value: rate(measured.lookups_per_second),
                target: format!("≥ {:.0}/s", f64::from(scenario.lookups) * RATE_FLOOR),
                verdict: floor(measured.lookups_per_second, scenario.lookups),
            },
            Row {
                measure: "Deltas sent",
                value: rate(measured.deltas_per_second),
                target: format!("≥ {:.0}/s", f64::from(scenario.deltas) * RATE_FLOOR),
                verdict: floor(measured.deltas_per_second, scenario.deltas),
            },
        ]
    }

    /// The report as Markdown, for a terminal or a workflow's job summary.
    #[must_use]
    pub fn markdown(&self) -> String {
        let s = &self.scenario;
        let mut out = format!(
            "## Load: one reflector (D33)\n\n{} agents × {} blobs from {} digests, {} lookups/s and {} deltas/s for \
             {:?} after {:?} of warm-up, on {} CPUs.\n\n| Measure | Value | Target | Result |\n|---|---|---|---|\n",
            s.agents, s.blobs, s.pool, s.lookups, s.deltas, s.steady, s.warmup, self.cpus
        );
        for row in self.rows() {
            let result = match row.verdict {
                Verdict::Met => "met",
                Verdict::Missed => "**missed**",
                Verdict::Goal(true) => "goal met",
                Verdict::Goal(false) => "goal missed (reported only)",
            };
            let value = row.value.as_deref().unwrap_or("not measured");
            let _ = writeln!(
                out,
                "| {} | {value} | {} | {result} |",
                row.measure, row.target
            );
        }
        let m = &self.measured;
        let _ = write!(
            out,
            "\nAlso: RSS {} at the end of the steady phase; {} lookups failed at the agents; the first fill took {}.\n\n{}\n",
            m.steady_rss
                .map_or("not measured".into(), |b| format!("{} MiB", b >> 20)),
            m.failed_lookups
                .map_or("not measured".into(), |n| n.to_string()),
            m.first_fill
                .map_or("not measured".into(), |d| format!("{d:.1?}")),
            if self.passed() {
                "**Every target met.**"
            } else {
                "**A target was missed.**"
            }
        );
        out
    }
}

/// One line of the report's table.
struct Row {
    measure: &'static str,
    value: Option<String>,
    target: String,
    verdict: Verdict,
}

fn verdict(met: bool) -> Verdict {
    if met { Verdict::Met } else { Verdict::Missed }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(measured: Measured) -> Report {
        Report {
            scenario: Scenario::D33,
            targets: Targets::D33,
            measured,
            cpus: 4,
        }
    }

    fn meeting() -> Measured {
        Measured {
            peak_rss: Some(512 << 20),
            steady_rss: Some(500 << 20),
            lookup_p99: Some(Duration::from_micros(500)),
            lookups_per_second: Some(4750.0),
            deltas_per_second: Some(950.0),
            failed_lookups: Some(0),
            first_fill: Some(Duration::from_secs(12)),
            resync: Some(Duration::from_secs(60)),
        }
    }

    #[test]
    fn targets_met_at_their_bounds_pass_and_goals_never_fail() {
        let report = report(meeting());
        assert!(report.passed());
        let markdown = report.markdown();
        assert!(
            markdown.contains("| Reflector peak RSS | 512 MiB | ≤ 1024 MiB | met |"),
            "{markdown}"
        );
        assert!(
            markdown.contains("goal missed (reported only)"),
            "{markdown}"
        );
        assert!(markdown.contains("**Every target met.**"), "{markdown}");
        assert!(markdown.contains("on 4 CPUs"), "{markdown}");
    }

    #[test]
    fn each_target_missed_fails_the_run() {
        let misses: [fn(&mut Measured); 6] = [
            |m| m.peak_rss = Some((1 << 30) + 1),
            |m| m.lookup_p99 = Some(Duration::from_micros(501)),
            |m| m.resync = None,
            |m| m.resync = Some(Duration::from_millis(60_001)),
            |m| m.lookups_per_second = Some(4749.0),
            |m| m.deltas_per_second = None,
        ];
        for miss in misses {
            let mut measured = meeting();
            miss(&mut measured);
            let report = report(measured);
            assert!(!report.passed(), "{measured:?}", measured = report.measured);
            let markdown = report.markdown();
            assert!(markdown.contains("**missed**"), "{markdown}");
            assert!(markdown.contains("**A target was missed.**"), "{markdown}");
        }
    }

    #[test]
    fn the_goal_is_reported_when_met() {
        let mut measured = meeting();
        measured.peak_rss = Some(256 << 20);
        assert!(report(measured).markdown().contains("| goal met |"));
        let empty = report(Measured::default()).markdown();
        assert!(
            empty.contains("| Resync after a reflector restart | not measured |"),
            "{empty}"
        );
        assert!(empty.contains("RSS not measured"), "{empty}");
    }
}
