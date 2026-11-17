use std::time::Duration;

use speculaire_registry::Refusal;
use tokio::time::Instant;

use super::Pauses;

const HOST: &str = "registry.example";

fn after(seconds: u64) -> Refusal {
    Refusal {
        retry_after: Some(Duration::from_secs(seconds)),
    }
}

const SILENT: Refusal = Refusal { retry_after: None };

#[test]
fn a_host_is_paused_until_the_later_of_the_backoff_step_and_retry_after() {
    let pauses = Pauses::default();
    let now = Instant::now();
    assert_eq!(
        pauses.refused(HOST, after(120), now),
        now + Duration::from_secs(120)
    );
    // The second refusal in a row steps to 60 s, later than the 5 s asked.
    assert_eq!(
        pauses.refused(HOST, after(5), now),
        now + Duration::from_secs(60)
    );
}

#[test]
fn the_backoff_doubles_up_to_five_minutes_and_an_answer_starts_it_over() {
    let pauses = Pauses::default();
    let now = Instant::now();
    let steps: Vec<u64> = (0..7)
        .map(|_| (pauses.refused(HOST, SILENT, now) - now).as_secs())
        .collect();
    assert_eq!(steps, [30, 60, 120, 240, 300, 300, 300]);
    pauses.answered(HOST);
    assert_eq!(
        pauses.refused(HOST, SILENT, now),
        now + Duration::from_secs(30)
    );
}

#[test]
fn a_pause_lasts_one_hour_at_most() {
    let pauses = Pauses::default();
    let now = Instant::now();
    assert_eq!(
        pauses.refused(HOST, after(86_400), now),
        now + Duration::from_secs(3600)
    );
    assert_eq!(
        pauses.refused(HOST, after(u64::MAX), now),
        now + Duration::from_secs(3600)
    );
}

#[test]
fn a_pause_holds_its_host_only_and_ends_at_its_time() {
    let pauses = Pauses::default();
    let now = Instant::now();
    let until = pauses.refused(HOST, after(120), now);
    assert_eq!(pauses.until(HOST, now), Some(until));
    assert_eq!(
        pauses.until(HOST, until - Duration::from_secs(1)),
        Some(until)
    );
    assert_eq!(pauses.until(HOST, until), None);
    assert_eq!(pauses.until("other.example", now), None);
}
