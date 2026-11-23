//! What falls through on containerd after a body failed.

use super::*;

fn digest(n: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
}

#[tokio::test(start_paused = true)]
async fn a_blob_whose_body_failed_falls_through_for_a_minute() {
    let broken = Broken::default();
    assert!(!broken.holds(&digest(1)));
    broken.mark(digest(1));
    assert!(broken.holds(&digest(1)));
    assert!(!broken.holds(&digest(2)));
    let tick = Duration::from_millis(1);
    tokio::time::advance(BROKEN_FOR.checked_sub(tick).unwrap()).await;
    assert!(broken.holds(&digest(1)));
    tokio::time::advance(tick).await;
    assert!(!broken.holds(&digest(1)));
    // Forgotten once over, not only ignored.
    assert!(broken.0.lock().unwrap().is_empty());
}

#[test]
fn a_body_dropped_before_it_is_sent_marks_its_blob_broken() {
    let broken = Broken::default();
    let sent = Unsent {
        digest: digest(1),
        broken: broken.clone(),
        sent: true,
    };
    drop(sent);
    assert!(broken.0.lock().unwrap().is_empty());
    drop(Unsent {
        digest: digest(2),
        broken: broken.clone(),
        sent: false,
    });
    assert!(broken.0.lock().unwrap().contains_key(&digest(2)));
}
