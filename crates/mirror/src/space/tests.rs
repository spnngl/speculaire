//! Claims on a small space.

use super::Space;

#[test]
fn claims_together_stay_within_the_bound_and_give_back_their_bytes_when_they_drop() {
    let space = Space::new(10);
    let six = space.claim(6).expect("6 of 10");
    assert!(space.claim(5).is_none(), "11 of 10");
    let mut four = space.claim(4).expect("10 of 10");
    assert_eq!(space.claimed(), 10);
    assert!(!four.grow(1), "11 of 10");
    assert_eq!(four.bytes(), 4);
    drop(six);
    assert_eq!(space.claimed(), 4);
    assert!(four.grow(6));
    assert_eq!(four.bytes(), 10);
    drop(four);
    assert_eq!(space.claimed(), 0);
}

#[test]
fn a_lowered_bound_refuses_the_next_claims_and_keeps_those_made() {
    let space = Space::new(10);
    let eight = space.claim(8).expect("8 of 10");
    space.set_max(5);
    assert_eq!(space.max(), 5);
    assert!(space.claim(0).is_none(), "8 of 5 already");
    drop(eight);
    assert!(space.claim(5).is_some());
}

#[test]
fn a_count_goes_past_the_bound_and_its_bytes_refuse_the_next_claims() {
    let space = Space::new(10);
    let mut count = space.count();
    count.add(12);
    assert_eq!(count.bytes(), 12);
    assert_eq!(space.claimed(), 12);
    assert!(space.claim(0).is_none(), "12 of 10");
    drop(count);
    assert_eq!(space.claimed(), 0);
    assert!(space.claim(10).is_some());
}

#[test]
fn a_claim_that_overflows_is_refused() {
    let space = Space::new(u64::MAX);
    let _most = space.claim(u64::MAX - 1).expect("within the bound");
    assert!(space.claim(2).is_none());
}
