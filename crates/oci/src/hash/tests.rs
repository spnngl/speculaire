use super::*;

#[test]
fn every_algorithm_a_digest_may_name_hashes_to_its_known_value() {
    for (name, hex) in [
        (
            "sha256",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "sha384",
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        ),
        (
            "sha512",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
    ] {
        let digest = of(name, b"abc").expect("a known algorithm");
        assert_eq!(digest.to_string(), format!("{name}:{hex}"));
    }
    assert!(of("md5", b"abc").is_none());
}

#[test]
fn a_hash_matches_only_the_content_of_its_digest() {
    let expected = of("sha256", b"abc").expect("a known algorithm");
    let mut hash = Hash::new(&expected).expect("a known algorithm");
    hash.update(b"ab");
    assert!(!hash.matches());
    hash.update(b"c");
    assert!(hash.matches());
    hash.update(b"d");
    assert!(!hash.matches());
}
