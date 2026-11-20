use super::{Error, chain_id, of_config};
use crate::reference::Digest;

fn digest(c: char) -> Digest {
    Digest::parse(&format!("sha256:{}", c.to_string().repeat(64))).unwrap()
}

#[test]
fn one_layer_is_its_own_chain() {
    assert_eq!(chain_id(&[digest('a')]), Some(digest('a')));
}

#[test]
fn each_layer_hashes_the_chain_below_it() {
    // `printf 'sha256:aaa… sha256:bbb…' | sha256sum`, then the same with the result and `sha256:ccc…`.
    let ab = "sha256:ccd722928bd92476ba1745586fed6e45a102504185ad88cd89e01ff116fd146c";
    let abc = "sha256:c1377126441fb2f5ec2c21ae2a60255331d639e830f0ee1b40a36e52d4c40588";
    assert_eq!(
        chain_id(&[digest('a'), digest('b')]),
        Some(Digest::parse(ab).unwrap())
    );
    assert_eq!(
        chain_id(&[digest('a'), digest('b'), digest('c')]),
        Some(Digest::parse(abc).unwrap())
    );
}

#[test]
fn no_layer_has_no_chain() {
    assert_eq!(chain_id(&[]), None);
    assert!(matches!(
        of_config(br#"{"rootfs":{"type":"layers","diff_ids":[]}}"#),
        Err(Error::NoLayers)
    ));
}

#[test]
fn a_config_is_read_for_its_diff_ids() {
    let config = format!(
        r#"{{"architecture":"arm64","os":"linux","rootfs":{{"type":"layers","diff_ids":["{}","{}"]}}}}"#,
        digest('a'),
        digest('b')
    );
    assert_eq!(
        of_config(config.as_bytes()).unwrap(),
        chain_id(&[digest('a'), digest('b')]).unwrap()
    );
}

#[test]
fn a_config_without_good_diff_ids_has_no_chain() {
    assert!(matches!(of_config(b"{}"), Err(Error::Json(_))));
    assert!(matches!(
        of_config(br#"{"rootfs":{"diff_ids":["sha256:A"]}}"#),
        Err(Error::Digest(_))
    ));
}

/// Configs and the parents of their containers' snapshots, recorded from kind's worker on containerd 2.3.7 (overlayfs,
/// linux/arm64): an OCI index's image of 4 layers and a Docker manifest's of 3.
#[test]
fn recorded_configs_chain_to_their_snapshot_parents() {
    let recorded: [(&[u8], &str); 2] = [
        (
            include_bytes!("../../../../fuzz/seeds/image_config/kindnetd.json"),
            "sha256:37afd94ea68e7ab6fc4a8587a7eba02e8034b1f3d4de608c1d1dad86264352ff",
        ),
        (
            include_bytes!("../../../../fuzz/seeds/image_config/kube-proxy.json"),
            "sha256:324106405779531c28807ebeff9950c9554ac5859ca8c3e099b442bc5db442bc",
        ),
    ];
    for (config, parent) in recorded {
        assert_eq!(of_config(config).unwrap(), Digest::parse(parent).unwrap());
    }
}
