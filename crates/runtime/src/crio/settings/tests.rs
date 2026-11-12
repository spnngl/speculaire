//! What preflight and the required plugins say of a CRI-O on a temporary tree.

use crate::crio::CriO;
use crate::detect::Runtime;
use crate::fixture::{Tree, has};
use crate::paths::Paths;

#[test]
fn the_validator_names_the_plugins_it_requires() {
    let node = Tree::configured(Runtime::CriO);
    assert_eq!(
        node.node.settings().required_plugins().unwrap().plugins,
        Vec::<String>::new()
    );
    node.nri(true, false, &["other", "speculaire"]);
    let required = node.node.settings().required_plugins().unwrap();
    assert_eq!(required.runtime, "cri-o");
    assert!(
        required.key.contains("nri_validator_required_plugins"),
        "{required:?}"
    );
    assert_eq!(required.plugins, ["other", "speculaire"]);
    // CRI-O that does not answer is an error, not no plugin.
    node.update(|answers| answers.crio_config = None);
    let err = node.node.settings().required_plugins().unwrap_err();
    assert!(
        err.to_string().contains("cannot read CRI-O's config"),
        "{err}"
    );
}

#[test]
fn crios_nri_that_is_off_or_closed_and_a_missing_drop_in_are_refused() {
    let node = Tree::configured(Runtime::CriO);
    node.nri(false, false, &[]);
    let problems = node.preflight();
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        has(
            &problems,
            &[
                "/run/cri-o.sock",
                "`enable_nri = false` in [crio.nri]",
                "set it to true",
                "(D54, D64)"
            ]
        ),
        "{problems:?}"
    );
    node.nri(true, true, &[]);
    assert!(has(
        &node.preflight(),
        &[
            "`nri_disable_connections = true` in [crio.nri]",
            "set it to false"
        ]
    ));
    node.nri(false, true, &[]);
    assert_eq!(node.preflight().len(), 2);
    node.nri(true, false, &[]);
    node.update(|answers| answers.crio_config = None);
    assert!(has(
        &node.preflight(),
        &["/run/cri-o.sock", "CRI-O's inspect API answered"]
    ));
    node.nri(true, false, &[]);
    std::fs::remove_file(node.crio_dropin()).unwrap();
    let problems = node.preflight();
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        has(
            &problems,
            &[
                "/etc/containers/registries.conf.d/99-speculaire.conf",
                "is missing",
                "run `speculaire configure`"
            ]
        ),
        "{problems:?}"
    );
}

#[test]
fn a_problem_that_check_and_preflight_both_find_is_the_same_problem() {
    // `check-config` reports each once because the two say it alike.
    let node = Tree::configured(Runtime::CriO);
    std::fs::remove_file(node.crio_dropin()).unwrap();
    std::fs::remove_dir_all(node.dir.path().join("var/lib/speculaire/mirror")).unwrap();
    node.nri(false, false, &[]);
    let preflight = node.preflight();
    let check = node.check();
    assert_eq!(preflight.len(), 3, "{preflight:?}");
    assert!(
        has(&preflight, &["enable_nri"])
            && has(&preflight, &["ca.crt"])
            && has(&preflight, &["99-speculaire.conf"])
    );
    assert_eq!(check.len(), 2, "{check:?}");
    assert!(check.iter().all(|problem| preflight.contains(problem)));
    // A problem only `check` finds: a drop-in that differs.
    let node = Tree::configured(Runtime::CriO);
    crate::fixture::put(&node.crio_dropin(), "# edited\n");
    let check = node.check_all().unwrap();
    assert!(
        check.iter().any(|p| p
            .message
            .contains("differs from what `speculaire configure` writes")),
        "{check:?}"
    );
    assert!(
        node.node
            .settings()
            .preflight()
            .iter()
            .all(|p| !p.message.contains("differs from what")),
    );
}

#[test]
fn crios_inspect_api_that_does_not_exist_is_an_error() {
    let node = Tree::new(Runtime::CriO);
    let crio = CriO::new(
        Paths::under(node.dir.path()),
        "/nonexistent/crio.sock",
        "systemctl",
    );
    assert!(crio.nri().is_err());
}
