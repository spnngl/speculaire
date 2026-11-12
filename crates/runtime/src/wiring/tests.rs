//! What a run prints.

use std::path::PathBuf;

use super::Problem;
use crate::files::Change;

#[test]
fn problems_and_changes_print_their_file() {
    let problem = Problem {
        path: PathBuf::from("/etc/x"),
        message: "is wrong".to_owned(),
    };
    assert_eq!(problem.to_string(), "/etc/x: is wrong");
    assert_eq!(
        Change::Removed(PathBuf::from("/a")).to_string(),
        "removed /a"
    );
}
