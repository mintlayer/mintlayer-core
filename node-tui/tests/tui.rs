use std::path::Path;

use assert_cmd::Command;

const BIN_NAME: &str = env!("CARGO_BIN_EXE_node-tui");

// This test is only needed because the node name ix hardcoded here, so if the name is changed we
// get an error that is easy to understand.
#[test]
fn node_path_is_correct() {
    assert!(Path::new(BIN_NAME).is_file());
}

#[test]
fn no_args() {
    Command::new(BIN_NAME).assert().failure();
}
