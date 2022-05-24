//! Test harness for functional tests.
//!
//! This extracts information about location of node binaries and other configuration and passes it
//! to the functional test framework by means of environment variables and config files.
//! The framework is taken from Bitcoin and is written in Python. It is ultimately responsible for
//! running the tests. All command line arguments are forwarded to it.

use std::env::consts::EXE_SUFFIX;
use std::{
    env,
    ffi::{OsStr, OsString},
    path::Path,
    process::Command,
};

// Useful paths we get from Cargo
const NODE_BINARY: &str = env!("CARGO_BIN_EXE_test_node");
const TEMP_DIR: &str = env!("CARGO_TARGET_TMPDIR");
const CRATE_DIR: &str = env!("CARGO_MANIFEST_DIR");
const PACKAGE_NAME: &str = env!("CARGO_PKG_NAME");
const PACKAGE_URL: &str = env!("CARGO_PKG_HOMEPAGE");

#[derive(thiserror::Error)]
enum Error {
    #[error("Config file creation: {0}")]
    ConfigFile(std::io::Error),
    #[error("Test runner failed to run: {0}")]
    RunnerFailed(std::io::Error),
    #[error("Test runner was killed")]
    RunnerKilled,
    #[error("Tests failed (exit code {0})")]
    TestsFailed(i32),
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

fn main() -> Result<(), Error> {
    // Various derived paths
    let top_source_dir = Path::new(CRATE_DIR).parent().unwrap().to_str().unwrap();
    let binary_dir = Path::new(NODE_BINARY).parent().unwrap().to_str().unwrap();
    let config_file_path = Path::new(TEMP_DIR).join("config.ini");
    let runner_path = Path::new(CRATE_DIR).join("functional").join("test_runner.py");

    // Generate a config file
    let config_str = format!(
        r#"# Automatically generated DO NOT MODIFY

[environment]
PACKAGE_NAME={PACKAGE_NAME}
PACKAGE_BUGREPORT={PACKAGE_URL}
SRCDIR={top_source_dir}
BUILDDIR={binary_dir}
EXEEXT={EXE_SUFFIX}

[components]
# Which components are enabled.
ENABLE_BITCOIND=true
"#
    );
    std::fs::write(&config_file_path, config_str).map_err(Error::ConfigFile)?;

    // Environment to be passed to the Python test runner
    let env_vars = [
        ("MINTLAYER_NODE", NODE_BINARY),
        ("RUST_LOG", &env::var("RUST_LOG").unwrap_or_else(|_| "info".into())),
    ];
    let env_vars = env_vars.iter().map(|(n, v)| (OsStr::new(n), OsStr::new(v)));

    // Command line arguments
    let args = [
        format!("--configfile={}", config_file_path.display()),
        format!("--tmpdirprefix={}", TEMP_DIR),
    ]
    .into_iter()
    .map(OsString::from)
    .chain(env::args_os().skip(1));

    // Run the tests and get result
    let status = Command::new(runner_path)
        .args(args)
        .envs(env_vars)
        .status()
        .map_err(Error::RunnerFailed)?;

    if !status.success() {
        let status = status.code().ok_or(Error::RunnerKilled)?;
        return Err(Error::TestsFailed(status));
    }
    Ok(())
}
