// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Test harness for functional tests.
//!
//! This extracts information about location of node binaries and other configuration and passes it
//! to the functional test framework by means of environment variables and config files.
//! The framework is taken from Bitcoin and is written in Python. It is ultimately responsible for
//! running the tests. All command line arguments are forwarded to it.

use libtest_mimic::{run, Arguments as HarnessArgs, Failed, Trial};
use std::env::consts::EXE_SUFFIX;
use std::path::PathBuf;
use std::{env, ffi::OsString, path::Path, process::Command};

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
        write!(f, "{self}")
    }
}

fn get_executable_from_path_env_var<P>(exe_name: P) -> Option<PathBuf>
where
    P: AsRef<Path>,
{
    assert!(
        exe_name.as_ref().is_relative(),
        "Path provided for executable must be relative; {} was provided",
        exe_name.as_ref().display()
    );
    let path_env_var = env::var_os("PATH").expect("PATH env var not found");
    env::split_paths(&path_env_var)
        .filter_map(|dir| {
            let full_path = dir.join(&exe_name);
            full_path.is_file().then_some(full_path)
        })
        .next()
}

fn do_run(runner_args: &[OsString]) -> Result<(), Failed> {
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

    let possible_python_execs = ["python3", "python"];
    let python_exe = {
        let file_suffix = (env::consts::OS == "windows").then_some(".exe").unwrap_or_default();
        possible_python_execs
            .into_iter()
            .filter_map(|exe| get_executable_from_path_env_var(format!("{exe}{file_suffix}")))
            .next()
            .expect(&format!(
                "Unable to find any of the executables {:?} in PATH",
                possible_python_execs
            ))
    };

    println!("Found python executable in path: {}", python_exe.display());

    // Run the tests and get result
    let status = Command::new(python_exe)
        // Add environment variables
        .env("MINTLAYER_NODE", NODE_BINARY)
        .env(
            "RUST_LOG",
            &env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        )
        // Pass command-line arguments
        .arg(runner_path)
        .arg(format!("--configfile={}", config_file_path.display()))
        .arg(format!("--tmpdirprefix={TEMP_DIR}"))
        // Forward the rest of the arguments from this executable
        .args(runner_args)
        // Wait for exit status
        .status()
        .map_err(Error::RunnerFailed)?;

    if !status.success() {
        let status = status.code().ok_or(Error::RunnerKilled)?;
        return Err(format!("{:?}", Error::TestsFailed(status)).into());
    }
    Ok(())
}

fn main() {
    // Pre-process command line arguments
    let (harness_args, runner_args) = {
        let all_args: Vec<_> = env::args_os().collect();
        // Arguments before a '--' are harness options, test_runner.py options come after the '--'
        let mut arg_sections = all_args.splitn(2, |x| x == "--").fuse();
        let mut harness_args = HarnessArgs::from_iter(arg_sections.next().unwrap_or(&[]));
        let runner_args = arg_sections.next().map_or(Default::default(), |args| {
            // If arguments are explicitly passed to test_runner.py, run ignored tests
            harness_args.ignored = true;
            args.to_owned()
        });
        (harness_args, runner_args)
    };

    let functional_tests =
        Trial::test("functional", move || do_run(&runner_args)).with_ignored_flag(true);

    let outcome = run(&harness_args, vec![functional_tests]);

    outcome.exit()
}
