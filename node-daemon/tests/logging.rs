// Copyright (c) 2021-2026 RBB S.r.l
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

//! End-to-end checks of the logging options: the node is started in regtest mode with logging
//! to a file and the file it writes is inspected.

use std::{
    fs::File,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

use serde_json::Value as JsonValue;
use tempfile::TempDir;

const BIN_NAME: &str = env!("CARGO_BIN_EXE_node-daemon");
const CONFIG_NAME: &str = "config.toml";

/// A regtest node run with networking and rpc disabled, so that tests can start it without
/// conflicting with anything listening on the default ports.
struct TestNode {
    data_dir: TempDir,
    stderr_path: PathBuf,
}

impl TestNode {
    fn new() -> Self {
        let data_dir = TempDir::new().unwrap();
        let stderr_path = data_dir.path().join("stderr.log");
        Self {
            data_dir,
            stderr_path,
        }
    }

    fn data_dir(&self) -> &Path {
        self.data_dir.path()
    }

    /// The node command line: `logging_args` are the top-level options, followed by the
    /// regtest subcommand.
    fn command(&self, logging_args: &[&str]) -> Command {
        let mut cmd = Command::new(BIN_NAME);
        cmd.arg("--datadir").arg(self.data_dir()).args(logging_args).args([
            "regtest",
            // Harmless when not run as root, required when the tests are.
            "--force-allow-run-as-root",
            "--rpc-enabled",
            "false",
            "--p2p-networking-enabled",
            "false",
        ]);
        cmd
    }

    /// Runs the node until `log_file` has at least `min_lines` lines, then stops it. Returns
    /// the log file contents and the pid the node ran with.
    fn run_until_logged(
        &self,
        logging_args: &[&str],
        log_file: &Path,
        min_lines: usize,
    ) -> (String, u32) {
        let stderr = File::create(&self.stderr_path).unwrap();
        let mut child = self
            .command(logging_args)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap();
        let pid = child.id();

        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if let Ok(contents) = std::fs::read_to_string(log_file)
                && contents.lines().count() >= min_lines
            {
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                panic!(
                    "the node exited early with {status}; stderr:\n{}",
                    self.stderr()
                );
            }
            assert!(
                Instant::now() < deadline,
                "the node did not write {min_lines} lines to the log file in time; stderr:\n{}",
                self.stderr()
            );
            std::thread::sleep(Duration::from_millis(50));
        }

        // The node may have exited by itself already; stopping it is best-effort.
        let _ = child.kill();
        let _ = child.wait();
        (std::fs::read_to_string(log_file).unwrap(), pid)
    }

    /// Runs the node to completion and returns its output.
    fn run_to_completion(&self, logging_args: &[&str]) -> Output {
        let mut cmd = self.command(logging_args);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        cmd.output().unwrap()
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }
}

fn json_events(log: &str) -> Vec<JsonValue> {
    log.lines()
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|err| panic!("line {line:?} is not json: {err}"))
        })
        .collect()
}

#[test]
fn json_file_sink_carries_the_enrichment_fields() {
    let node = TestNode::new();
    let log_file = node.data_dir().join("node.jsonl");
    let log_file_str = log_file.to_str().unwrap();

    let (log, pid) = node.run_until_logged(
        &[
            "--log-to-file",
            "true",
            "--log-file-path",
            log_file_str,
            "--log-file-format",
            "json",
            "--log-fields",
            "role=seed",
            "--log-source-location",
            "true",
            "--log-thread-info",
            "true",
        ],
        &log_file,
        // Past the subsystem start lines, which are emitted from the tokio worker threads.
        20,
    );

    let events = json_events(&log);
    // The startup lines are emitted on the main thread, which is where the enrichment span
    // is entered (see `enter_root_span`).
    let main_thread_events: Vec<_> =
        events.iter().filter(|event| event["threadName"] == "main").collect();
    assert!(main_thread_events.len() >= 3, "{log}");

    for event in &main_thread_events {
        assert!(event["timestamp"].is_string(), "{event}");
        assert!(event["level"].is_string(), "{event}");
        assert!(event["fields"]["message"].is_string(), "{event}");
        assert!(event["filename"].is_string(), "{event}");
        assert!(event["line_number"].is_u64(), "{event}");
        assert!(event["threadId"].is_string(), "{event}");

        let spans = event["spans"].as_array().unwrap_or_else(|| panic!("{event}"));
        assert_eq!(spans.len(), 1, "{event}");
        assert_eq!(spans[0]["name"], "node", "{event}");
        assert!(!spans[0]["version"].as_str().unwrap().is_empty(), "{event}");
        assert_eq!(spans[0]["chain"], "regtest", "{event}");
        assert_eq!(spans[0]["pid"], pid, "{event}");
        assert_eq!(spans[0]["role"], "seed", "{event}");
    }

    assert!(
        main_thread_events.iter().any(|event| event["fields"]["message"]
            .as_str()
            .is_some_and(|message| message.starts_with("Starting mintlayer-core version"))),
        "{log}"
    );

    // The subsystem tasks are started inside the span that is current on the main thread,
    // so their lines, emitted on a tokio worker thread, carry the enrichment too.
    let subsystem_start = events
        .iter()
        .find(|event| {
            event["fields"]["message"].as_str().is_some_and(|message| {
                message.starts_with("Subsystem mintlayer/chainstate starting")
            })
        })
        .unwrap_or_else(|| panic!("{log}"));
    assert_ne!(subsystem_start["threadName"], "main", "{subsystem_start}");
    let spans = subsystem_start["spans"]
        .as_array()
        .unwrap_or_else(|| panic!("{subsystem_start}"));
    assert_eq!(spans.len(), 1, "{subsystem_start}");
    assert_eq!(spans[0]["name"], "node", "{subsystem_start}");
    assert_eq!(spans[0]["pid"], pid, "{subsystem_start}");
}

#[test]
fn text_file_sink_keeps_the_legacy_layout() {
    let node = TestNode::new();
    let log_file = node.data_dir().join("node.log");
    let log_file_str = log_file.to_str().unwrap();

    let (log, pid) = node.run_until_logged(
        &["--log-to-file", "true", "--log-file-path", log_file_str],
        &log_file,
        5,
    );

    let mut event_lines = 0;
    for line in log.lines() {
        assert!(!line.contains('\x1b'), "{line}");
        if !line.starts_with(|c: char| c.is_ascii_digit()) {
            // A continuation of a multi-line message (the pretty-printed config), not an event.
            continue;
        }
        event_lines += 1;
        // Timestamp, level, then the span prefixes and the target.
        assert!(
            line.contains(" INFO ") || line.contains(" WARN ") || line.contains(" ERROR "),
            "{line}"
        );
        assert!(!line.starts_with('{'), "{line}");
    }
    assert!(event_lines >= 5, "{log}");

    // The text lines of the main thread carry the enrichment as a compact span prefix in
    // front of the target; the rest of the layout is the legacy one.
    let startup_line = log
        .lines()
        .find(|line| line.contains("Starting mintlayer-core version"))
        .unwrap_or_else(|| panic!("{log}"));
    assert!(
        startup_line.contains(" INFO node{version=\""),
        "{startup_line}"
    );
    assert!(
        startup_line.contains(&format!(
            " chain=\"regtest\" pid={pid}}}: node_lib::runner: Starting mintlayer-core version"
        )),
        "{startup_line}"
    );
}

#[test]
fn relative_log_file_path_is_resolved_against_the_data_dir() {
    let node = TestNode::new();
    let log_file = node.data_dir().join("logs").join("relative.jsonl");

    let (log, _) = node.run_until_logged(
        &["--log-to-file", "true", "--log-file-path", "logs/relative.jsonl"],
        &log_file,
        2,
    );

    assert!(log.contains("Starting mintlayer-core version"), "{log}");
}

#[test]
fn logging_config_file_section_is_applied() {
    let node = TestNode::new();
    std::fs::write(
        node.data_dir().join(CONFIG_NAME),
        "[logging]\n\
         log_to_file = true\n\
         log_file_path = \"from-config.jsonl\"\n\
         log_file_format = \"json\"\n\
         log_fields = [\"source=config\"]\n",
    )
    .unwrap();
    let log_file = node.data_dir().join("from-config.jsonl");

    // No logging command line options: everything comes from the config file.
    let (log, _) = node.run_until_logged(&[], &log_file, 5);

    let events = json_events(&log);
    let enriched = events
        .iter()
        .find(|event| event["spans"].as_array().is_some_and(|spans| !spans.is_empty()))
        .unwrap_or_else(|| panic!("{log}"));
    assert_eq!(enriched["spans"][0]["source"], "config", "{log}");
}

#[test]
fn unwritable_log_file_path_is_a_startup_error() {
    let node = TestNode::new();
    // A regular file where the log directory would have to be created.
    let blocker = node.data_dir().join("blocker");
    File::create(&blocker).unwrap();

    let output = node.run_to_completion(&[
        "--log-to-file",
        "true",
        "--log-file-path",
        blocker.join("node.log").to_str().unwrap(),
    ]);

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to create the log file directory"),
        "stderr: {stderr}"
    );
}

#[test]
fn logging_config_file_values_are_validated() {
    let node = TestNode::new();
    std::fs::write(
        node.data_dir().join(CONFIG_NAME),
        "[logging]\nlog_to_file = true\nlog_file_max_files = 0\n",
    )
    .unwrap();

    let output = node.run_to_completion(&[]);

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("log_file_max_files"), "stderr: {stderr}");
}
