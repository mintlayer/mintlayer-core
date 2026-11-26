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

//! Logging settings resolved from the command line options and the `[logging]` config section.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use logging::LogFormat;

use crate::{
    config_files::LoggingConfigFile,
    options::{TopLevelOptions, parse_log_field},
};

/// Default size of the log file at which it is rotated.
pub const DEFAULT_LOG_FILE_MAX_SIZE_BYTES: u64 = 10_000_000;

/// Default number of log files kept by rotation, including the one being written to.
pub const DEFAULT_LOG_FILE_MAX_FILES: u64 = 14;

/// Logging settings with every value resolved.
///
/// A value given on the command line wins over the `[logging]` config section, which wins over
/// the defaults. The default of `log_to_file` is the one of node-daemon (`false`) unless
/// [`LoggingOptions::resolve_with_default`] is told otherwise, as node-gui does. The stderr
/// format has no default: when neither source sets it, the `ML_LOG_STYLE` env variable applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggingOptions {
    pub log_to_file: bool,
    pub log_file_path: Option<PathBuf>,
    pub log_file_format: LogFormat,
    pub log_format: Option<LogFormat>,
    pub log_file_max_size_bytes: u64,
    pub log_file_max_files: u64,
    pub log_fields: Vec<(String, String)>,
    pub log_source_location: bool,
    pub log_thread_info: bool,
}

impl LoggingOptions {
    /// Resolves the settings from the command line options and the config section, with
    /// `log_to_file` off unless one of them turns it on.
    pub fn resolve(options: &TopLevelOptions, config: LoggingConfigFile) -> Result<Self> {
        Self::resolve_with_default(options, config, false)
    }

    /// Resolves the settings like [`resolve`](Self::resolve), with `log_to_file` defaulting
    /// to `default_log_to_file` when neither the command line nor the config section sets it.
    ///
    /// The default has to enter here rather than into the command line options: a default
    /// written there would win over the config section, like any command line value.
    pub fn resolve_with_default(
        options: &TopLevelOptions,
        config: LoggingConfigFile,
        default_log_to_file: bool,
    ) -> Result<Self> {
        let LoggingConfigFile {
            log_to_file,
            log_file_path,
            log_file_format,
            log_format,
            log_file_max_size_bytes,
            log_file_max_files,
            log_fields,
            log_source_location,
            log_thread_info,
        } = config;

        let log_file_format =
            resolve_format(options.log_file_format, log_file_format, "log_file_format")?
                .unwrap_or(LogFormat::Text);
        let log_format = resolve_format(options.log_format, log_format, "log_format")?;

        let log_file_max_size_bytes = options
            .log_file_max_size_bytes
            .or(log_file_max_size_bytes)
            .unwrap_or(DEFAULT_LOG_FILE_MAX_SIZE_BYTES);
        let log_file_max_files = options
            .log_file_max_files
            .or(log_file_max_files)
            .unwrap_or(DEFAULT_LOG_FILE_MAX_FILES);
        // The command line parser rejects smaller values, but they would make the rotation
        // panic, so the config file is checked here as well.
        anyhow::ensure!(
            log_file_max_size_bytes >= 1,
            "`[logging] log_file_max_size_bytes` must be at least 1, got {log_file_max_size_bytes}"
        );
        anyhow::ensure!(
            log_file_max_files >= 1,
            "`[logging] log_file_max_files` must be at least 1, got {log_file_max_files}"
        );

        let log_fields = match options.log_fields.clone() {
            Some(fields) => fields,
            None => log_fields
                .unwrap_or_default()
                .iter()
                .map(|entry| {
                    parse_log_field(entry).map_err(|err| {
                        anyhow::anyhow!("invalid `[logging] log_fields` entry {entry:?}: {err}")
                    })
                })
                .collect::<Result<_>>()?,
        };

        Ok(Self {
            log_to_file: options.log_to_file.or(log_to_file).unwrap_or(default_log_to_file),
            log_file_path: options.log_file_path.clone().or(log_file_path),
            log_file_format,
            log_format,
            log_file_max_size_bytes,
            log_file_max_files,
            log_fields,
            log_source_location: options
                .log_source_location
                .or(log_source_location)
                .unwrap_or(false),
            log_thread_info: options.log_thread_info.or(log_thread_info).unwrap_or(false),
        })
    }

    /// The path of the log file of a node running in `data_dir`.
    ///
    /// The configured path is used as is when absolute and resolved against the data directory
    /// when relative; without one, the default is `<data dir>/logs/<default_log_file_name>`.
    pub fn log_file_path(&self, data_dir: &Path, default_log_file_name: &str) -> PathBuf {
        match &self.log_file_path {
            Some(path) if path.is_absolute() => path.clone(),
            Some(path) => data_dir.join(path),
            None => data_dir.join("logs").join(default_log_file_name),
        }
    }
}

/// Picks the format from the command line or, when absent, parses the config file value.
fn resolve_format(
    cli: Option<LogFormat>,
    file: Option<String>,
    name: &str,
) -> Result<Option<LogFormat>> {
    match (cli, file) {
        (Some(cli), _) => Ok(Some(cli)),
        (None, None) => Ok(None),
        (None, Some(value)) => value
            .parse()
            .map(Some)
            .with_context(|| format!("invalid value for `[logging] {name}`: {value:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config_files::NodeConfigFile,
        options::logging_options_test_support::{clear_logging_env_vars, parse_top_level_options},
    };

    fn config_from_toml(toml: &str) -> LoggingConfigFile {
        toml::from_str::<NodeConfigFile>(toml)
            .unwrap()
            .logging
            .expect("the fixture has a [logging] section")
    }

    fn default_options() -> LoggingOptions {
        LoggingOptions::resolve(&default_cli_options(), LoggingConfigFile::default()).unwrap()
    }

    fn default_cli_options() -> TopLevelOptions {
        parse_top_level_options(&[])
    }

    #[test]
    #[serial_test::serial]
    fn defaults() {
        clear_logging_env_vars();
        let options = default_options();

        assert_eq!(
            options,
            LoggingOptions {
                log_to_file: false,
                log_file_path: None,
                log_file_format: LogFormat::Text,
                log_format: None,
                log_file_max_size_bytes: DEFAULT_LOG_FILE_MAX_SIZE_BYTES,
                log_file_max_files: DEFAULT_LOG_FILE_MAX_FILES,
                log_fields: Vec::new(),
                log_source_location: false,
                log_thread_info: false,
            }
        );
        assert_eq!(options.log_file_max_size_bytes, 10_000_000);
        assert_eq!(options.log_file_max_files, 14);
    }

    #[test]
    #[serial_test::serial]
    fn file_only() {
        clear_logging_env_vars();
        let config = config_from_toml(
            "[logging]\n\
             log_to_file = true\n\
             log_file_path = \"logs/custom.log\"\n\
             log_file_format = \"json\"\n\
             log_format = \"json\"\n\
             log_file_max_size_bytes = 1234\n\
             log_file_max_files = 3\n\
             log_fields = [\"role=seed\", \"dc=eu\"]\n\
             log_source_location = true\n\
             log_thread_info = true\n",
        );

        let options = LoggingOptions::resolve(&default_cli_options(), config).unwrap();

        assert_eq!(
            options,
            LoggingOptions {
                log_to_file: true,
                log_file_path: Some("logs/custom.log".into()),
                log_file_format: LogFormat::Json,
                log_format: Some(LogFormat::Json),
                log_file_max_size_bytes: 1234,
                log_file_max_files: 3,
                log_fields: vec![
                    ("role".to_owned(), "seed".to_owned()),
                    ("dc".to_owned(), "eu".to_owned())
                ],
                log_source_location: true,
                log_thread_info: true,
            }
        );
    }

    #[test]
    #[serial_test::serial]
    fn cli_only() {
        clear_logging_env_vars();
        let cli = parse_top_level_options(&[
            "--log-to-file",
            "true",
            "--log-file-format",
            "json",
            "--log-format",
            "json",
            "--log-file-max-files",
            "5",
            "--log-fields",
            "role=seed",
            "--log-thread-info",
            "true",
        ]);

        let options = LoggingOptions::resolve(&cli, LoggingConfigFile::default()).unwrap();

        assert!(options.log_to_file);
        assert_eq!(options.log_file_format, LogFormat::Json);
        assert_eq!(options.log_format, Some(LogFormat::Json));
        assert_eq!(options.log_file_max_files, 5);
        assert_eq!(
            options.log_fields,
            vec![("role".to_owned(), "seed".to_owned())]
        );
        assert!(options.log_thread_info);
        // Untouched values keep their defaults.
        assert_eq!(options.log_file_path, None);
        assert_eq!(
            options.log_file_max_size_bytes,
            DEFAULT_LOG_FILE_MAX_SIZE_BYTES
        );
        assert!(!options.log_source_location);
    }

    #[test]
    #[serial_test::serial]
    fn cli_wins_over_file() {
        clear_logging_env_vars();
        let config = config_from_toml(
            "[logging]\n\
             log_to_file = false\n\
             log_file_path = \"from-file.log\"\n\
             log_file_format = \"json\"\n\
             log_format = \"json\"\n\
             log_file_max_size_bytes = 1\n\
             log_file_max_files = 2\n\
             log_fields = [\"role=file\"]\n\
             log_source_location = true\n\
             log_thread_info = true\n",
        );
        let cli = parse_top_level_options(&[
            "--log-to-file",
            "true",
            "--log-file-path",
            "from-cli.log",
            "--log-file-format",
            "text",
            "--log-format",
            "text",
            "--log-file-max-size-bytes",
            "7",
            "--log-file-max-files",
            "8",
            "--log-fields",
            "role=cli",
            "--log-source-location",
            "false",
            "--log-thread-info",
            "false",
        ]);

        let options = LoggingOptions::resolve(&cli, config).unwrap();

        assert_eq!(
            options,
            LoggingOptions {
                log_to_file: true,
                log_file_path: Some("from-cli.log".into()),
                log_file_format: LogFormat::Text,
                log_format: Some(LogFormat::Text),
                log_file_max_size_bytes: 7,
                log_file_max_files: 8,
                log_fields: vec![("role".to_owned(), "cli".to_owned())],
                log_source_location: false,
                log_thread_info: false,
            }
        );
    }

    #[test]
    #[serial_test::serial]
    fn file_wins_for_options_absent_from_cli() {
        clear_logging_env_vars();
        let config = config_from_toml(
            "[logging]\nlog_to_file = true\nlog_file_format = \"json\"\nlog_file_max_files = 3\n",
        );
        let cli = parse_top_level_options(&["--log-file-format", "text"]);

        let options = LoggingOptions::resolve(&cli, config).unwrap();

        assert!(options.log_to_file);
        assert_eq!(options.log_file_format, LogFormat::Text);
        assert_eq!(options.log_file_max_files, 3);
    }

    #[test]
    #[serial_test::serial]
    fn invalid_file_values_are_rejected() {
        clear_logging_env_vars();
        for (key, value) in [("log_file_max_files", "0"), ("log_file_max_size_bytes", "0")] {
            let err = LoggingOptions::resolve(
                &default_cli_options(),
                config_from_toml(&format!("[logging]\n{key} = {value}\n")),
            )
            .unwrap_err();
            assert!(err.to_string().contains(key), "{err}");
        }

        let bad_format = LoggingOptions::resolve(
            &default_cli_options(),
            config_from_toml("[logging]\nlog_file_format = \"jsn\"\n"),
        )
        .unwrap_err();
        assert!(
            bad_format.to_string().contains("log_file_format"),
            "{bad_format}"
        );

        let bad_field = LoggingOptions::resolve(
            &default_cli_options(),
            config_from_toml("[logging]\nlog_fields = [\"role=seed\", \"malformed\"]\n"),
        )
        .unwrap_err();
        assert!(bad_field.to_string().contains("malformed"), "{bad_field}");

        // A config file value that the command line overrides is never used, so it is not
        // validated either.
        let options = LoggingOptions::resolve(
            &parse_top_level_options(&["--log-file-max-files", "5"]),
            config_from_toml("[logging]\nlog_file_max_files = 0\n"),
        )
        .unwrap();
        assert_eq!(options.log_file_max_files, 5);
    }

    #[test]
    #[serial_test::serial]
    fn default_log_to_file_applies_below_cli_and_file() {
        clear_logging_env_vars();

        // node-gui logs to a file by default...
        let options = LoggingOptions::resolve_with_default(
            &default_cli_options(),
            LoggingConfigFile::default(),
            true,
        )
        .unwrap();
        assert!(options.log_to_file);

        // ...but the config file and the command line still win over the default.
        let options = LoggingOptions::resolve_with_default(
            &default_cli_options(),
            config_from_toml("[logging]\nlog_to_file = false\n"),
            true,
        )
        .unwrap();
        assert!(!options.log_to_file);

        let options = LoggingOptions::resolve_with_default(
            &parse_top_level_options(&["--log-to-file", "false"]),
            LoggingConfigFile::default(),
            true,
        )
        .unwrap();
        assert!(!options.log_to_file);

        let options = LoggingOptions::resolve_with_default(
            &parse_top_level_options(&["--log-to-file", "true"]),
            config_from_toml("[logging]\nlog_to_file = false\n"),
            true,
        )
        .unwrap();
        assert!(options.log_to_file);
    }

    /// The rejection of unknown keys inside the `[logging]` section is covered end to end by
    /// `read_logging_section_rejects_unknown_keys` in `tests/cli.rs`; this covers the section
    /// names, which are parsed here.
    #[test]
    fn unknown_sections_are_rejected() {
        let err = toml::from_str::<NodeConfigFile>("[loggingg]\nlog_to_file = true\n").unwrap_err();
        assert!(err.to_string().contains("loggingg"), "{err}");
    }

    #[test]
    fn log_file_path_resolution() {
        let data_dir = Path::new("/data/dir");
        let default_name = "mintlayerd.log";

        let mut options = LoggingOptions {
            log_to_file: false,
            log_file_path: None,
            log_file_format: LogFormat::Text,
            log_format: None,
            log_file_max_size_bytes: DEFAULT_LOG_FILE_MAX_SIZE_BYTES,
            log_file_max_files: DEFAULT_LOG_FILE_MAX_FILES,
            log_fields: Vec::new(),
            log_source_location: false,
            log_thread_info: false,
        };
        assert_eq!(
            options.log_file_path(data_dir, default_name),
            PathBuf::from("/data/dir/logs/mintlayerd.log")
        );

        options.log_file_path = Some("logs/node.jsonl".into());
        assert_eq!(
            options.log_file_path(data_dir, default_name),
            PathBuf::from("/data/dir/logs/node.jsonl")
        );

        options.log_file_path = Some("/var/log/node.jsonl".into());
        assert_eq!(
            options.log_file_path(data_dir, default_name),
            PathBuf::from("/var/log/node.jsonl")
        );
    }
}
