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

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The `[logging]` section of the node configuration file.
///
/// Every value is optional; an absent value means the corresponding command line option
/// applies, or the documented default when that is absent too. The section is merged with
/// the command line by [`LoggingOptions::resolve`](crate::LoggingOptions::resolve).
#[must_use]
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfigFile {
    /// Whether to log to a file.
    ///
    /// By default, this is enabled for node-gui and disabled for node-daemon.
    pub log_to_file: Option<bool>,

    /// Path of the log file used when logging to a file is enabled.
    ///
    /// A relative path is resolved against the data directory. If unset, the file is
    /// `<data dir>/logs/<executable name>.log`.
    pub log_file_path: Option<PathBuf>,

    /// Format of the log file: `text` or `json`.
    ///
    /// Defaults to `text`.
    pub log_file_format: Option<String>,

    /// Format of the log output written to stderr: `text` or `json`.
    ///
    /// If unset, the `ML_LOG_STYLE` env variable applies (plain text by default).
    pub log_format: Option<String>,

    /// Size of the log file at which it is rotated, in bytes.
    ///
    /// Defaults to 10000000.
    pub log_file_max_size_bytes: Option<u64>,

    /// Number of rotated log files to keep, including the one being written to.
    ///
    /// Defaults to 14. Must be at least 1.
    pub log_file_max_files: Option<u64>,

    /// Extra fields added to every log line, as a list of `"key=value"` strings.
    pub log_fields: Option<Vec<String>>,

    /// Whether to include the source file name and line number of every log line.
    ///
    /// Defaults to `false`.
    pub log_source_location: Option<bool>,

    /// Whether to include the thread id and thread name of every log line.
    ///
    /// Defaults to `false`.
    pub log_thread_info: Option<bool>,
}
