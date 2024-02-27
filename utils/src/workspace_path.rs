// Copyright (c) 2021-2024 RBB S.r.l
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

/// Return the path to the workspace, as it was recorded on the build machine. The path has
/// a trailing path separator.
///
/// Note that the path is produced by the build script using PathBuf::to_string_lossy, so if it
/// contained non-Unicode characters, this value will be an approximation rather than the exact
/// path itself.
pub fn workspace_path() -> &'static str {
    env!("WORKSPACE_PATH")
}

/// Given a path to a source file, such as one obtained from std::panic::Location::file(),
/// try to make it relative to the workspace; if that is impossible for any reason,
/// return the original path.
///
/// The purpose of this function is to shorten file paths before printing them to the log.
pub fn relative_src_file_path(src_file_path: &str) -> &str {
    // Note: the passed path may have been retrieved from std::panic::Location; if so,
    // it's not suitable for passing to Path::new (according to the docs), so we avoid that.
    src_file_path.strip_prefix(workspace_path()).unwrap_or(src_file_path)
}
