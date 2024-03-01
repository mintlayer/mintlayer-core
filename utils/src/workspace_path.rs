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
pub fn workspace_path() -> &'static str {
    env!("WORKSPACE_PATH")
}

/// Given a path to a source file, such as one obtained from std::panic::Location::file(),
/// try to make it relative to the workspace; if that is impossible for any reason,
/// return the original path.
///
/// The purpose of this function is to shorten file paths before printing them to the log.
///
/// Note: std::panic::Location::caller().file() may return an absolute or a relative path,
/// depending on the circumstances (it looks like the result depends on whether the file belongs
/// to the package where the binary crate is located - if it does, a relative path is returned,
/// if not, an absolute one is).
pub fn relative_src_file_path(src_file_path: &str) -> &str {
    // Note: the passed path is not suitable for passing to Path::new, because it was obtained
    // on the build machine, which may use the other path separator (if we're cross-compiling).
    src_file_path.strip_prefix(workspace_path()).unwrap_or(src_file_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workspace_path() {
        // Note:  file!() and std::panic::Location::caller().file() will return relative paths
        // inside the test, so we can't use them for testing here.

        let cargo_utils_toml_dir = env!("CARGO_MANIFEST_DIR");
        assert_eq!(cargo_utils_toml_dir, format!("{}utils", workspace_path()));
        assert_eq!(relative_src_file_path(cargo_utils_toml_dir), "utils");
    }
}
