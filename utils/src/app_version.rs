// Copyright (c) 2026 RBB S.r.l
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

use std::fmt::Write as _;

use crate::debug_panic_or_log;

// Note:
// 1) Here we extract the app version from the env var `CARGO_PKG_VERSION`, which contains
//    the version of the package that is currently being built.
//    Though technically each package may have its own distinct version, in this project we require
//    that all packages inherit their version from the workspace, which is enforced by `codecheck.py`.
// 2) `app_version_with_git_info` is a macro and not a function. This is because we want to force
//    a rebuild when the git head changes, but only for the packages that actually need the version
//    information. Making it a macro forces all packages that need it to define their own `build.rs`
//    and call `build_utils::emit_git_env_vars` from there, which will set the env var and force
//    the rebuild on git head change for that package only.

#[macro_export]
macro_rules! app_version_with_git_info {
    () => {{
        let version = env!("CARGO_PKG_VERSION");

        let git_head_hash = env!("GIT_HEAD_HASH").trim();
        let git_info = if !git_head_hash.is_empty() {
            Some($crate::app_version::AppVersionGitInfo {
                head_hash: git_head_hash,
            })
        } else {
            None
        };

        $crate::app_version::AppVersionWithGitInfo { version, git_info }
    }};
}

// The maximum number of hex digits from Git commit hash that we'll use as the build metadata.
// Note that currently 9 digits is enough to uniquely identify a commit in this repo, but we
// want to have some leeway.
const MAX_GIT_HASH_LEN: usize = 12;

pub struct AppVersionWithGitInfo {
    pub version: &'static str,
    pub git_info: Option<AppVersionGitInfo>,
}

impl AppVersionWithGitInfo {
    /// Produce a string of the kind "1.2.3 (HEAD hash: aabbccddeeff)".
    pub fn to_pretty_string(&self) -> String {
        let mut buf = String::new();

        let mut writer = || -> std::fmt::Result {
            write!(buf, "{}", self.version)?;

            if let Some(git_info) = &self.git_info {
                write!(buf, " (HEAD hash: {})", git_info.short_head_hash())?;
            }

            Ok(())
        };

        writer().expect("writing to a string cannot fail");

        buf
    }

    /// Produce a string of the kind "1.2.3+aabbccddeeff".
    pub fn to_semver_string(&self) -> String {
        let mut buf = String::new();

        let mut writer = || -> std::fmt::Result {
            write!(buf, "{}", self.version)?;

            if let Some(git_info) = &self.git_info {
                write!(buf, "+{}", git_info.short_head_hash())?;
            }

            Ok(())
        };

        writer().expect("writing to a string cannot fail");

        buf
    }
}

pub struct AppVersionGitInfo {
    pub head_hash: &'static str,
}

impl AppVersionGitInfo {
    fn short_head_hash(&self) -> &'static str {
        // Shouldn't happen, but a sanity check won't hurt.
        if !self.head_hash.is_char_boundary(MAX_GIT_HASH_LEN) {
            debug_panic_or_log!("Git hash '{}' is not an ascii string", self.head_hash);
            return self.head_hash;
        }

        #[allow(clippy::string_slice)]
        &self.head_hash[0..MAX_GIT_HASH_LEN]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        let version = AppVersionWithGitInfo {
            version: "12.34.56",
            git_info: None,
        };
        let version_str = version.to_pretty_string();
        assert_eq!(version_str, "12.34.56");
        let version_str = version.to_semver_string();
        assert_eq!(version_str, "12.34.56");

        let version = AppVersionWithGitInfo {
            version: "12.34.56",
            git_info: Some(AppVersionGitInfo {
                head_hash: "aabbccddeeff00aabbccddeeff00",
            }),
        };
        let version_str = version.to_pretty_string();
        assert_eq!(version_str, "12.34.56 (HEAD hash: aabbccddeeff)");
        let version_str = version.to_semver_string();
        assert_eq!(version_str, "12.34.56+aabbccddeeff");
    }
}
