// Copyright (c) 2023 RBB S.r.l
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

/// Get the Wallet version and optionally git hash
pub fn get_version() -> String {
    let git_head_hash = env!("GIT_HEAD_HASH");
    let git_tree_clean = env!("GIT_TREE_CLEAN");
    let version = env!("CARGO_PKG_VERSION");

    let version_string = version;

    // If the git hash is not available, we don't want to print anything
    let git_hash_string = if git_head_hash.trim().is_empty() {
        "".to_string()
    } else {
        format!("(HEAD hash: {})", git_head_hash)
    };

    // If the git tree is clean, we don't want to print anything
    let git_tree_clean_string = if git_tree_clean.trim().is_empty() {
        ""
    } else {
        "(dirty)"
    };

    [version_string, &git_hash_string, git_tree_clean_string]
        .iter()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect::<Vec<String>>()
        .join(" ")
}
