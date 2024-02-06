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

use std::process::Command;

fn main() {
    let git_head_hash = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string());

    let git_tree_clean = Command::new("git")
        .args(["status", "--untracked-files=no", "--porcelain"])
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string());

    println!(
        "cargo:rustc-env=GIT_HEAD_HASH={}",
        git_head_hash.unwrap_or("".to_string())
    );
    println!(
        "cargo:rustc-env=GIT_TREE_CLEAN={}",
        git_tree_clean.unwrap_or("".to_string())
    );
}
