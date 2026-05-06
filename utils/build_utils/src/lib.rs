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

use std::process::Command;

use substrate_build_script_utils::rerun_if_git_head_changed;

pub fn emit_git_env_vars() {
    // Emit GIT_HEAD_HASH
    {
        let git_head_hash = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .map_or("".to_string(), |out| {
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            });

        // Sanity check
        assert!(git_head_hash.is_ascii());

        println!("cargo:rustc-env=GIT_HEAD_HASH={git_head_hash}");
    }

    // Rerun the build if the git head changes by emitting "cargo:rerun-if-changed" for certain
    // files in the git repo.
    // Note:
    // 1) Doing it manually is not trivial - you have to emit "rerun-if-changed" for both
    //    `.git/HEAD` and the corresponding ref file that HEAD refers to, and also handle work
    //    trees correctly. E.g. the popular crate `vergen`, which appears among the first when
    //    googling, doesn't do it properly (as of March 2026), so making a commit inside a work
    //    tree won't trigger a rebuild. `substrate_build_script_utils`, on the other hand, works
    //    fine.
    // 2) Emitting "rerun-if..." has a side-effect - it turns off the default rerunning rules,
    //    so the script will only be rerun if the things specified in "rerun-if..." were changed,
    //    but not when package's source code was changed.
    rerun_if_git_head_changed();

    // Note: it's also tempting to maintain an env var with the "dirty" flag based on whether
    // `git status --untracked-files=no --porcelain` returns anything or not, to use it as part
    // of the app version. Unfortunately, it doesn't seem to be possible to set it correctly
    // in a reliable way. E.g. due to "rerun-if-changed" being emitted by `rerun_if_git_head_changed`
    // above, the build script won't be rerun when a source file is changed in the package, so
    // the dirty flag is likely to be bogus on the developer's machine. On the other hand, if
    // we don't call `rerun_if_git_head_changed`, then the git head hash is likely to become
    // wrong on the developer's machine and the dirty flag, though correct, will become useless.
}
