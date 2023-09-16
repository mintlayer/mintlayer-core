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
    let git_hash = env!("GIT_HASH");
    let version = env!("CARGO_PKG_VERSION");

    match git_hash {
        "" => version.to_owned(),
        git_hash => format!("{version} (HEAD hash: {git_hash})"),
    }
}
