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

/// Specify the rules for including a transaction in the mempool
#[derive(serde::Serialize, serde::Deserialize, PartialEq, PartialOrd, Ord, Eq, Debug)]
pub struct InclusionPolicy {
    /// Force the transaction in even if it conflicts with a existing ones.
    force_replace: bool,

    /// Bypass mempool policy checks
    bypass_checks: bool,
}

impl Default for InclusionPolicy {
    fn default() -> Self {
        Self {
            force_replace: false,
            bypass_checks: bool,
        }
    }
}
