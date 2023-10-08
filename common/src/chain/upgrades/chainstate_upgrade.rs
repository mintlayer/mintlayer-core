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

use crate::chain::tokens::TokenIssuanceVersion;

use super::Activate;

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct ChainstateUpgrade {
    token_issuance_version: TokenIssuanceVersion,
}

impl ChainstateUpgrade {
    pub fn new(token_issuance_version: TokenIssuanceVersion) -> Self {
        Self {
            token_issuance_version,
        }
    }

    pub fn token_issuance_version(&self) -> TokenIssuanceVersion {
        self.token_issuance_version
    }
}

impl Activate for ChainstateUpgrade {}
