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

use crypto::key::extended::ExtendedPublicKey;
use serialization::{Decode, Encode};

/// Account metadata that contains information like from which master key it was derived from
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum AccountInfo {
    #[codec(index = 0)]
    Deterministic(DeterministicAccountInfo),
}

/// Serialized data for deterministic accounts. The fields are documented in `AccountKeyChain`.
// TODO tbd what metadata we need to store
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct DeterministicAccountInfo {
    root_hierarchy_key: Option<ExtendedPublicKey>,
    account_key: ExtendedPublicKey,
    lookahead_size: u32,
}

impl DeterministicAccountInfo {
    pub fn new(
        root_hierarchy_key: Option<ExtendedPublicKey>,
        account_key: ExtendedPublicKey,
        lookahead_size: u32,
    ) -> Self {
        Self {
            root_hierarchy_key,
            account_key,
            lookahead_size,
        }
    }

    pub fn root_hierarchy_key(&self) -> &Option<ExtendedPublicKey> {
        &self.root_hierarchy_key
    }

    pub fn account_key(&self) -> &ExtendedPublicKey {
        &self.account_key
    }

    pub fn lookahead_size(&self) -> u32 {
        self.lookahead_size
    }
}
