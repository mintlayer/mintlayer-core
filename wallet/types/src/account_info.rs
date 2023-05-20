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

use crypto::key::{extended::ExtendedPublicKey, hdkd::u31::U31};
use serialization::{Decode, Encode};

pub const DEFAULT_ACCOUNT_INDEX: U31 = match U31::from_u32(0) {
    Some(v) => v,
    None => unreachable!(),
};

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
    account_index: U31,
    account_key: ExtendedPublicKey,
    lookahead_size: u32,
}

impl DeterministicAccountInfo {
    pub fn new(account_index: U31, account_key: ExtendedPublicKey, lookahead_size: u32) -> Self {
        Self {
            account_index,
            account_key,
            lookahead_size,
        }
    }

    pub fn account_index(&self) -> U31 {
        self.account_index
    }

    pub fn account_key(&self) -> &ExtendedPublicKey {
        &self.account_key
    }

    pub fn lookahead_size(&self) -> u32 {
        self.lookahead_size
    }
}
