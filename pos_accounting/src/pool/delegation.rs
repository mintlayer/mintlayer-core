// Copyright (c) 2022 RBB S.r.l
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

use crypto::key::PublicKey;
use serialization::{Decode, Encode};

use crate::PoolId;

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct DelegationData {
    spend_key: PublicKey,
    source_pool: PoolId,
}

impl DelegationData {
    pub fn new(source_pool: PoolId, spend_key: PublicKey) -> Self {
        Self {
            spend_key,
            source_pool,
        }
    }

    pub fn spend_public_key(&self) -> &PublicKey {
        &self.spend_key
    }

    pub fn source_pool(&self) -> &PoolId {
        &self.source_pool
    }
}
