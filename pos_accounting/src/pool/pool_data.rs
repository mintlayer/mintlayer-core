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

use common::primitives::Amount;
use crypto::key::PublicKey;
use serialization::{Decode, Encode};

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct PoolData {
    decommission_public_key: PublicKey,
    pledge_amount: Amount,
}

impl PoolData {
    pub fn new(decommission_public_key: PublicKey, pledge_amount: Amount) -> Self {
        Self {
            decommission_public_key,
            pledge_amount,
        }
    }

    pub fn decommission_key(&self) -> &PublicKey {
        &self.decommission_public_key
    }

    pub fn pledge_amount(&self) -> Amount {
        self.pledge_amount
    }
}
