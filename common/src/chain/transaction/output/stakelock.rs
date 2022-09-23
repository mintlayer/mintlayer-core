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

use crypto::vrf::VRFPublicKey;
use serialization::{Decode, Encode};

use crate::primitives::Amount;

use super::Destination;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct StakePoolData {
    owner: Destination,
    staker: Option<Destination>,
    vrf_public_key: VRFPublicKey,
    // TODO: create a PerThousand type
    #[codec(compact)]
    margin_ratio_per_thousand: u64,
    cost_per_epoch: Amount,
}

impl StakePoolData {
    pub fn new(
        owner: Destination,
        staker: Option<Destination>,
        vrf_public_key: VRFPublicKey,
        margin_ratio_per_thousand: u64,
        cost_per_epoch: Amount,
    ) -> Self {
        Self {
            owner,
            staker,
            vrf_public_key,
            margin_ratio_per_thousand,
            cost_per_epoch,
        }
    }

    pub fn owner(&self) -> &Destination {
        &self.owner
    }

    pub fn vrf_public_key(&self) -> &VRFPublicKey {
        &self.vrf_public_key
    }

    pub fn staker(&self) -> &Destination {
        self.staker.as_ref().unwrap_or(&self.owner)
    }

    pub fn is_delegated(&self) -> bool {
        self.staker.is_some()
    }

    pub fn margin_ratio_per_thousand(&self) -> u64 {
        self.margin_ratio_per_thousand
    }

    pub fn cost_per_epoch(&self) -> &Amount {
        &self.cost_per_epoch
    }
}
