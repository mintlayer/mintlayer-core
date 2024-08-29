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

use super::Activate;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum TokenIssuanceVersion {
    /// Initial issuance implementation
    V0,
    /// Enable modifying token supply
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum RewardDistributionVersion {
    /// Initial distribution implementation
    V0,
    /// Distribute reward to staker proportional to its balance
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum TokensFeeVersion {
    /// Initial tokens fee values
    V0,
    /// Updated tokens fee values
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum HtlcActivated {
    Yes,
    No,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum OrdersActivated {
    Yes,
    No,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum DataDepositFeeVersion {
    V0,
    V1,
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct ChainstateUpgrade {
    token_issuance_version: TokenIssuanceVersion,
    reward_distribution_version: RewardDistributionVersion,
    tokens_fee_version: TokensFeeVersion,
    data_deposit_fee_version: DataDepositFeeVersion,
    htlc_activated: HtlcActivated,
    orders_activated: OrdersActivated,
}

impl ChainstateUpgrade {
    pub fn new(
        token_issuance_version: TokenIssuanceVersion,
        reward_distribution_version: RewardDistributionVersion,
        tokens_fee_version: TokensFeeVersion,
        data_deposit_fee_version: DataDepositFeeVersion,
        htlc_activated: HtlcActivated,
        orders_activated: OrdersActivated,
    ) -> Self {
        Self {
            token_issuance_version,
            reward_distribution_version,
            tokens_fee_version,
            data_deposit_fee_version,
            htlc_activated,
            orders_activated,
        }
    }

    pub fn token_issuance_version(&self) -> TokenIssuanceVersion {
        self.token_issuance_version
    }

    pub fn reward_distribution_version(&self) -> RewardDistributionVersion {
        self.reward_distribution_version
    }

    pub fn tokens_fee_version(&self) -> TokensFeeVersion {
        self.tokens_fee_version
    }

    pub fn htlc_activated(&self) -> HtlcActivated {
        self.htlc_activated
    }

    pub fn orders_activated(&self) -> OrdersActivated {
        self.orders_activated
    }

    pub fn data_deposit_fee_version(&self) -> DataDepositFeeVersion {
        self.data_deposit_fee_version
    }
}

impl Activate for ChainstateUpgrade {}
