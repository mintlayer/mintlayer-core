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
pub enum StakerDestinationUpdateForbidden {
    Yes,
    No,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum DataDepositFeeVersion {
    V0,
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum ChangeTokenMetadataUriActivated {
    Yes,
    No,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum FrozenTokensValidationVersion {
    V0,
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum OrdersVersion {
    /// Initial orders implementation
    V0,
    /// Calculate fill amount based on original balances; ignore nonce for order operations
    V1,
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct ChainstateUpgrade {
    token_issuance_version: TokenIssuanceVersion,
    reward_distribution_version: RewardDistributionVersion,
    tokens_fee_version: TokensFeeVersion,
    data_deposit_fee_version: DataDepositFeeVersion,
    change_token_metadata_uri_activated: ChangeTokenMetadataUriActivated,
    frozen_tokens_validation_version: FrozenTokensValidationVersion,
    htlc_activated: HtlcActivated,
    orders_activated: OrdersActivated,
    orders_version: OrdersVersion,
    staker_destination_update_forbidden: StakerDestinationUpdateForbidden,
}

impl ChainstateUpgrade {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token_issuance_version: TokenIssuanceVersion,
        reward_distribution_version: RewardDistributionVersion,
        tokens_fee_version: TokensFeeVersion,
        data_deposit_fee_version: DataDepositFeeVersion,
        change_token_metadata_uri_activated: ChangeTokenMetadataUriActivated,
        frozen_tokens_validation_version: FrozenTokensValidationVersion,
        htlc_activated: HtlcActivated,
        orders_activated: OrdersActivated,
        orders_version: OrdersVersion,
        staker_destination_update_forbidden: StakerDestinationUpdateForbidden,
    ) -> Self {
        Self {
            token_issuance_version,
            reward_distribution_version,
            tokens_fee_version,
            data_deposit_fee_version,
            change_token_metadata_uri_activated,
            frozen_tokens_validation_version,
            htlc_activated,
            orders_activated,
            orders_version,
            staker_destination_update_forbidden,
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

    pub fn staker_destination_update_forbidden(&self) -> StakerDestinationUpdateForbidden {
        self.staker_destination_update_forbidden
    }

    pub fn data_deposit_fee_version(&self) -> DataDepositFeeVersion {
        self.data_deposit_fee_version
    }

    pub fn change_token_metadata_uri_activated(&self) -> ChangeTokenMetadataUriActivated {
        self.change_token_metadata_uri_activated
    }

    pub fn frozen_tokens_validation_version(&self) -> FrozenTokensValidationVersion {
        self.frozen_tokens_validation_version
    }

    pub fn orders_version(&self) -> OrdersVersion {
        self.orders_version
    }
}
