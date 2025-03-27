// Copyright (c) 2025 RBB S.r.l
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

use common::chain::{
    ChainstateUpgrade, ChangeTokenMetadataUriActivated, DataDepositFeeVersion,
    FrozenTokensValidationVersion, HtlcActivated, OrdersActivated, OrdersVersion,
    RewardDistributionVersion, StakerDestinationUpdateForbidden, TokenIssuanceVersion,
    TokensFeeVersion,
};

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct ChainstateUpgradeBuilder {
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

macro_rules! builder_method {
    ($name:ident: $type:ty) => {
        #[doc = concat!("Set the `", stringify!($name), "` field.")]
        #[must_use = "ChainstateUpgradeBuilder dropped prematurely"]
        pub fn $name(mut self, $name: $type) -> Self {
            self.$name = $name;
            self
        }
    };
}

impl ChainstateUpgradeBuilder {
    pub fn latest() -> Self {
        Self {
            token_issuance_version: TokenIssuanceVersion::V1,
            reward_distribution_version: RewardDistributionVersion::V1,
            tokens_fee_version: TokensFeeVersion::V1,
            data_deposit_fee_version: DataDepositFeeVersion::V1,
            change_token_metadata_uri_activated: ChangeTokenMetadataUriActivated::Yes,
            frozen_tokens_validation_version: FrozenTokensValidationVersion::V1,
            htlc_activated: HtlcActivated::Yes,
            orders_activated: OrdersActivated::Yes,
            orders_version: OrdersVersion::V1,
            staker_destination_update_forbidden: StakerDestinationUpdateForbidden::Yes,
        }
    }

    pub fn build(self) -> ChainstateUpgrade {
        ChainstateUpgrade::new(
            self.token_issuance_version,
            self.reward_distribution_version,
            self.tokens_fee_version,
            self.data_deposit_fee_version,
            self.change_token_metadata_uri_activated,
            self.frozen_tokens_validation_version,
            self.htlc_activated,
            self.orders_activated,
            self.orders_version,
            self.staker_destination_update_forbidden,
        )
    }

    builder_method!(token_issuance_version: TokenIssuanceVersion);
    builder_method!(change_token_metadata_uri_activated: ChangeTokenMetadataUriActivated);
    builder_method!(htlc_activated: HtlcActivated);
    builder_method!(orders_activated: OrdersActivated);
    builder_method!(orders_version: OrdersVersion);
    builder_method!(staker_destination_update_forbidden: StakerDestinationUpdateForbidden);
}
