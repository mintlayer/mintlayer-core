// Copyright (c) 2021-2025 RBB S.r.l
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

use crate::chain::{
    ChainstateUpgrade, ChangeTokenMetadataUriActivated, DataDepositFeeVersion,
    FrozenTokensValidationVersion, HtlcActivated, OrdersActivated, OrdersVersion,
    RewardDistributionVersion, StakerDestinationUpdateForbidden, TokenIdGenerationVersion,
    TokenIssuanceVersion, TokensFeeVersion,
};

/// A builder for `ChainstateUpgrade`.
///
/// If `strict` is set to true, builder methods will panic if the new value is the same
/// as the original one.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct ChainstateUpgradeBuilder {
    upgrade: ChainstateUpgrade,
    strict: bool,
}

macro_rules! builder_method {
    ($name:ident: $type:ty) => {
        #[doc = concat!("Set the `", stringify!($name), "` field.")]
        #[must_use = "ChainstateUpgradeBuilder dropped prematurely"]
        pub fn $name(mut self, $name: $type) -> Self {
            assert!(
                !self.strict || self.upgrade.$name != $name,
                "field set to the same value in strict mode"
            );
            self.upgrade.$name = $name;
            self
        }
    };
}

impl ChainstateUpgradeBuilder {
    pub fn new(upgrade: ChainstateUpgrade) -> Self {
        Self {
            upgrade,
            strict: false,
        }
    }

    pub fn new_strict(upgrade: ChainstateUpgrade) -> Self {
        Self {
            upgrade,
            strict: true,
        }
    }

    pub fn latest() -> Self {
        Self::new(ChainstateUpgrade {
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
            token_id_generation_version: TokenIdGenerationVersion::V1,
        })
    }

    pub fn build(self) -> ChainstateUpgrade {
        self.upgrade
    }

    builder_method!(token_issuance_version: TokenIssuanceVersion);
    builder_method!(reward_distribution_version: RewardDistributionVersion);
    builder_method!(tokens_fee_version: TokensFeeVersion);
    builder_method!(data_deposit_fee_version: DataDepositFeeVersion);
    builder_method!(change_token_metadata_uri_activated: ChangeTokenMetadataUriActivated);
    builder_method!(frozen_tokens_validation_version: FrozenTokensValidationVersion);
    builder_method!(htlc_activated: HtlcActivated);
    builder_method!(orders_activated: OrdersActivated);
    builder_method!(orders_version: OrdersVersion);
    builder_method!(staker_destination_update_forbidden: StakerDestinationUpdateForbidden);
    builder_method!(token_id_generation_version: TokenIdGenerationVersion);
}
