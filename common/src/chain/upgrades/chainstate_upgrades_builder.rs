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

use crate::primitives::BlockHeight;

use super::{ChainstateUpgrade, ChainstateUpgradeBuilder, NetUpgrades};

/// A builder for NetUpgrades<ChainstateUpgrade> that uses `ChainstateUpgradeBuilder`
/// to build individual `ChainstateUpgrade`s.
pub struct ChainstateUpgradesBuilder(Vec<(BlockHeight, ChainstateUpgrade)>);

impl ChainstateUpgradesBuilder {
    pub fn new(initial: ChainstateUpgrade) -> Self {
        Self(vec![(BlockHeight::new(0), initial)])
    }

    /// Append another upgrade.
    ///
    /// The height must be strictly bigger than the previous one;
    /// `make_upgrade` will receive a `ChainstateUpgradeBuilder` initialized with the previous
    /// upgrade, so only the fields that need to change at this particular height should be modified.
    pub fn then<MakeUpgrade>(mut self, height: BlockHeight, make_upgrade: MakeUpgrade) -> Self
    where
        MakeUpgrade: FnOnce(ChainstateUpgradeBuilder) -> ChainstateUpgradeBuilder,
    {
        let last_upgrade = self.0.last().expect("known to be non-empty");
        assert!(last_upgrade.0 < height, "bad height");

        let upgrade =
            make_upgrade(ChainstateUpgradeBuilder::new_strict(last_upgrade.1.clone())).build();
        self.0.push((height, upgrade));
        self
    }

    pub fn build(self) -> NetUpgrades<ChainstateUpgrade> {
        NetUpgrades::initialize(self.0).expect("the upgrades are known to be valid")
    }
}

#[cfg(test)]
mod tests {
    use crate::chain::{
        ChangeTokenMetadataUriActivated, DataDepositFeeVersion, FrozenTokensValidationVersion,
        HtlcActivated, OrdersActivated, OrdersVersion, RewardDistributionVersion,
        SighashInputCommitmentVersion, StakerDestinationUpdateForbidden, TokenIdGenerationVersion,
        TokenIssuanceVersion, TokensFeeVersion,
    };

    use super::*;

    #[test]
    fn correct_sequential_upgrades() {
        let upgrades = ChainstateUpgradesBuilder::new(ChainstateUpgrade::new(
            TokenIssuanceVersion::V0,
            RewardDistributionVersion::V0,
            TokensFeeVersion::V0,
            DataDepositFeeVersion::V0,
            ChangeTokenMetadataUriActivated::No,
            FrozenTokensValidationVersion::V0,
            HtlcActivated::No,
            OrdersActivated::No,
            OrdersVersion::V0,
            StakerDestinationUpdateForbidden::No,
            TokenIdGenerationVersion::V0,
            SighashInputCommitmentVersion::V0,
        ))
        .then(BlockHeight::new(1), |builder| {
            builder.token_issuance_version(TokenIssuanceVersion::V1)
        })
        .then(BlockHeight::new(2), |builder| {
            builder.reward_distribution_version(RewardDistributionVersion::V1)
        })
        .then(BlockHeight::new(3), |builder| {
            builder.tokens_fee_version(TokensFeeVersion::V1)
        })
        .then(BlockHeight::new(4), |builder| {
            builder.data_deposit_fee_version(DataDepositFeeVersion::V1)
        })
        .then(BlockHeight::new(5), |builder| {
            builder.change_token_metadata_uri_activated(ChangeTokenMetadataUriActivated::Yes)
        })
        .then(BlockHeight::new(6), |builder| {
            builder.frozen_tokens_validation_version(FrozenTokensValidationVersion::V1)
        })
        .then(BlockHeight::new(7), |builder| {
            builder.htlc_activated(HtlcActivated::Yes)
        })
        .then(BlockHeight::new(8), |builder| {
            builder.orders_activated(OrdersActivated::Yes)
        })
        .then(BlockHeight::new(9), |builder| {
            builder.orders_version(OrdersVersion::V1)
        })
        .then(BlockHeight::new(10), |builder| {
            builder.staker_destination_update_forbidden(StakerDestinationUpdateForbidden::Yes)
        })
        .then(BlockHeight::new(11), |builder| {
            builder.token_id_generation_version(TokenIdGenerationVersion::V1)
        })
        .then(BlockHeight::new(12), |builder| {
            builder.sighash_input_commitment_version(SighashInputCommitmentVersion::V1)
        })
        .build();

        let expected_upgrades = NetUpgrades::initialize(vec![
            (
                BlockHeight::new(0),
                ChainstateUpgrade::new(
                    TokenIssuanceVersion::V0,
                    RewardDistributionVersion::V0,
                    TokensFeeVersion::V0,
                    DataDepositFeeVersion::V0,
                    ChangeTokenMetadataUriActivated::No,
                    FrozenTokensValidationVersion::V0,
                    HtlcActivated::No,
                    OrdersActivated::No,
                    OrdersVersion::V0,
                    StakerDestinationUpdateForbidden::No,
                    TokenIdGenerationVersion::V0,
                    SighashInputCommitmentVersion::V0,
                ),
            ),
            (
                BlockHeight::new(1),
                ChainstateUpgrade::new(
                    TokenIssuanceVersion::V1,
                    RewardDistributionVersion::V0,
                    TokensFeeVersion::V0,
                    DataDepositFeeVersion::V0,
                    ChangeTokenMetadataUriActivated::No,
                    FrozenTokensValidationVersion::V0,
                    HtlcActivated::No,
                    OrdersActivated::No,
                    OrdersVersion::V0,
                    StakerDestinationUpdateForbidden::No,
                    TokenIdGenerationVersion::V0,
                    SighashInputCommitmentVersion::V0,
                ),
            ),
            (
                BlockHeight::new(2),
                ChainstateUpgrade::new(
                    TokenIssuanceVersion::V1,
                    RewardDistributionVersion::V1,
                    TokensFeeVersion::V0,
                    DataDepositFeeVersion::V0,
                    ChangeTokenMetadataUriActivated::No,
                    FrozenTokensValidationVersion::V0,
                    HtlcActivated::No,
                    OrdersActivated::No,
                    OrdersVersion::V0,
                    StakerDestinationUpdateForbidden::No,
                    TokenIdGenerationVersion::V0,
                    SighashInputCommitmentVersion::V0,
                ),
            ),
            (
                BlockHeight::new(3),
                ChainstateUpgrade::new(
                    TokenIssuanceVersion::V1,
                    RewardDistributionVersion::V1,
                    TokensFeeVersion::V1,
                    DataDepositFeeVersion::V0,
                    ChangeTokenMetadataUriActivated::No,
                    FrozenTokensValidationVersion::V0,
                    HtlcActivated::No,
                    OrdersActivated::No,
                    OrdersVersion::V0,
                    StakerDestinationUpdateForbidden::No,
                    TokenIdGenerationVersion::V0,
                    SighashInputCommitmentVersion::V0,
                ),
            ),
            (
                BlockHeight::new(4),
                ChainstateUpgrade::new(
                    TokenIssuanceVersion::V1,
                    RewardDistributionVersion::V1,
                    TokensFeeVersion::V1,
                    DataDepositFeeVersion::V1,
                    ChangeTokenMetadataUriActivated::No,
                    FrozenTokensValidationVersion::V0,
                    HtlcActivated::No,
                    OrdersActivated::No,
                    OrdersVersion::V0,
                    StakerDestinationUpdateForbidden::No,
                    TokenIdGenerationVersion::V0,
                    SighashInputCommitmentVersion::V0,
                ),
            ),
            (
                BlockHeight::new(5),
                ChainstateUpgrade::new(
                    TokenIssuanceVersion::V1,
                    RewardDistributionVersion::V1,
                    TokensFeeVersion::V1,
                    DataDepositFeeVersion::V1,
                    ChangeTokenMetadataUriActivated::Yes,
                    FrozenTokensValidationVersion::V0,
                    HtlcActivated::No,
                    OrdersActivated::No,
                    OrdersVersion::V0,
                    StakerDestinationUpdateForbidden::No,
                    TokenIdGenerationVersion::V0,
                    SighashInputCommitmentVersion::V0,
                ),
            ),
            (
                BlockHeight::new(6),
                ChainstateUpgrade::new(
                    TokenIssuanceVersion::V1,
                    RewardDistributionVersion::V1,
                    TokensFeeVersion::V1,
                    DataDepositFeeVersion::V1,
                    ChangeTokenMetadataUriActivated::Yes,
                    FrozenTokensValidationVersion::V1,
                    HtlcActivated::No,
                    OrdersActivated::No,
                    OrdersVersion::V0,
                    StakerDestinationUpdateForbidden::No,
                    TokenIdGenerationVersion::V0,
                    SighashInputCommitmentVersion::V0,
                ),
            ),
            (
                BlockHeight::new(7),
                ChainstateUpgrade::new(
                    TokenIssuanceVersion::V1,
                    RewardDistributionVersion::V1,
                    TokensFeeVersion::V1,
                    DataDepositFeeVersion::V1,
                    ChangeTokenMetadataUriActivated::Yes,
                    FrozenTokensValidationVersion::V1,
                    HtlcActivated::Yes,
                    OrdersActivated::No,
                    OrdersVersion::V0,
                    StakerDestinationUpdateForbidden::No,
                    TokenIdGenerationVersion::V0,
                    SighashInputCommitmentVersion::V0,
                ),
            ),
            (
                BlockHeight::new(8),
                ChainstateUpgrade::new(
                    TokenIssuanceVersion::V1,
                    RewardDistributionVersion::V1,
                    TokensFeeVersion::V1,
                    DataDepositFeeVersion::V1,
                    ChangeTokenMetadataUriActivated::Yes,
                    FrozenTokensValidationVersion::V1,
                    HtlcActivated::Yes,
                    OrdersActivated::Yes,
                    OrdersVersion::V0,
                    StakerDestinationUpdateForbidden::No,
                    TokenIdGenerationVersion::V0,
                    SighashInputCommitmentVersion::V0,
                ),
            ),
            (
                BlockHeight::new(9),
                ChainstateUpgrade::new(
                    TokenIssuanceVersion::V1,
                    RewardDistributionVersion::V1,
                    TokensFeeVersion::V1,
                    DataDepositFeeVersion::V1,
                    ChangeTokenMetadataUriActivated::Yes,
                    FrozenTokensValidationVersion::V1,
                    HtlcActivated::Yes,
                    OrdersActivated::Yes,
                    OrdersVersion::V1,
                    StakerDestinationUpdateForbidden::No,
                    TokenIdGenerationVersion::V0,
                    SighashInputCommitmentVersion::V0,
                ),
            ),
            (
                BlockHeight::new(10),
                ChainstateUpgrade::new(
                    TokenIssuanceVersion::V1,
                    RewardDistributionVersion::V1,
                    TokensFeeVersion::V1,
                    DataDepositFeeVersion::V1,
                    ChangeTokenMetadataUriActivated::Yes,
                    FrozenTokensValidationVersion::V1,
                    HtlcActivated::Yes,
                    OrdersActivated::Yes,
                    OrdersVersion::V1,
                    StakerDestinationUpdateForbidden::Yes,
                    TokenIdGenerationVersion::V0,
                    SighashInputCommitmentVersion::V0,
                ),
            ),
            (
                BlockHeight::new(11),
                ChainstateUpgrade::new(
                    TokenIssuanceVersion::V1,
                    RewardDistributionVersion::V1,
                    TokensFeeVersion::V1,
                    DataDepositFeeVersion::V1,
                    ChangeTokenMetadataUriActivated::Yes,
                    FrozenTokensValidationVersion::V1,
                    HtlcActivated::Yes,
                    OrdersActivated::Yes,
                    OrdersVersion::V1,
                    StakerDestinationUpdateForbidden::Yes,
                    TokenIdGenerationVersion::V1,
                    SighashInputCommitmentVersion::V0,
                ),
            ),
            (
                BlockHeight::new(12),
                ChainstateUpgrade::new(
                    TokenIssuanceVersion::V1,
                    RewardDistributionVersion::V1,
                    TokensFeeVersion::V1,
                    DataDepositFeeVersion::V1,
                    ChangeTokenMetadataUriActivated::Yes,
                    FrozenTokensValidationVersion::V1,
                    HtlcActivated::Yes,
                    OrdersActivated::Yes,
                    OrdersVersion::V1,
                    StakerDestinationUpdateForbidden::Yes,
                    TokenIdGenerationVersion::V1,
                    SighashInputCommitmentVersion::V1,
                ),
            ),
        ])
        .unwrap();

        assert_eq!(upgrades, expected_upgrades);
    }

    #[test]
    #[should_panic(expected = "bad height")]
    fn wrong_height_order() {
        let _ = ChainstateUpgradesBuilder::new(ChainstateUpgrade::new(
            TokenIssuanceVersion::V0,
            RewardDistributionVersion::V0,
            TokensFeeVersion::V0,
            DataDepositFeeVersion::V0,
            ChangeTokenMetadataUriActivated::No,
            FrozenTokensValidationVersion::V0,
            HtlcActivated::No,
            OrdersActivated::No,
            OrdersVersion::V0,
            StakerDestinationUpdateForbidden::No,
            TokenIdGenerationVersion::V0,
            SighashInputCommitmentVersion::V0,
        ))
        .then(BlockHeight::new(2), |builder| {
            builder.token_issuance_version(TokenIssuanceVersion::V1)
        })
        .then(BlockHeight::new(1), |builder| {
            builder.reward_distribution_version(RewardDistributionVersion::V1)
        })
        .build();
    }

    #[test]
    #[should_panic(expected = "bad height")]
    fn same_height_twice() {
        let _ = ChainstateUpgradesBuilder::new(ChainstateUpgrade::new(
            TokenIssuanceVersion::V0,
            RewardDistributionVersion::V0,
            TokensFeeVersion::V0,
            DataDepositFeeVersion::V0,
            ChangeTokenMetadataUriActivated::No,
            FrozenTokensValidationVersion::V0,
            HtlcActivated::No,
            OrdersActivated::No,
            OrdersVersion::V0,
            StakerDestinationUpdateForbidden::No,
            TokenIdGenerationVersion::V0,
            SighashInputCommitmentVersion::V0,
        ))
        .then(BlockHeight::new(1), |builder| {
            builder.token_issuance_version(TokenIssuanceVersion::V1)
        })
        .then(BlockHeight::new(1), |builder| {
            builder.reward_distribution_version(RewardDistributionVersion::V1)
        })
        .build();
    }

    #[test]
    #[should_panic(expected = "bad height")]
    fn zero_height_twice() {
        let _ = ChainstateUpgradesBuilder::new(ChainstateUpgrade::new(
            TokenIssuanceVersion::V0,
            RewardDistributionVersion::V0,
            TokensFeeVersion::V0,
            DataDepositFeeVersion::V0,
            ChangeTokenMetadataUriActivated::No,
            FrozenTokensValidationVersion::V0,
            HtlcActivated::No,
            OrdersActivated::No,
            OrdersVersion::V0,
            StakerDestinationUpdateForbidden::No,
            TokenIdGenerationVersion::V0,
            SighashInputCommitmentVersion::V0,
        ))
        .then(BlockHeight::new(0), |builder| {
            builder.token_issuance_version(TokenIssuanceVersion::V1)
        })
        .build();
    }

    #[test]
    #[should_panic(expected = "field set to the same value")]
    fn set_to_same_value() {
        let _ = ChainstateUpgradesBuilder::new(ChainstateUpgrade::new(
            TokenIssuanceVersion::V0,
            RewardDistributionVersion::V0,
            TokensFeeVersion::V0,
            DataDepositFeeVersion::V0,
            ChangeTokenMetadataUriActivated::No,
            FrozenTokensValidationVersion::V0,
            HtlcActivated::No,
            OrdersActivated::No,
            OrdersVersion::V0,
            StakerDestinationUpdateForbidden::No,
            TokenIdGenerationVersion::V0,
            SighashInputCommitmentVersion::V0,
        ))
        .then(BlockHeight::new(1), |builder| {
            builder.token_issuance_version(TokenIssuanceVersion::V0)
        })
        .build();
    }
}
