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

mod builder;

pub use builder::ChainstateUpgradeBuilder;

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

// TODO: the ability to change the destination has never been used up until now and it will likely
// never be. In such a case, when the corresponding fork height + 1000 blocks (the reorg limit)
// will have been passed both on testnet and mainnet, this upgrade can be completely removed,
// as if this ability has never existed.
// Note: it should be enough to just remove the upgrade (i.e. disable the staker destination change
// unconditionally) and attempt to do a full sync for testnet and mainnet; if it syncs to
// the correct tip, the upgrade can be removed permanently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum StakerDestinationUpdateForbidden {
    Yes,
    No,
}

// TODO: in our wallet we don't produce token-issuing transactions where the 1st input is not a UTXO.
// Which means that this upgrade may probably be completely removed when the "fork height + reorg limit"
// height has been passed.
// Note: unlike StakerDestinationUpdateForbidden, it may not be enough to just sync and compare tips
// in order to prove that the upgrade can be permanently removed. But the following approach should
// be safe:
// a) Add token id logging during token creation.
// b) For both testnet and mainnet, do one full sync with the upgrade present and another one with
// it removed (i.e. where the V1 generation is always used); if the logged ids are the same,
// the upgrade can be removed permanently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum TokenIdGenerationVersion {
    // Token id is generated from the 1st input of the issuing transaction.
    V0,
    // Token id is generated from the 1st UTXO input of the issuing transaction.
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum SighashInputCommitmentVersion {
    V0,
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
    token_id_generation_version: TokenIdGenerationVersion,
    sighash_input_commitment_version: SighashInputCommitmentVersion,
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
        token_id_generation_version: TokenIdGenerationVersion,
        sighash_input_commitment_version: SighashInputCommitmentVersion,
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
            token_id_generation_version,
            sighash_input_commitment_version,
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

    pub fn token_id_generation_version(&self) -> TokenIdGenerationVersion {
        self.token_id_generation_version
    }

    pub fn sighash_input_commitment_version(&self) -> SighashInputCommitmentVersion {
        self.sighash_input_commitment_version
    }
}
