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

//! A module that deals with the id generation for pools, delegations, tokens and orders.
//!
//! Note:
//!
//! The id generation logic differs for different types of ids, so given the same input,
//! `make_pool_id`/`make_delegation_id`/`make_token_id`/`make_order_id` will produce
//! different id values.
//!
//! For pools and delegations this is achieved by including a distinct "id_preimage_suffix"
//! into the hashed data.
//!
//! For tokens and orders "id_preimage_suffix" is not used (due to historical reasons), but
//! the ids are still distinct (for tokens we hash a `TxInput` and for orders a `UtxoOutPoint`;
//! for pools and delegations we hash a `UtxoOutPoint` too, but due to the use of
//! "id_preimage_suffix" the ids will differ both from each other and from the corresponding
//! order id).
//!
//! Any future entity id generation should follow the "id_preimage_suffix" approach.

use crypto::hash::StreamHasher as _;

use crate::primitives::{
    id::{hash_encoded, hash_encoded_to, DefaultHashAlgoStream},
    BlockHeight,
};

use super::{
    tokens::TokenId, ChainConfig, DelegationId, OrderId, PoolId, TokenIdGenerationVersion, TxInput,
    UtxoOutPoint,
};

pub fn make_pool_id(inputs: &[TxInput]) -> Result<PoolId, IdCreationError> {
    let input_utxo_outpoint = inputs
        .iter()
        .find_map(|input| input.utxo_outpoint())
        .ok_or(IdCreationError::NoUtxoInputsForPoolIdCreation)?;
    Ok(PoolId::from_utxo(input_utxo_outpoint))
}

pub fn make_delegation_id(inputs: &[TxInput]) -> Result<DelegationId, IdCreationError> {
    let input_utxo_outpoint = inputs
        .iter()
        .find_map(|input| input.utxo_outpoint())
        .ok_or(IdCreationError::NoUtxoInputsForDelegationIdCreation)?;
    Ok(DelegationId::from_utxo(input_utxo_outpoint))
}

pub fn make_order_id(inputs: &[TxInput]) -> Result<OrderId, IdCreationError> {
    let input_utxo_outpoint = inputs
        .iter()
        .find_map(|input| input.utxo_outpoint())
        .ok_or(IdCreationError::NoUtxoInputsForOrderIdCreation)?;
    Ok(OrderId::from_utxo(input_utxo_outpoint))
}

pub fn make_token_id(
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    inputs: &[TxInput],
) -> Result<TokenId, IdCreationError> {
    make_token_id_with_version(
        chain_config
            .chainstate_upgrades()
            .version_at_height(block_height)
            .1
            .token_id_generation_version(),
        inputs,
    )
}

pub fn make_token_id_with_version(
    version: TokenIdGenerationVersion,
    inputs: &[TxInput],
) -> Result<TokenId, IdCreationError> {
    match version {
        TokenIdGenerationVersion::V0 => Ok(TokenId::from_tx_input(
            inputs.first().ok_or(IdCreationError::NoInputsForTokenIdCreation)?,
        )),
        TokenIdGenerationVersion::V1 => {
            let utxo_input = inputs
                .iter()
                .find(|input| input.utxo_outpoint().is_some())
                .ok_or(IdCreationError::NoUtxoInputsForTokenIdCreation)?;
            Ok(TokenId::from_tx_input(utxo_input))
        }
    }
}

impl PoolId {
    pub fn from_utxo(utxo_outpoint: &UtxoOutPoint) -> Self {
        let mut hasher = DefaultHashAlgoStream::new();

        hash_encoded_to(&utxo_outpoint, &mut hasher);

        hash_encoded_to(&pool_id_preimage_suffix(), &mut hasher);
        Self::new(hasher.finalize().into())
    }
}

impl DelegationId {
    pub fn from_utxo(utxo_outpoint: &UtxoOutPoint) -> Self {
        let mut hasher = DefaultHashAlgoStream::new();

        hash_encoded_to(&utxo_outpoint, &mut hasher);

        hash_encoded_to(&delegation_id_preimage_suffix(), &mut hasher);
        Self::new(hasher.finalize().into())
    }
}

impl TokenId {
    pub fn from_tx_input(tx_input: &TxInput) -> Self {
        Self::new(hash_encoded(tx_input))
    }
}

impl OrderId {
    pub fn from_utxo(utxo_outpoint: &UtxoOutPoint) -> Self {
        Self::new(hash_encoded(utxo_outpoint))
    }
}

fn pool_id_preimage_suffix() -> u32 {
    // arbitrary, we use this to create different values when hashing with no security requirements
    0
}

fn delegation_id_preimage_suffix() -> u32 {
    // arbitrary, we use this to create different values when hashing with no security requirements
    1
}

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum IdCreationError {
    #[error("No UTXO inputs for pool id creation")]
    NoUtxoInputsForPoolIdCreation,

    #[error("No UTXO inputs for delegation id creation")]
    NoUtxoInputsForDelegationIdCreation,

    #[error("No UTXO inputs for order id creation")]
    NoUtxoInputsForOrderIdCreation,

    #[error("No UTXO inputs for token id creation")]
    NoUtxoInputsForTokenIdCreation,

    #[error("No inputs for token id creation")]
    NoInputsForTokenIdCreation,
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use randomness::Rng;
    use test_utils::random::Seed;

    use crate::{
        chain::{
            config, AccountNonce, AccountOutPoint, AccountSpending, ChainstateUpgradeBuilder,
            NetUpgrades, OutPointSourceId, TokenIdGenerationVersion, TxInput, UtxoOutPoint,
        },
        primitives::{Amount, BlockHeight, Id},
    };

    use super::*;

    // Check that make_token_id generates identical ids before and after the fork if the first
    // input is a utxo.
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn token_id_consistency(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let fork_height = BlockHeight::new(rng.gen_range(1..1_000_000));
        let chain_config = config::Builder::test_chain()
            .chainstate_upgrades(
                NetUpgrades::initialize(vec![
                    (
                        BlockHeight::zero(),
                        ChainstateUpgradeBuilder::latest()
                            .token_id_generation_version(TokenIdGenerationVersion::V0)
                            .build(),
                    ),
                    (
                        fork_height,
                        ChainstateUpgradeBuilder::latest()
                            .token_id_generation_version(TokenIdGenerationVersion::V1)
                            .build(),
                    ),
                ])
                .unwrap(),
            )
            .build();

        logging::init_logging();
        logging::log::warn!("fork_height = {fork_height}");

        let non_utxo_input = TxInput::Account(AccountOutPoint::new(
            AccountNonce::new(rng.gen()),
            AccountSpending::DelegationBalance(
                Id::random_using(&mut rng),
                Amount::from_atoms(rng.gen()),
            ),
        ));
        let utxo_input = TxInput::Utxo(UtxoOutPoint::new(
            if rng.gen_bool(0.5) {
                OutPointSourceId::Transaction(Id::random_using(&mut rng))
            } else {
                OutPointSourceId::BlockReward(Id::random_using(&mut rng))
            },
            rng.gen(),
        ));

        // Sanity check - if the first input is non-utxo, the ids will be generated differently
        // before and after the fork.
        {
            let inputs = [non_utxo_input.clone(), utxo_input.clone()];
            let id1 =
                make_token_id(&chain_config, fork_height.prev_height().unwrap(), &inputs).unwrap();
            let id2 = make_token_id(&chain_config, fork_height, &inputs).unwrap();
            assert_ne!(id1, id2);
        }

        // The first input is a utxo, the generated ids should be identical.
        {
            let inputs = [utxo_input];
            let id1 =
                make_token_id(&chain_config, fork_height.prev_height().unwrap(), &inputs).unwrap();
            let id2 = make_token_id(&chain_config, fork_height, &inputs).unwrap();
            assert_eq!(id1, id2);
        }
    }
}
