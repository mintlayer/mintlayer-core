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

use super::{
    tokens::TokenId, ChainConfig, DelegationId, OrderId, PoolId, TokenIdGenerationVersion, TxInput,
};
use crate::primitives::{id::hash_encoded, BlockHeight};

pub fn make_pool_id(inputs: &[TxInput]) -> Option<PoolId> {
    let input_utxo_outpoint = inputs.iter().find_map(|input| input.utxo_outpoint())?;
    Some(PoolId::from_utxo(input_utxo_outpoint))
}

pub fn make_delegation_id(inputs: &[TxInput]) -> Option<DelegationId> {
    let input_utxo_outpoint = inputs.iter().find_map(|input| input.utxo_outpoint())?;
    Some(DelegationId::from_utxo(input_utxo_outpoint))
}

pub fn make_order_id(inputs: &[TxInput]) -> Option<OrderId> {
    let input_utxo_outpoint = inputs.iter().find_map(|input| input.utxo_outpoint())?;
    Some(OrderId::from_utxo(input_utxo_outpoint))
}

pub fn make_token_id(
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    inputs: &[TxInput],
) -> Option<TokenId> {
    match chain_config
        .chainstate_upgrades()
        .version_at_height(block_height)
        .1
        .token_id_generation_version()
    {
        TokenIdGenerationVersion::V0 => Some(TokenId::new(hash_encoded(inputs.first()?))),
        TokenIdGenerationVersion::V1 => {
            let input_utxo_outpoint = inputs.iter().find_map(|input| input.utxo_outpoint())?;
            Some(TokenId::from_utxo(input_utxo_outpoint))
        }
    }
}
