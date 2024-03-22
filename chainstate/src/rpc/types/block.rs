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

use chainstate_types::BlockIndex;
use common::{
    address::AddressError,
    chain::{block::timestamp::BlockTimestamp, Block, ChainConfig, GenBlock},
    primitives::{BlockHeight, Id, Idable},
};
use serialization::hex_encoded::HexEncoded;

use super::{
    block_reward::RpcBlockReward, consensus_data::RpcConsensusData,
    signed_transaction::RpcSignedTransaction,
};

#[derive(Debug, Clone, serde::Serialize)]
pub struct RpcBlock {
    id: Id<Block>,
    prev_block_id: Id<GenBlock>,
    height: BlockHeight,
    chain_transaction_count: u128,
    timestamp: BlockTimestamp,
    consensus_data: RpcConsensusData,

    block_reward: RpcBlockReward,
    transaction_count_in_block: u32,
    transactions: Vec<RpcSignedTransaction>,

    block_hex: HexEncoded<Block>,
}

impl RpcBlock {
    pub fn new(
        chain_config: &ChainConfig,
        block: Block,
        block_index: BlockIndex,
    ) -> Result<Self, AddressError> {
        let rpc_consensus_data = RpcConsensusData::new(chain_config, block.consensus_data())?;
        let rpc_block_reward = RpcBlockReward::new(chain_config, block.block_reward())?;
        let rpc_transactions = block
            .transactions()
            .iter()
            .map(|tx| RpcSignedTransaction::new(chain_config, tx.clone()))
            .collect::<Result<Vec<_>, _>>()?;

        let rpc_block = Self {
            id: block.get_id(),
            prev_block_id: block.prev_block_id(),
            height: block_index.block_height(),
            chain_transaction_count: block_index.chain_transaction_count(),
            timestamp: block.timestamp(),
            consensus_data: rpc_consensus_data,
            block_reward: rpc_block_reward,
            transaction_count_in_block: block.transactions().len() as u32,
            transactions: rpc_transactions,
            block_hex: block.into(),
        };
        Ok(rpc_block)
    }
}
