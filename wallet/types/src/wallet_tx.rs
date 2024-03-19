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

use std::fmt::Display;

use common::chain::block::timestamp::BlockTimestamp;
use common::chain::block::ConsensusData;
use serialization::{Decode, Encode};

use common::chain::{
    Block, GenBlock, Genesis, OutPointSourceId, SignedTransaction, Transaction, TxInput, TxOutput,
};
use common::primitives::id::WithId;
use common::primitives::{BlockHeight, Id, Idable};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode, serde::Serialize)]
pub enum TxState {
    /// Confirmed transaction in a block
    #[codec(index = 0)]
    Confirmed(BlockHeight, BlockTimestamp, u64),
    /// Unconfirmed transaction in the mempool
    #[codec(index = 1)]
    InMempool(u64),
    /// Conflicted transaction with a confirmed block
    #[codec(index = 2)]
    Conflicted(Id<GenBlock>),
    /// Transaction that is not confirmed or conflicted and is not in the mempool.
    #[codec(index = 3)]
    Inactive(u64),
    /// Transaction that is not confirmed or conflicted and is not in the mempool and marked as
    /// abandoned by the user
    #[codec(index = 4)]
    Abandoned,
}

impl TxState {
    pub fn block_height(&self) -> Option<BlockHeight> {
        match self {
            TxState::Confirmed(block_height, _timestamp, _idx) => Some(*block_height),
            TxState::InMempool(_)
            | TxState::Conflicted(_)
            | TxState::Inactive(_)
            | TxState::Abandoned => None,
        }
    }

    pub fn block_order_index(&self) -> Option<u64> {
        match self {
            TxState::Confirmed(_, _, idx) | TxState::InMempool(idx) | TxState::Inactive(idx) => {
                Some(*idx)
            }
            TxState::Conflicted(_) | TxState::Abandoned => None,
        }
    }

    pub fn timestamp(&self) -> Option<BlockTimestamp> {
        match self {
            TxState::Confirmed(_block_height, timestamp, _idx) => Some(*timestamp),
            TxState::InMempool(_)
            | TxState::Conflicted(_)
            | TxState::Inactive(_)
            | TxState::Abandoned => None,
        }
    }

    pub fn short_name(&self) -> &'static str {
        match self {
            TxState::Confirmed(_height, _timestamp, _idx) => "Confirmed",
            TxState::Conflicted(_id) => "Conflicted",
            TxState::InMempool(_) => "InMempool",
            TxState::Inactive(_) => "Inactive",
            TxState::Abandoned => "Abandoned",
        }
    }

    pub fn is_abandoned(&self) -> bool {
        match self {
            TxState::Abandoned => true,
            TxState::Confirmed(_, _, _)
            | TxState::Conflicted(_)
            | TxState::InMempool(_)
            | TxState::Inactive(_) => false,
        }
    }
}

impl Display for TxState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxState::Confirmed(height, timestamp, _idx) => f.write_fmt(format_args!(
                "Confirmed at height {}, on {}",
                height, timestamp
            )),
            TxState::Conflicted(id) => f.write_fmt(format_args!("Conflicted by {}", id)),
            TxState::InMempool(_) => f.write_str("InMempool"),
            TxState::Inactive(_) => f.write_str("Inactive"),
            TxState::Abandoned => f.write_str("Abandoned"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
pub struct BlockInfo {
    pub height: BlockHeight,
    pub timestamp: BlockTimestamp,
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub enum WalletTx {
    Block(BlockData),
    Tx(TxData),
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub struct TxData {
    tx: SignedTransaction,

    state: TxState,
}

/// This represents the information pertaining to a block information that was created by the wallet owner.
/// This structure is used to store inputs (kernel inputs in PoS only)
/// and reward outputs of the blocks that belong to the wallet.
/// Spent outputs are found by looking at all locally stored transactions
/// and blocks. In case of reorg, top blocks are simply removed from the DB.
/// We use the same approach as the Bitcoin Core wallet, but unlike Bitcoin
/// we don't have coinbase transactions, so the additional `BlockData`
/// struct is invented here.
#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode, serde::Serialize, serde::Deserialize)]
pub struct BlockData {
    // `GenBlock` because this may be the genesis block (kernel_inputs will be empty in this case)
    block_id: Id<GenBlock>,

    height: BlockHeight,

    timestamp: BlockTimestamp,

    kernel_inputs: Vec<TxInput>,

    reward: Vec<TxOutput>,
}

impl WalletTx {
    pub fn id(&self) -> OutPointSourceId {
        match self {
            WalletTx::Block(block) => OutPointSourceId::BlockReward(*block.block_id()),
            WalletTx::Tx(tx) => OutPointSourceId::Transaction(tx.tx.transaction().get_id()),
        }
    }

    pub fn state(&self) -> TxState {
        match self {
            WalletTx::Block(block) => TxState::Confirmed(block.height(), block.timestamp(), 0),
            WalletTx::Tx(tx) => tx.state,
        }
    }

    pub fn inputs(&self) -> &[TxInput] {
        match self {
            WalletTx::Block(block) => block.kernel_inputs(),
            WalletTx::Tx(tx) => tx.tx.inputs(),
        }
    }

    pub fn outputs(&self) -> &[TxOutput] {
        match self {
            WalletTx::Block(block) => block.reward(),
            WalletTx::Tx(tx) => tx.tx.outputs(),
        }
    }
}

impl TxData {
    pub fn new(tx: SignedTransaction, state: TxState) -> Self {
        Self { tx, state }
    }

    pub fn get_signed_transaction(&self) -> &SignedTransaction {
        &self.tx
    }

    pub fn into_signed_transaction(self) -> SignedTransaction {
        self.tx
    }

    pub fn get_transaction(&self) -> &Transaction {
        self.tx.transaction()
    }

    pub fn into_transaction(self) -> Transaction {
        self.tx.take_transaction()
    }

    pub fn get_transaction_with_id(&self) -> WithId<&Transaction> {
        WithId::new(self.tx.transaction())
    }

    pub fn state(&self) -> &TxState {
        &self.state
    }

    pub fn set_state(&mut self, state: TxState) {
        self.state = state
    }
}

impl BlockData {
    pub fn from_genesis(genesis: &Genesis) -> Self {
        BlockData {
            block_id: genesis.get_id().into(),
            height: BlockHeight::zero(),
            timestamp: genesis.timestamp(),
            kernel_inputs: Vec::new(),
            reward: genesis.utxos().to_vec(),
        }
    }

    pub fn from_block(block: &Block, block_height: BlockHeight) -> Self {
        let kernel_inputs = match block.header().consensus_data() {
            ConsensusData::PoS(pos) => pos.kernel_inputs().to_vec(),
            ConsensusData::PoW(_) | ConsensusData::None => Vec::new(),
        };

        BlockData {
            block_id: block.get_id().into(),
            height: block_height,
            timestamp: block.timestamp(),
            kernel_inputs,
            reward: block.block_reward().outputs().to_vec(),
        }
    }

    pub fn block_id(&self) -> &Id<GenBlock> {
        &self.block_id
    }

    pub fn height(&self) -> BlockHeight {
        self.height
    }

    pub fn timestamp(&self) -> BlockTimestamp {
        self.timestamp
    }

    pub fn kernel_inputs(&self) -> &[TxInput] {
        &self.kernel_inputs
    }

    pub fn reward(&self) -> &[TxOutput] {
        &self.reward
    }
}
