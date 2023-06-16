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

use common::chain::block::ConsensusData;
use serialization::{Decode, Encode};

use common::chain::{Block, GenBlock, Genesis, OutPointSourceId, Transaction, TxInput, TxOutput};
use common::primitives::id::WithId;
use common::primitives::{BlockHeight, Id, Idable};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
pub enum TxState {
    /// Confirmed transaction in a block
    #[codec(index = 0)]
    Confirmed(BlockHeight),
    /// Unconfirmed transaction in the mempool
    #[codec(index = 1)]
    InMempool,
    /// Conflicted transaction with a confirmed block
    #[codec(index = 2)]
    Conflicted(Id<GenBlock>),
    /// Transaction that is not confirmed or conflicted and is not in the mempool.
    #[codec(index = 3)]
    Inactive,
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub enum WalletTx {
    Block(BlockData),
    Tx(TxData),
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub struct TxData {
    tx: WithId<Transaction>,

    state: TxState,
}

/// This represents the information pertaining to a block information that was created by the wallet owner.
/// This structure is used to store inputs (kernel inputs in PoS only)
/// and reward outputs of the blocks that belong to the wallet.
/// Spent outputs are found by looking at all locally stored transactions
/// and blocks. In case of reorg, top blocks are simply removed from the DB.
/// We use the same approach as the Bitcoin Core wallet, but unlike Bitcoin
/// we don't have coinbase transactions, so the additional `OwnedBlockRewardData`
/// struct is invented here.
#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub struct BlockData {
    // `GenBlock` because this may be the genesis block (kernel_inputs will be empty in this case)
    block_id: Id<GenBlock>,

    height: BlockHeight,

    kernel_inputs: Vec<TxInput>,

    reward: Vec<TxOutput>,
}

impl WalletTx {
    pub fn id(&self) -> OutPointSourceId {
        match self {
            WalletTx::Block(block) => OutPointSourceId::BlockReward(*block.block_id()),
            WalletTx::Tx(tx) => OutPointSourceId::Transaction(tx.tx.get_id()),
        }
    }

    pub fn state(&self) -> TxState {
        match self {
            WalletTx::Block(block) => TxState::Confirmed(block.height()),
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
    pub fn new(tx: WithId<Transaction>, state: TxState) -> Self {
        Self { tx, state }
    }

    pub fn get_transaction(&self) -> &Transaction {
        WithId::get(&self.tx)
    }
}

impl BlockData {
    pub fn from_genesis(genesis: &Genesis) -> Self {
        BlockData {
            block_id: genesis.get_id().into(),
            height: BlockHeight::zero(),
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

    pub fn kernel_inputs(&self) -> &[TxInput] {
        &self.kernel_inputs
    }

    pub fn reward(&self) -> &[TxOutput] {
        &self.reward
    }
}
