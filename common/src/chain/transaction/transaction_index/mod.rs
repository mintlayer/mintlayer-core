// Copyright (c) 2022 RBB S.r.l
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

use super::Transaction;
use crate::{
    chain::{Block, GenBlock},
    primitives::{Id, Idable},
};
use serialization::{Decode, Encode};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Spender {
    /// Spending a transaction output
    #[codec(index = 0)]
    RegularInput(Id<Transaction>),
    /// Spending a block reward or a premine in genesis
    #[codec(index = 1)]
    BlockInput(Id<GenBlock>),
}

impl From<Id<Transaction>> for Spender {
    fn from(spender: Id<Transaction>) -> Spender {
        Spender::RegularInput(spender)
    }
}

impl From<Id<Block>> for Spender {
    fn from(spender: Id<Block>) -> Spender {
        Spender::BlockInput(spender.into())
    }
}

impl From<Id<GenBlock>> for Spender {
    fn from(block_id: Id<GenBlock>) -> Spender {
        Spender::BlockInput(block_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum OutputSpentState {
    Unspent,
    SpentBy(Spender),
}

/// A transaction is stored in the database as part of a block,
/// specifically in the mainchain.
/// To find a transaction in the database, we first locate the block that contains it,
/// and we then read the binary data at a specific offset and size, which we deserialize
/// to get the transaction.
/// This struct represents the position of a transaction in the database
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct TxMainChainPosition {
    block_id: Id<Block>,
    byte_offset_in_block: u32,
}

impl TxMainChainPosition {
    pub fn new(block_id: Id<Block>, byte_offset_in_block: u32) -> Self {
        TxMainChainPosition {
            block_id,
            byte_offset_in_block,
        }
    }

    pub fn block_id(&self) -> &Id<Block> {
        &self.block_id
    }

    pub fn byte_offset_in_block(&self) -> u32 {
        self.byte_offset_in_block
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpendError {
    AlreadySpent(Spender),
    AlreadyUnspent,
    OutOfRange {
        tx_id: Option<Spender>,
        source_output_index: usize,
    },
}

/// This enum represents that we can either spend from a block reward or a regular transaction
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum SpendablePosition {
    Transaction(TxMainChainPosition),
    BlockReward(Id<GenBlock>),
}

impl From<TxMainChainPosition> for SpendablePosition {
    fn from(pos: TxMainChainPosition) -> SpendablePosition {
        SpendablePosition::Transaction(pos)
    }
}

impl From<Id<Block>> for SpendablePosition {
    fn from(pos: Id<Block>) -> SpendablePosition {
        SpendablePosition::BlockReward(pos.into())
    }
}

impl From<Id<GenBlock>> for SpendablePosition {
    fn from(pos: Id<GenBlock>) -> SpendablePosition {
        SpendablePosition::BlockReward(pos)
    }
}

impl SpendablePosition {
    pub fn block_id_anyway(&self) -> Id<GenBlock> {
        match self {
            SpendablePosition::Transaction(pos) => (*pos.block_id()).into(),
            SpendablePosition::BlockReward(id) => *id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxMainChainIndexError {
    InvalidOutputCount,
    SerializationInvariantError(Id<Block>),
    InvalidTxNumberForBlock(usize, Id<Block>),
}

/// Assuming a transaction is in the mainchain, its index contains two things:
/// 1. The state on whether its outputs are spent
/// 2. The position on where to find that transaction in the mainchain (block + binary position)
/// This struct also is used in a read-modify-write operation to modify the spent-state of a transaction
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct TxMainChainIndex {
    position: SpendablePosition,
    spent: Vec<OutputSpentState>,
}

// TODO: This function should probably operate on the whole block at once.
//  I.e. take a block in and return a sequence of transaction positions.
//  This way, we have to ask for each transaction separately and every time
//  the whole block is encoded, giving O(N^2) complexity in number of transactions
//  which rather unpleasant. Also the implementation could be improved by
//  only asking about offsets, leveraging Encode::encoded_size method, since
//  we are only interested in offsets in the encoded stream, not the contents.
pub fn calculate_tx_index_from_block(
    block: &Block,
    tx_num: usize,
) -> Result<TxMainChainIndex, TxMainChainIndexError> {
    let tx = block
        .transactions()
        .get(tx_num)
        .ok_or_else(|| TxMainChainIndexError::InvalidTxNumberForBlock(tx_num, block.get_id()))?;
    let enc_block = block.encode();
    let enc_tx = tx.encode();
    let offset_tx = enc_block
        .windows(enc_tx.len())
        .enumerate()
        .find_map(|(window_num, enc_data)| (enc_data == enc_tx).then(|| window_num))
        .ok_or_else(|| TxMainChainIndexError::SerializationInvariantError(block.get_id()))?
        .try_into()
        .expect("Number conversion from usize to u32 should not fail here (1)");

    let tx_position = TxMainChainPosition::new(block.get_id(), offset_tx);

    TxMainChainIndex::new(
        SpendablePosition::from(tx_position),
        tx.outputs()
            .len()
            .try_into()
            .expect("Number conversion from usize to u32 should not fail here (3)"),
    )
}

impl TxMainChainIndex {
    fn spend_internal(
        spent_state: &mut OutputSpentState,
        spender: Spender,
    ) -> Result<(), SpendError> {
        match spent_state {
            OutputSpentState::Unspent => {
                *spent_state = OutputSpentState::SpentBy(spender);
                Ok(())
            }
            OutputSpentState::SpentBy(spender) => Err(SpendError::AlreadySpent(spender.clone())),
        }
    }

    fn unspend_internal(spent_state: &mut OutputSpentState) -> Result<(), SpendError> {
        match spent_state {
            OutputSpentState::Unspent => Err(SpendError::AlreadyUnspent),
            OutputSpentState::SpentBy(_) => {
                *spent_state = OutputSpentState::Unspent;
                Ok(())
            }
        }
    }

    pub fn spend(&mut self, index: u32, spender: Spender) -> Result<(), SpendError> {
        let index = index as usize;

        match self.spent.get_mut(index) {
            None => Err(SpendError::OutOfRange {
                tx_id: Some(spender),
                source_output_index: index,
            }),
            Some(spent_state) => Self::spend_internal(spent_state, spender),
        }
    }

    pub fn unspend(&mut self, index: u32) -> Result<(), SpendError> {
        let index = index as usize;

        match self.spent.get_mut(index) {
            None => Err(SpendError::OutOfRange {
                tx_id: None,
                source_output_index: index,
            }),
            Some(spent_state) => Self::unspend_internal(spent_state),
        }
    }

    pub fn position(&self) -> &SpendablePosition {
        &self.position
    }

    pub fn get_spent_state(&self, output_index: u32) -> Result<OutputSpentState, SpendError> {
        match self.spent.get(output_index as usize) {
            None => Err(SpendError::OutOfRange {
                tx_id: None,
                source_output_index: output_index as usize,
            }),
            Some(state) => Ok(state.clone()),
        }
    }

    pub fn all_outputs_spent(&self) -> bool {
        self.spent.iter().all(|s| matches!(s, OutputSpentState::SpentBy(_)))
    }

    pub fn output_count(&self) -> u32 {
        self.spent.len() as u32
    }

    pub fn new(
        position: SpendablePosition,
        output_count: u32,
    ) -> Result<Self, TxMainChainIndexError> {
        if output_count == 0 {
            match position {
                SpendablePosition::Transaction(_) => {
                    return Err(TxMainChainIndexError::InvalidOutputCount)
                }
                SpendablePosition::BlockReward(_) => (), // Block rewards can be forfeited
            };
        }

        let spent_vec = std::iter::repeat_with(|| OutputSpentState::Unspent)
            .take(output_count as usize)
            .collect();
        let res = TxMainChainIndex {
            position,
            spent: spent_vec,
        };
        Ok(res)
    }
}

#[cfg(test)]
mod tests;
