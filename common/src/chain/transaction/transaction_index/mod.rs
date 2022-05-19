use super::Transaction;
use crate::{
    chain::block::Block,
    primitives::{Id, Idable},
};
use serialization::{Decode, Encode};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Spender {
    #[codec(index = 0)]
    RegularInput(Id<Transaction>),
    #[codec(index = 1)]
    StakeKernel(Id<Block>),
}

impl From<Id<Transaction>> for Spender {
    fn from(spender: Id<Transaction>) -> Spender {
        Spender::RegularInput(spender)
    }
}

impl From<Id<Block>> for Spender {
    fn from(spender: Id<Block>) -> Spender {
        Spender::StakeKernel(spender)
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
    serialized_size: u32,
}

impl TxMainChainPosition {
    pub fn new(block_id: Id<Block>, byte_offset_in_block: u32, serialized_size: u32) -> Self {
        TxMainChainPosition {
            block_id,
            byte_offset_in_block,
            serialized_size,
        }
    }

    pub fn get_block_id(&self) -> &Id<Block> {
        &self.block_id
    }

    pub fn get_byte_offset_in_block(&self) -> u32 {
        self.byte_offset_in_block
    }

    pub fn get_serialized_size(&self) -> u32 {
        self.serialized_size
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpendError {
    AlreadySpent(Spender),
    AlreadyUnspent,
    OutOfRange,
}

/// This enum represents that we can either spend from a block reward or a regular transaction
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum SpendablePosition {
    Transaction(TxMainChainPosition),
    BlockReward(Id<Block>),
}

impl From<TxMainChainPosition> for SpendablePosition {
    fn from(pos: TxMainChainPosition) -> SpendablePosition {
        SpendablePosition::Transaction(pos)
    }
}

impl From<Id<Block>> for SpendablePosition {
    fn from(pos: Id<Block>) -> SpendablePosition {
        SpendablePosition::BlockReward(pos)
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

    let tx_position = TxMainChainPosition::new(
        block.get_id(),
        offset_tx,
        enc_tx
            .len()
            .try_into()
            .expect("Number conversion from usize to u32 should not fail here (2)"),
    );

    TxMainChainIndex::new(
        SpendablePosition::from(tx_position),
        tx.get_outputs()
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
        if index >= self.spent.len() {
            return Err(SpendError::OutOfRange);
        }

        match self.spent.get_mut(index) {
            None => Err(SpendError::OutOfRange),
            Some(spent_state) => Self::spend_internal(spent_state, spender),
        }
    }

    pub fn unspend(&mut self, index: u32) -> Result<(), SpendError> {
        let index = index as usize;
        if index >= self.spent.len() {
            return Err(SpendError::OutOfRange);
        }

        match self.spent.get_mut(index) {
            None => Err(SpendError::OutOfRange),
            Some(spent_state) => Self::unspend_internal(spent_state),
        }
    }

    pub fn get_position(&self) -> &SpendablePosition {
        &self.position
    }

    pub fn get_spent_state(&self, output_index: u32) -> Result<OutputSpentState, SpendError> {
        match self.spent.get(output_index as usize) {
            None => Err(SpendError::OutOfRange),
            Some(state) => Ok(state.clone()),
        }
    }

    pub fn all_outputs_spent(&self) -> bool {
        self.spent.iter().all(|s| matches!(s, OutputSpentState::SpentBy(_)))
    }

    pub fn get_output_count(&self) -> u32 {
        self.spent.len() as u32
    }

    pub fn new(
        position: SpendablePosition,
        output_count: u32,
    ) -> Result<Self, TxMainChainIndexError> {
        if output_count == 0 {
            return Err(TxMainChainIndexError::InvalidOutputCount);
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
