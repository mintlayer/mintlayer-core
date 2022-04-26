use super::Transaction;
use crate::{
    chain::block::Block,
    primitives::{Id, Idable},
};
use parity_scale_codec::Encode;
use parity_scale_codec_derive::{Decode as DecodeDer, Encode as EncodeDer};

#[derive(Clone, Debug, PartialEq, Eq, EncodeDer, DecodeDer)]
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

#[derive(Clone, Debug, PartialEq, Eq, EncodeDer, DecodeDer)]
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
#[derive(Clone, Debug, PartialEq, Eq, Encode, DecodeDer)]
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
#[derive(Clone, Debug, PartialEq, Eq, EncodeDer, DecodeDer)]
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
#[derive(Clone, Debug, PartialEq, Eq, EncodeDer, DecodeDer)]
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
mod tests {
    use super::*;
    use crate::primitives::H256;
    use std::str::FromStr;

    #[test]
    fn invalid_output_count() {
        let block_id =
            H256::from_str("000000000000000000000000000000000000000000000000000000000000007b")
                .unwrap();
        let pos = TxMainChainPosition::new(block_id.into(), 1, 2).into();
        let tx_index = TxMainChainIndex::new(pos, 0);
        assert_eq!(
            tx_index.unwrap_err(),
            TxMainChainIndexError::InvalidOutputCount
        );
    }

    #[test]
    fn basic_spending() {
        let block_id =
            H256::from_str("000000000000000000000000000000000000000000000000000000000000007b")
                .unwrap();
        let pos = TxMainChainPosition::new(block_id.into(), 1, 2).into();
        let mut tx_index = TxMainChainIndex::new(pos, 3).unwrap();

        // ensure index accesses are correct
        assert!(tx_index.get_spent_state(0).is_ok());
        assert!(tx_index.get_spent_state(1).is_ok());
        assert!(tx_index.get_spent_state(2).is_ok());
        assert_eq!(
            tx_index.get_spent_state(3).unwrap_err(),
            SpendError::OutOfRange
        );
        assert_eq!(
            tx_index.get_spent_state(4).unwrap_err(),
            SpendError::OutOfRange
        );
        assert_eq!(tx_index.get_output_count(), 3);

        let p = match tx_index.position {
            SpendablePosition::Transaction(ref p) => p,
            _ => {
                unreachable!();
            }
        };

        // check that all are unspent
        assert_eq!(p.block_id, H256::from_low_u64_be(123).into());
        for output in &tx_index.spent {
            assert_eq!(*output, OutputSpentState::Unspent);
        }
        assert!(!tx_index.all_outputs_spent());

        for i in 0..tx_index.get_output_count() {
            assert_eq!(
                tx_index.get_spent_state(i).unwrap(),
                OutputSpentState::Unspent
            );
        }

        let tx_spending_output_0 = Id::<Transaction>::new(
            &H256::from_str("0000000000000000000000000000000000000000000000000000000000000333")
                .unwrap(),
        );
        let tx_spending_output_1 = Id::<Block>::new(
            &H256::from_str("0000000000000000000000000000000000000000000000000000000000000444")
                .unwrap(),
        );
        let tx_spending_output_2 = Id::<Transaction>::new(
            &H256::from_str("0000000000000000000000000000000000000000000000000000000000000555")
                .unwrap(),
        );

        // spend one output
        let spend_0_res = tx_index.spend(0, tx_spending_output_0.clone().into());
        assert!(spend_0_res.is_ok());

        // check state
        assert_eq!(
            tx_index.get_spent_state(0).unwrap(),
            OutputSpentState::SpentBy(tx_spending_output_0.clone().into())
        );
        assert_eq!(
            tx_index.get_spent_state(1).unwrap(),
            OutputSpentState::Unspent
        );
        assert_eq!(
            tx_index.get_spent_state(2).unwrap(),
            OutputSpentState::Unspent
        );

        assert!(!tx_index.all_outputs_spent());

        // attempt double-spend
        assert_eq!(
            tx_index.spend(0, tx_spending_output_1.clone().into()).unwrap_err(),
            SpendError::AlreadySpent(tx_spending_output_0.clone().into())
        );

        // spend all other outputs
        assert!(tx_index.spend(1, tx_spending_output_1.clone().into()).is_ok());
        assert!(tx_index.spend(2, tx_spending_output_2.clone().into()).is_ok());

        // check that all are spent
        assert!(tx_index.all_outputs_spent());

        assert_eq!(
            tx_index.get_spent_state(0).unwrap(),
            OutputSpentState::SpentBy(tx_spending_output_0.into())
        );
        assert_eq!(
            tx_index.get_spent_state(1).unwrap(),
            OutputSpentState::SpentBy(tx_spending_output_1.clone().into())
        );
        assert_eq!(
            tx_index.get_spent_state(2).unwrap(),
            OutputSpentState::SpentBy(tx_spending_output_2.clone().into())
        );

        // unspend output 1
        assert!(tx_index.unspend(0).is_ok());

        // cannot "double unspend"
        assert_eq!(tx_index.unspend(0).unwrap_err(), SpendError::AlreadyUnspent);

        // check the new unspent state
        assert!(!tx_index.all_outputs_spent());
        assert_eq!(
            tx_index.get_spent_state(0).unwrap(),
            OutputSpentState::Unspent
        );
        assert_eq!(
            tx_index.get_spent_state(1).unwrap(),
            OutputSpentState::SpentBy(tx_spending_output_1.into())
        );
        assert_eq!(
            tx_index.get_spent_state(2).unwrap(),
            OutputSpentState::SpentBy(tx_spending_output_2.into())
        );

        // unspent the rest
        assert!(tx_index.unspend(1).is_ok());
        assert!(tx_index.unspend(2).is_ok());

        // check the new unspent state
        assert!(!tx_index.all_outputs_spent());
        assert_eq!(
            tx_index.get_spent_state(0).unwrap(),
            OutputSpentState::Unspent
        );
        assert_eq!(
            tx_index.get_spent_state(1).unwrap(),
            OutputSpentState::Unspent
        );
        assert_eq!(
            tx_index.get_spent_state(2).unwrap(),
            OutputSpentState::Unspent
        );
    }
}
