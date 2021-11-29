use crate::primitives::H256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputSpentState {
    Unspent,
    SpentBy(H256),
}

/// A transaction is stored in the database as part of a block,
/// specifically in the mainchain.
/// To find a transaction in the database, we first locate the block that contains it,
/// and we then read the binary data at a specific offset and size, which we deserialize
/// to get the transaction.
/// This struct represents the position of a transaction in the database
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxMainChainPosition {
    block_id: H256,
    byte_offset_in_block: usize,
    serialized_size: usize,
}

impl TxMainChainPosition {
    pub fn new(block_id: &H256, byte_offset_in_block: usize, serialized_size: usize) -> Self {
        TxMainChainPosition {
            block_id: *block_id,
            byte_offset_in_block,
            serialized_size,
        }
    }

    pub fn get_block_id(&self) -> &H256 {
        &self.block_id
    }

    pub fn get_byte_offset_in_block(&self) -> usize {
        self.byte_offset_in_block
    }

    pub fn get_serialized_size(&self) -> usize {
        self.serialized_size
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpendError {
    AlreadySpent(H256),
    AlreadyUnspent,
    OutOfRange,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxMainChainIndexError {
    InvalidOutputCount,
}

/// Assuming a transaction is in the mainchain, its index contains two things:
/// 1. The state on whether its outputs are spent
/// 2. The position on where to find that transaction in the mainchain (block + bianry position)#[derive(Clone, Debug, PartialEq, Eq)]
/// This struct also is used in a read-modify-write operation to modify the spent-state of a transaction
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxMainChainIndex {
    position: TxMainChainPosition,
    spent: Vec<OutputSpentState>,
}

impl TxMainChainIndex {
    fn spend_internal(
        spent_state: &mut OutputSpentState,
        spender: &H256,
    ) -> Result<(), SpendError> {
        match spent_state {
            OutputSpentState::Unspent => {
                *spent_state = OutputSpentState::SpentBy(*spender);
                return Ok(());
            }
            OutputSpentState::SpentBy(spender) => {
                return Err(SpendError::AlreadySpent(*spender));
            }
        }
    }

    fn unspend_internal(spent_state: &mut OutputSpentState) -> Result<(), SpendError> {
        match spent_state {
            OutputSpentState::Unspent => {
                return Err(SpendError::AlreadyUnspent);
            }
            OutputSpentState::SpentBy(_) => {
                *spent_state = OutputSpentState::Unspent;
                return Ok(());
            }
        }
    }

    pub fn spend(&mut self, index: u32, spender: &H256) -> Result<(), SpendError> {
        let index = index as usize;
        if index >= self.spent.len() {
            return Err(SpendError::OutOfRange);
        }

        match self.spent.get_mut(index) {
            None => return Err(SpendError::OutOfRange),
            Some(spent_state) => {
                return Self::spend_internal(spent_state, spender);
            }
        }
    }

    pub fn unspend(&mut self, index: u32) -> Result<(), SpendError> {
        let index = index as usize;
        if index >= self.spent.len() {
            return Err(SpendError::OutOfRange);
        }

        match self.spent.get_mut(index) {
            None => return Err(SpendError::OutOfRange),
            Some(spent_state) => {
                return Self::unspend_internal(spent_state);
            }
        }
    }

    pub fn get_tx_position(&self) -> &TxMainChainPosition {
        &self.position
    }

    pub fn get_spent_state(&self, output_index: u32) -> Result<OutputSpentState, SpendError> {
        match self.spent.get(output_index as usize) {
            None => Err(SpendError::OutOfRange),
            Some(state) => Ok(*state),
        }
    }

    pub fn all_outputs_spent(&self) -> bool {
        self.spent.iter().all(|s| match s {
            OutputSpentState::SpentBy(_) => true,
            _ => false,
        })
    }

    pub fn get_output_count(&self) -> u32 {
        self.spent.len() as u32
    }

    pub fn new(
        tx_position: TxMainChainPosition,
        output_count: u32,
    ) -> Result<Self, TxMainChainIndexError> {
        if output_count <= 0 {
            return Err(TxMainChainIndexError::InvalidOutputCount);
        }

        let spent_vec = std::iter::repeat_with(|| OutputSpentState::Unspent)
            .take(output_count as usize)
            .collect();
        let res = TxMainChainIndex {
            position: tx_position,
            spent: spent_vec,
        };
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn invalid_output_count() {
        let block_id =
            H256::from_str("000000000000000000000000000000000000000000000000000000000000007b");
        let pos = TxMainChainPosition::new(&block_id.unwrap(), 1, 2);
        let tx_index = TxMainChainIndex::new(pos, 0);
        assert_eq!(
            tx_index.unwrap_err(),
            TxMainChainIndexError::InvalidOutputCount
        );
    }

    #[test]
    fn basic_spending() {
        let block_id =
            H256::from_str("000000000000000000000000000000000000000000000000000000000000007b");
        let pos = TxMainChainPosition::new(&block_id.unwrap(), 1, 2);
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

        // check that all are unspent
        assert_eq!(tx_index.position.block_id, H256::from_low_u64_be(123));
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

        let tx_spending_output_0 =
            H256::from_str("0000000000000000000000000000000000000000000000000000000000000333")
                .unwrap();
        let tx_spending_output_1 =
            H256::from_str("0000000000000000000000000000000000000000000000000000000000000444")
                .unwrap();
        let tx_spending_output_2 =
            H256::from_str("0000000000000000000000000000000000000000000000000000000000000555")
                .unwrap();

        // spend one output
        let spend_0_res = tx_index.spend(0, &tx_spending_output_0);
        assert!(spend_0_res.is_ok());

        // check state
        assert_eq!(
            tx_index.get_spent_state(0).unwrap(),
            OutputSpentState::SpentBy(tx_spending_output_0)
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
            tx_index.spend(0, &tx_spending_output_1).unwrap_err(),
            SpendError::AlreadySpent(tx_spending_output_0)
        );

        // spend all other outputs
        assert!(tx_index.spend(1, &tx_spending_output_1).is_ok());
        assert!(tx_index.spend(2, &tx_spending_output_2).is_ok());

        // check that all are spent
        assert!(tx_index.all_outputs_spent());

        assert_eq!(
            tx_index.get_spent_state(0).unwrap(),
            OutputSpentState::SpentBy(tx_spending_output_0)
        );
        assert_eq!(
            tx_index.get_spent_state(1).unwrap(),
            OutputSpentState::SpentBy(tx_spending_output_1)
        );
        assert_eq!(
            tx_index.get_spent_state(2).unwrap(),
            OutputSpentState::SpentBy(tx_spending_output_2)
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
            OutputSpentState::SpentBy(tx_spending_output_1)
        );
        assert_eq!(
            tx_index.get_spent_state(2).unwrap(),
            OutputSpentState::SpentBy(tx_spending_output_2)
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
