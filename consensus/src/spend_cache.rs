use std::collections::{btree_map::Entry, BTreeMap};

use blockchain_storage::{BlockchainStorageRead, BlockchainStorageWrite};
use common::{
    chain::{block::Block, OutPoint, OutPointSourceId, Spender, Transaction, TxMainChainIndex},
    primitives::{BlockDistance, BlockHeight, Id, Idable},
};

use crate::{BlockError, ConsensusRef, TxRw};

enum CachedInputsOperation {
    Write(TxMainChainIndex),
    Read(TxMainChainIndex),
    Erase,
}

impl CachedInputsOperation {
    fn spend(&mut self, output_index: u32, spender: Spender) -> Result<(), BlockError> {
        let result = match self {
            CachedInputsOperation::Write(tx_index) => CachedInputsOperation::Write({
                tx_index.spend(output_index, spender).map_err(BlockError::from)?;
                tx_index.clone() // TODO: improve by moving out of the enum and consuming it
            }),
            CachedInputsOperation::Read(tx_index) => CachedInputsOperation::Write({
                tx_index.spend(output_index, spender).map_err(BlockError::from)?;
                tx_index.clone() // TODO: improve by moving out of the enum and consuming it
            }),
            CachedInputsOperation::Erase => {
                return Err(BlockError::MissingOutputOrSpentOutputErased)
            }
        };
        let _ = std::mem::replace(self, result);
        Ok(())
    }

    fn unspend(&mut self, output_index: u32) -> Result<(), BlockError> {
        let result = match self {
            CachedInputsOperation::Write(tx_index) => CachedInputsOperation::Write({
                tx_index.unspend(output_index).map_err(BlockError::from)?;
                tx_index.clone() // TODO: improve by moving out of the enum and consuming it
            }),
            CachedInputsOperation::Read(tx_index) => CachedInputsOperation::Write({
                tx_index.unspend(output_index).map_err(BlockError::from)?;
                tx_index.clone() // TODO: improve by moving out of the enum and consuming it
            }),
            CachedInputsOperation::Erase => {
                return Err(BlockError::MissingOutputOrSpentOutputErased)
            }
        };
        let _ = std::mem::replace(self, result);
        Ok(())
    }
}

pub struct ConsumedCachedInputs {
    data: BTreeMap<OutPointSourceId, CachedInputsOperation>,
}

pub struct CachedInputs<'a> {
    db_tx: &'a TxRw<'a>,
    inputs: BTreeMap<OutPointSourceId, CachedInputsOperation>,
}

impl<'a> CachedInputs<'a> {
    pub fn new(db_tx: &'a TxRw<'a>) -> Self {
        Self {
            db_tx,
            inputs: BTreeMap::new(),
        }
    }

    // TODO: add block reward outputs

    fn add_outputs(&mut self, block: &Block, tx: &Transaction) -> Result<(), BlockError> {
        let tx_index = CachedInputsOperation::Write(ConsensusRef::calculate_indices(block, tx)?);
        let tx_id = tx.get_id();
        match self.inputs.entry(OutPointSourceId::from(tx_id)) {
            Entry::Occupied(_) => return Err(BlockError::OutputAlreadyPresentInInputsCache),
            Entry::Vacant(entry) => entry.insert(tx_index),
        };
        Ok(())
    }

    fn remove_outputs(&mut self, tx: &Transaction) -> Result<(), BlockError> {
        self.inputs.insert(
            OutPointSourceId::from(tx.get_id()),
            CachedInputsOperation::Erase,
        );
        Ok(())
    }

    fn check_blockreward_maturity(
        &self,
        spending_block_id: &Id<Block>,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<(), BlockError> {
        let source_block_index = self.db_tx.get_block_index(spending_block_id)?;
        let source_block_index =
            source_block_index.ok_or(BlockError::InvariantBrokenSourceBlockIndexNotFound)?;
        let source_height = source_block_index.get_block_height();
        let actual_distance =
            (*spend_height - source_height).ok_or(BlockError::BlockHeightArithmeticError)?;
        if actual_distance < *blockreward_maturity {
            return Err(BlockError::ImmatureBlockRewardSpend);
        }
        Ok(())
    }

    fn fetch_and_cache(
        &mut self,
        outpoint: &OutPoint,
    ) -> Result<&mut CachedInputsOperation, BlockError> {
        let result = match self.inputs.entry(outpoint.get_tx_id()) {
            Entry::Occupied(entry) => {
                // If tx index was loaded
                entry.into_mut()
            }
            Entry::Vacant(entry) => {
                // Maybe the utxo is in a previous block?
                let tx_index = self
                    .db_tx
                    .get_mainchain_tx_index(&outpoint.get_tx_id())?
                    .ok_or(BlockError::MissingOutputOrSpent)?;
                entry.insert(CachedInputsOperation::Read(tx_index))
            }
        };
        Ok(result)
    }

    pub fn spend(
        &mut self,
        block: &Block,
        tx: &Transaction,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<(), BlockError> {
        // spend inputs of this transaction
        for input in tx.get_inputs() {
            let outpoint = input.get_outpoint();

            if let OutPointSourceId::BlockReward(block_id) = outpoint.get_tx_id() {
                self.check_blockreward_maturity(&block_id, spend_height, blockreward_maturity)?;
            }

            let prev_tx_index_op = self.fetch_and_cache(outpoint)?;
            prev_tx_index_op
                .spend(outpoint.get_output_index(), Spender::from(tx.get_id()))
                .map_err(BlockError::from)?;
        }

        // add the outputs of this transaction to the cache
        self.add_outputs(block, tx)?;

        Ok(())
    }

    pub fn unspend(&mut self, tx: &Transaction) -> Result<(), BlockError> {
        // Delete TxMainChainIndex for the current tx
        self.remove_outputs(tx)?;

        // unspend inputs
        for input in tx.get_inputs() {
            let outpoint = input.get_outpoint();

            let input_tx_id_op = self.fetch_and_cache(outpoint)?;

            // Mark input as unspend
            input_tx_id_op.unspend(outpoint.get_output_index()).map_err(BlockError::from)?;
        }
        Ok(())
    }

    pub fn consume(self) -> Result<ConsumedCachedInputs, BlockError> {
        Ok(ConsumedCachedInputs { data: self.inputs })
    }

    pub fn flush_to_storage(
        db_tx: &mut TxRw<'a>,
        input_data: ConsumedCachedInputs,
    ) -> Result<(), BlockError> {
        for (tx_id, tx_index_op) in input_data.data {
            match tx_index_op {
                CachedInputsOperation::Write(ref tx_index) => {
                    db_tx.set_mainchain_tx_index(&tx_id, tx_index)?
                }
                CachedInputsOperation::Read(_) => (),
                CachedInputsOperation::Erase => db_tx.del_mainchain_tx_index(&tx_id)?,
            }
        }
        Ok(())
    }
}

// TODO: write tests for CachedInputs that covers all possible mutations
