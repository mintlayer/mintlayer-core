use std::collections::{btree_map::Entry, BTreeMap};

use blockchain_storage::{BlockchainStorageRead, BlockchainStorageWrite};
use common::{
    chain::{block::Block, OutPointSourceId, Spender, Transaction, TxMainChainIndex},
    primitives::{Id, Idable},
};

use crate::{BlockError, ConsensusRef, TxRw};

enum CachedInputsOperation {
    Write(TxMainChainIndex),
    Erase,
}

pub struct ConsumedCachedInputs {
    data: BTreeMap<Id<Transaction>, CachedInputsOperation>,
}

#[derive()]
pub struct CachedInputs<'a> {
    db_tx: &'a TxRw<'a>,
    inputs: BTreeMap<Id<Transaction>, CachedInputsOperation>,
}

impl<'a> CachedInputs<'a> {
    pub fn new(db_tx: &'a TxRw<'a>) -> Self {
        Self {
            db_tx,
            inputs: BTreeMap::new(),
        }
    }

    fn add_outputs(&mut self, block: &Block, tx: &Transaction) -> Result<(), BlockError> {
        let tx_index = CachedInputsOperation::Write(ConsensusRef::calculate_indices(block, tx)?);
        let tx_id = tx.get_id();
        match self.inputs.entry(tx_id) {
            Entry::Occupied(_) => return Err(BlockError::OutputAlreadyPresentInInputs),
            Entry::Vacant(entry) => entry.insert(tx_index),
        };
        Ok(())
    }

    pub fn spend(&mut self, block: &Block, tx: &Transaction) -> Result<(), BlockError> {
        for input in tx.get_inputs() {
            let outpoint = input.get_outpoint();
            match outpoint.get_tx_id() {
                OutPointSourceId::Transaction(prev_tx_id) => {
                    let prev_tx_index_op = match self.inputs.entry(prev_tx_id.clone()) {
                        Entry::Occupied(entry) => {
                            // If tx index was loaded
                            entry.into_mut()
                        }
                        Entry::Vacant(entry) => {
                            // Maybe the utxo is in a previous block?
                            let tx_index = self
                                .db_tx
                                .get_mainchain_tx_index(&prev_tx_id)?
                                .ok_or(BlockError::MissingOutputOrSpent)?;
                            entry.insert(CachedInputsOperation::Write(tx_index))
                        }
                    };

                    let prev_tx_index = match prev_tx_index_op {
                        CachedInputsOperation::Write(e) => e,
                        CachedInputsOperation::Erase => {
                            return Err(BlockError::UnspendInvariantErrorOutputNotPresent)
                        }
                    };

                    if outpoint.get_output_index() >= prev_tx_index.get_output_count() {
                        return Err(BlockError::OutputIndexOutOfRange);
                    }

                    prev_tx_index
                        .spend(outpoint.get_output_index(), Spender::from(tx.get_id()))
                        .map_err(BlockError::from)?;
                }
                OutPointSourceId::BlockReward(_block_id) => unimplemented!(),
            }
        }

        self.add_outputs(block, tx)?;

        Ok(())
    }

    pub fn unspend(&mut self, tx: &Transaction) -> Result<(), BlockError> {
        // Delete TxMainChainIndex for the current tx
        self.inputs.insert(tx.get_id(), CachedInputsOperation::Erase);

        // unspend inputs
        for input in tx.get_inputs() {
            let input_index = input.get_outpoint().get_output_index();
            let input_tx_id = match input.get_outpoint().get_tx_id() {
                OutPointSourceId::Transaction(tx_id) => tx_id,
                OutPointSourceId::BlockReward(_) => {
                    unimplemented!()
                }
            };

            let tx_index_op = match self.inputs.entry(input_tx_id.clone()) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(CachedInputsOperation::Write(
                    self.db_tx.get_mainchain_tx_index(&input_tx_id)?.ok_or(BlockError::Unknown)?,
                )),
            };

            let tx_index = match tx_index_op {
                CachedInputsOperation::Write(e) => e,
                CachedInputsOperation::Erase => return Err(BlockError::MissingOutputOrSpent),
            };

            if input_index >= tx_index.get_output_count() {
                return Err(BlockError::OutputIndexOutOfRange);
            }
            // Mark input as unspend
            tx_index.unspend(input_index).map_err(BlockError::from)?;
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
                    db_tx.set_mainchain_tx_index(&tx_id, &tx_index)?
                }
                CachedInputsOperation::Erase => db_tx.del_mainchain_tx_index(&tx_id)?,
            }
        }
        Ok(())
    }
}
