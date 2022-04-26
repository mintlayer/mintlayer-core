#![allow(dead_code)]

use crate::{Error, Store, UndoRead, UndoWrite, UtxoRead, UtxoWrite};
use common::chain::block::Block;
use common::chain::OutPoint;
use common::primitives::Id;
use utxo::{utxo_storage::UtxosPersistentStorage, BlockUndo, Utxo};

#[derive(Clone)]
pub struct UtxoDBInterface {
    store: Store,
}

impl UtxoDBInterface {
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

impl UtxosPersistentStorage for UtxoDBInterface {
    fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> Result<(), utxo::Error> {
        self.store.add_utxo(outpoint, entry).map_err(|e| e.into())
    }
    fn del_utxo(&mut self, outpoint: &OutPoint) -> Result<(), utxo::Error> {
        self.store.del_utxo(outpoint).map_err(|e| e.into())
    }
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, utxo::Error> {
        self.store.get_utxo(outpoint).map_err(|e| e.into())
    }
    fn set_best_block_id(&mut self, block_id: &Id<Block>) -> Result<(), utxo::Error> {
        // TODO: fix; don't store in general block id
        self.store.set_best_block_for_utxos(block_id).map_err(|e| e.into())
    }
    fn get_best_block_id(&self) -> Result<Option<Id<Block>>, utxo::Error> {
        // TODO: fix; don't get general block id
        self.store.get_best_block_for_utxos().map_err(|e| e.into())
    }

    fn set_undo_data(&mut self, id: Id<Block>, undo: &BlockUndo) -> Result<(), utxo::Error> {
        self.store.add_undo_data(id, undo).map_err(|e| e.into())
    }

    fn del_undo_data(&mut self, id: Id<Block>) -> Result<(), utxo::Error> {
        self.store.del_undo_data(id).map_err(|e| e.into())
    }

    fn get_undo_data(&self, id: Id<Block>) -> Result<Option<BlockUndo>, utxo::Error> {
        self.store.get_undo_data(id).map_err(|e| e.into())
    }
}

impl From<Error> for utxo::Error {
    fn from(e: Error) -> Self {
        utxo::Error::DBError(format!("{:?}", e))
    }
}

// TODO: write basic tests for reads/writes in db for UtxoDBInterface
#[cfg(test)]
mod test {
    use super::*;
    use common::chain::{Destination, OutPointSourceId, Transaction, TxInput, TxOutput};
    use common::primitives::consensus_data::ConsensusData;
    use common::primitives::{Amount, BlockHeight, Idable, H256};
    use crypto::random::{make_pseudo_rng, Rng};
    use itertools::Itertools;
    use num_traits::FromPrimitive;
    use rand::seq;
    use utxo::utxo_storage::UtxoDB;
    use utxo::{flush_to_base, UtxosCache, UtxosView};

    fn create_tx_outputs(size: u32) -> Vec<TxOutput> {
        let mut tx_outputs = vec![];
        for _ in 0..size {
            let random_amt = make_pseudo_rng().gen_range(1..u128::MAX);
            tx_outputs.push(TxOutput::new(
                Amount::new(random_amt),
                Destination::PublicKey,
            ));
        }

        tx_outputs
    }

    fn create_transactions(inputs: Vec<TxInput>, num_of_txs: usize) -> Vec<Transaction> {
        // distribute the inputs on the number of the transactions specified.
        let input_size = inputs.len() / num_of_txs;

        // create the multiple transactions
        inputs
            .chunks(input_size)
            .into_iter()
            .map(|inputs| {
                Transaction::new(0x00, inputs.to_vec(), vec![], 0)
                    .expect("should create a transaction successfully")
            })
            .collect_vec()
    }

    fn create_block(inputs: Vec<TxInput>, prev_block_id: Id<Block>, num_of_txs: usize) -> Block {
        let txs = create_transactions(inputs, num_of_txs);
        Block::new(txs, prev_block_id, 1, ConsensusData::None)
            .expect("should be able to create a block")
    }

    fn convert_to_utxo(output: TxOutput, height: u64, output_idx: usize) -> (OutPoint, Utxo) {
        let utxo_id: Id<Block> = Id::new(&H256::random());
        let id = OutPointSourceId::BlockReward(utxo_id);
        let idx = u32::from_usize(output_idx).expect("it should convert with no problems");
        let outpoint = OutPoint::new(id, idx);
        let utxo = Utxo::new(output, true, BlockHeight::new(height));

        (outpoint, utxo)
    }

    fn initialize_db(
        db_interface: &mut UtxoDBInterface,
        tx_outputs_size: u32,
    ) -> (Id<Block>, Vec<OutPoint>) {
        let best_block_id: Id<Block> = Id::new(&H256::random());
        assert!(db_interface.set_best_block_id(&best_block_id).is_ok());

        // let's populate the db with outputs.
        let tx_outputs = create_tx_outputs(tx_outputs_size);

        // collect outpoints for spending later
        let outpoints = tx_outputs
            .into_iter()
            .enumerate()
            .map(|(idx, output)| {
                let (outpoint, utxo) = convert_to_utxo(output, 0, idx);
                // immediately add to the db
                assert!(db_interface.set_utxo(&outpoint, utxo).is_ok());

                outpoint
            })
            .collect_vec();

        (best_block_id, outpoints)
    }

    // randomly select some outpoints to spend
    fn create_tx_inputs(outpoints: &Vec<OutPoint>) -> Vec<TxInput> {
        let mut rng = make_pseudo_rng();
        let to_spend =
            seq::index::sample(&mut rng, outpoints.len(), outpoints.len() / 2).into_vec();
        to_spend
            .into_iter()
            .map(|idx| {
                let outpoint = outpoints.get(idx).expect("should return an outpoint");
                TxInput::new(outpoint.get_tx_id(), outpoint.get_output_index(), vec![])
            })
            .collect_vec()
    }

    #[test]
    fn simulation_test() {
        let store = Store::new_empty().unwrap();
        let mut db_interface = UtxoDBInterface::new(store);

        // initializing the db with existing utxos.
        let (best_block_id, outpoints) = initialize_db(&mut db_interface, 10);
        // create the TxInputs for spending.
        let tx_inputs = create_tx_inputs(&outpoints);

        let mut db_interface_clone = db_interface.clone();
        let mut db = UtxoDB::new(&mut db_interface_clone);
        // let's check that each tx_input exists in the db, using the UtxoDB
        tx_inputs.iter().for_each(|input| {
            let outpoint = input.get_outpoint();
            assert!(db.has_utxo(outpoint));
        });

        // test the spend
        let (block, block_undo) = {
            // create a view based on the db.
            let mut view = db.derive_cache();

            // create a new block to spend.
            let block = create_block(tx_inputs.clone(), best_block_id, 3);

            // spend the block
            let block_undo = {
                let undos = block
                    .get_transactions()
                    .iter()
                    .map(|tx| {
                        view.spend_utxos(tx, BlockHeight::new(1)).expect("should spend okay.")
                    })
                    .collect_vec();
                BlockUndo::new(undos)
            };

            // create the base and flush it.
            {
                let mut base = UtxoDB::new(&mut db_interface);
                assert!(flush_to_base(view, &mut base).is_ok());
            }

            (block, block_undo)
        };

        // check that all in tx_inputs do NOT exist
        tx_inputs.iter().for_each(|input| {
            assert_eq!(db.get_utxo(input.get_outpoint()), None);
        });

        // save the undo data to the db.
        {
            assert!(db_interface.set_best_block_id(&block.get_id()).is_ok());
            assert!(db_interface.set_undo_data(block.get_id(), &block_undo).is_ok());

            let block_undo_from_db = db_interface
                .get_undo_data(block.get_id())
                .expect("getting undo data should not cause any problems")
                .expect("should have undo data.");
            assert_eq!(&block_undo, &block_undo_from_db);
        }

        // check that the inputs of the block do not exist in the utxo column.
        {
            block.get_transactions().iter().for_each(|tx| {
                tx.get_inputs().iter().for_each(|input| {
                    assert_eq!(db_interface.get_utxo(input.get_outpoint()), Ok(None));
                });
            });
        }

        // let's try to reverse it
        {
            // get the best_block_id
            let best_block_id = db.get_best_block_hash().expect("should return the best block id");

            let undo_file = db
                .get_undo_data(best_block_id.clone())
                .expect("query should not fail")
                .expect("should return the undo file");

            assert_eq!(undo_file.inner().len(), tx_inputs.len());

            let mut view = UtxosCache::default();
            // set the best block to the previous one.
            view.set_best_block(block.get_prev_block_id());

            // get the block txinputs, and add them to the view.
            block.get_transactions().iter().enumerate().for_each(|(idx, tx)| {
                // use the undo to get the utxos
                let undo = undo_file.inner().get(idx).expect("it should return undo");
                let undos = undo.inner();

                tx.get_inputs().iter().enumerate().for_each(|(in_idx, input)| {
                    let utxo = undos.get(in_idx).expect("it should have utxo");
                    assert!(view.add_utxo(utxo.clone(), input.get_outpoint(), true).is_ok());
                });
            });

            assert!(flush_to_base(view, &mut db).is_ok());
        }

        // check that all the tx_inputs exists.
        tx_inputs.iter().for_each(|inputs| {
            assert!(db.get_utxo(inputs.get_outpoint()).is_some());
        });

        // create dummy tx_inputs for spending.
        {
            let rnd = make_pseudo_rng().gen_range(5..20);

            let tx_inputs: Vec<TxInput> = (0..rnd)
                .into_iter()
                .map(|i| {
                    let id: Id<Block> = Id::new(&H256::random());
                    let id = OutPointSourceId::BlockReward(id);

                    TxInput::new(id, i, vec![])
                })
                .collect();

            let id = db.get_best_block_hash().expect("it should return an id");
            let block = create_block(tx_inputs, id, 5);

            let mut view = db.derive_cache();

            let tx = block.get_transactions().get(0).expect("should return a transaction");
            assert!(view.spend_utxos(tx, BlockHeight::new(2)).is_err());
            // try to spend the transaction
        }
    }
}
