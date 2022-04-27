#![allow(dead_code, unused_variables, unused_imports)]
// todo: remove ^ when all untested codes are tested

use std::collections::{BTreeMap, HashMap};

use crate::utxo_impl::{FlushableUtxoView, Utxo, UtxosCache, UtxosView};
use crate::{BlockUndo, Error};
use common::chain::block::Block;
use common::chain::OutPoint;
use common::primitives::{Id, H256};

pub trait UtxosPersistentStorage {
    fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> Result<(), crate::Error>;
    fn del_utxo(&mut self, outpoint: &OutPoint) -> Result<(), crate::Error>;
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, crate::Error>;
    fn set_best_block_id(&mut self, block_id: &Id<Block>) -> Result<(), crate::Error>;
    fn get_best_block_id(&self) -> Result<Option<Id<Block>>, crate::Error>;

    fn set_undo_data(&mut self, id: Id<Block>, undo: &BlockUndo) -> Result<(), crate::Error>;
    fn del_undo_data(&mut self, id: Id<Block>) -> Result<(), crate::Error>;
    fn get_undo_data(&self, id: Id<Block>) -> Result<Option<BlockUndo>, crate::Error>;
}

pub struct UtxoDB<'a, S: UtxosPersistentStorage>(&'a mut S);

impl<'a, S: UtxosPersistentStorage> UtxoDB<'a, S> {
    pub fn new(store: &'a mut S) -> Self {
        Self(store)
    }

    pub fn set_undo_data(&mut self, id: Id<Block>, undo: &BlockUndo) -> Result<(), crate::Error> {
        self.0.set_undo_data(id, undo)
    }

    pub fn del_undo_data(&mut self, id: Id<Block>) -> Result<(), crate::Error> {
        self.0.del_undo_data(id)
    }

    pub fn get_undo_data(&self, id: Id<Block>) -> Result<Option<BlockUndo>, crate::Error> {
        self.0.get_undo_data(id)
    }
}

impl<'a, S: UtxosPersistentStorage> UtxosView for UtxoDB<'a, S> {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<Utxo> {
        match self.0.get_utxo(outpoint) {
            Ok(res) => res,
            Err(_) => {
                //todo: handle errors
                None
            }
        }
    }

    fn has_utxo(&self, outpoint: &OutPoint) -> bool {
        self.get_utxo(outpoint).is_some()
    }

    fn get_best_block_hash(&self) -> Option<Id<Block>> {
        match self.0.get_best_block_id() {
            Ok(opt_id) => opt_id,
            Err(_) => {
                // TODO: handle errors
                None
            }
        }
    }

    fn estimated_size(&self) -> usize {
        todo!()
    }

    fn derive_cache(&self) -> UtxosCache {
        let mut cache = UtxosCache::new(self);
        if let Some(hash) = self.get_best_block_hash() {
            cache.set_best_block(hash);
        }
        cache
    }
}

impl<'a, S: UtxosPersistentStorage> FlushableUtxoView for UtxoDB<'a, S> {
    fn batch_write(
        &mut self,
        utxos: crate::utxo_impl::ConsumedUtxoCache,
    ) -> Result<(), crate::Error> {
        // check each entry if it's dirty. Only then will the db be updated.
        for (key, entry) in utxos.container {
            let outpoint = &key;
            if entry.is_dirty() {
                if let Some(utxo) = entry.utxo() {
                    self.0.set_utxo(outpoint, utxo)?;
                } else {
                    // entry is spent
                    self.0.del_utxo(outpoint)?;
                };
            }
        }
        self.0.set_best_block_id(&utxos.best_block)?;
        Ok(())
    }
}

#[derive(Clone)]
struct UtxoInMemoryDBInterface {
    store: BTreeMap<OutPoint, Utxo>,
    undo_store: HashMap<H256, BlockUndo>,
    best_block_id: Option<Id<Block>>,
}

impl UtxoInMemoryDBInterface {
    fn new() -> Self {
        Self {
            store: BTreeMap::new(),
            undo_store: HashMap::new(),
            best_block_id: None,
        }
    }
}

impl UtxosPersistentStorage for UtxoInMemoryDBInterface {
    fn set_utxo(
        &mut self,
        outpoint: &OutPoint,
        entry: Utxo,
    ) -> Result<(), crate::utxo_impl::Error> {
        self.store.insert(outpoint.clone(), entry);
        Ok(())
    }
    fn del_utxo(&mut self, outpoint: &OutPoint) -> Result<(), crate::utxo_impl::Error> {
        self.store.remove(outpoint);
        Ok(())
    }
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, crate::utxo_impl::Error> {
        let res = self.store.get(outpoint);
        Ok(res.cloned())
    }
    fn set_best_block_id(&mut self, block_id: &Id<Block>) -> Result<(), crate::utxo_impl::Error> {
        // TODO: fix; don't store in general block id
        self.best_block_id = Some(block_id.clone());
        Ok(())
    }
    fn get_best_block_id(&self) -> Result<Option<Id<Block>>, crate::utxo_impl::Error> {
        // TODO: fix; don't get general block id
        Ok(self.best_block_id.clone())
    }

    fn set_undo_data(&mut self, id: Id<Block>, undo: &BlockUndo) -> Result<(), Error> {
        self.undo_store.insert(id.get(), undo.clone());
        Ok(())
    }

    fn del_undo_data(&mut self, id: Id<Block>) -> Result<(), Error> {
        self.undo_store.remove(&id.get());
        Ok(())
    }

    fn get_undo_data(&self, id: Id<Block>) -> Result<Option<BlockUndo>, Error> {
        let res = self.undo_store.get(&id.get());
        Ok(res.cloned())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_helper::{convert_to_utxo, create_tx_inputs, create_tx_outputs, create_utxo};
    use crate::utxo_impl::{
        flush_to_base, utxo_storage::UtxoDB, FlushableUtxoView, Utxo, UtxoEntry, UtxosCache,
        UtxosView,
    };
    use crate::ConsumedUtxoCache;
    use common::chain::config::create_mainnet;
    use common::chain::{Destination, OutPointSourceId, Transaction, TxInput, TxOutput};
    use common::primitives::consensus_data::ConsensusData;
    use common::primitives::{Amount, BlockHeight, Idable};
    use common::primitives::{Id, H256};
    use crypto::random::{make_pseudo_rng, seq, Rng};
    use iter_tools::Itertools;
    use std::collections::BTreeMap;

    fn create_transactions(
        inputs: Vec<TxInput>,
        max_num_of_outputs: usize,
        num_of_txs: usize,
    ) -> Vec<Transaction> {
        // distribute the inputs on the number of the transactions specified.
        let input_size = inputs.len() / num_of_txs;

        // create the multiple transactions based on the inputs.
        inputs
            .chunks(input_size)
            .into_iter()
            .map(|inputs| {
                let outputs = if max_num_of_outputs > 1 {
                    let rnd = make_pseudo_rng().gen_range(1..max_num_of_outputs);
                    create_tx_outputs(rnd as u32)
                } else {
                    vec![]
                };

                Transaction::new(0x00, inputs.to_vec(), outputs, 0)
                    .expect("should create a transaction successfully")
            })
            .collect_vec()
    }

    fn create_block(
        prev_block_id: Id<Block>,
        inputs: Vec<TxInput>,
        max_num_of_outputs: usize,
        num_of_txs: usize,
    ) -> Block {
        let txs = create_transactions(inputs, max_num_of_outputs, num_of_txs);
        Block::new(txs, prev_block_id, 1, ConsensusData::None)
            .expect("should be able to create a block")
    }

    /// populate the db with random values, for testing.
    /// returns a tuple of the best block id and the outpoints (for spending)
    fn initialize_db(
        db_interface: &mut UtxoInMemoryDBInterface,
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

    fn create_utxo_entries(num_of_utxos: u8) -> BTreeMap<OutPoint, UtxoEntry> {
        let mut map = BTreeMap::new();
        for _ in 0..num_of_utxos {
            let (utxo, outpoint) = create_utxo(0);
            let entry = UtxoEntry::new(utxo.clone(), true, true);
            map.insert(outpoint, entry);
        }

        map
    }

    #[test]
    // This tests the utxo and the undo. This does not include testing the state of the block.
    fn utxo_and_undo_test() {
        let tx_outputs_size = 3;
        let num_of_txs = 1;

        let mut db_interface = UtxoInMemoryDBInterface::new();

        // initializing the db with existing utxos.
        let (best_block_id, outpoints) = initialize_db(&mut db_interface, tx_outputs_size);
        // create the TxInputs for spending.
        let expected_tx_inputs = create_tx_inputs(&outpoints);

        // create the UtxoDB.
        let mut db_interface_clone = db_interface.clone();
        let mut db = UtxoDB::new(&mut db_interface_clone);

        // let's check that each tx_input exists in the db. Secure the spent utxos.
        let spent_utxos = expected_tx_inputs
            .iter()
            .map(|input| {
                let outpoint = input.get_outpoint();
                assert!(db.has_utxo(outpoint));

                db.get_utxo(outpoint).expect("utxo should exist.")
            })
            .collect_vec();

        // test the spend
        let (block, block_undo) = {
            // create a view based on the db.

            let mut parent_view = UtxosCache::default();
            db.0.store.iter().for_each(|(outpoint, utxo)| {
                assert!(parent_view.add_utxo(utxo.clone(), outpoint, false).is_ok());
            });
            parent_view
                .set_best_block(db.get_best_block_hash().expect("there should be best block hash"));

            let mut view = parent_view.derive_cache();

            // create a new block to spend.
            let block = create_block(best_block_id, expected_tx_inputs.clone(), 0, num_of_txs);
            let block_height = BlockHeight::new(1);
            // spend the block
            let block_undo = {
                let undos = block
                    .get_transactions()
                    .iter()
                    .map(|tx| view.spend_utxos(tx, block_height).expect("should spend okay."))
                    .collect_vec();
                BlockUndo::new(undos, block_height)
            };

            // check that the block_undo contains the same utxos recorded as "spent",
            // using the `spent_utxos`
            {
                block_undo.tx_undos().iter().enumerate().for_each(|(b_idx, tx_undo)| {
                    tx_undo.inner().iter().enumerate().for_each(|(t_idx, utxo)| {
                        assert_eq!(Some(utxo), spent_utxos.get(b_idx + t_idx));
                    })
                })
            }

            // flush to db
            view.set_best_block(block.get_id());
            assert!(flush_to_base(view, &mut db).is_ok());

            (block, block_undo)
        };

        // check that all in tx_inputs do NOT exist
        expected_tx_inputs.iter().for_each(|input| {
            assert_eq!(db.get_utxo(input.get_outpoint()), None);
        });

        // save the undo data to the db.
        {
            assert!(db.set_undo_data(block.get_id(), &block_undo).is_ok());

            // check that the block_undo retrieved from db is the same as the one being stored.
            let block_undo_from_db = db
                .get_undo_data(block.get_id())
                .expect("getting undo data should not cause any problems");

            assert_eq!(block_undo_from_db.as_ref(), Some(&block_undo));
        }

        // check that the inputs of the block do not exist in the utxo column.
        {
            block.get_transactions().iter().for_each(|tx| {
                tx.get_inputs().iter().for_each(|input| {
                    assert_eq!(db.get_utxo(input.get_outpoint()), None);
                });
            });
        }

        // let's try to reverse the spending.
        {
            // get the best_block_id
            let current_best_block_id =
                db.get_best_block_hash().expect("should return the best block id");

            println!("the current block id: {:?}", current_best_block_id);

            // the current best_block_id should be the block id..
            //  assert_eq!(&current_best_block_id, &block.get_id());

            // get the block_undo.
            let block_undo = db
                .get_undo_data(current_best_block_id)
                .expect("query should not fail")
                .expect("should return the undo file");

            // check that the block_undo's size is the same as the expected tx inputs.
            assert_eq!(block_undo.tx_undos().len(), expected_tx_inputs.len());

            // let's create a view.
            let mut view = UtxosCache::default();
            // set the best block to the previous one
            {
                view.set_best_block(block.get_prev_block_id());
                // the best block id should be the same as the old one.
                assert_eq!(
                    view.get_best_block_hash().as_ref(),
                    Some(&block.get_prev_block_id())
                );
            }

            // get the block txinputs, and add them to the view.
            block.get_transactions().iter().enumerate().for_each(|(idx, tx)| {
                // use the undo to get the utxos
                let undo = block_undo.tx_undos().get(idx).expect("it should return undo");
                let undos = undo.inner();

                // add the undo utxos back to the view.
                tx.get_inputs().iter().enumerate().for_each(|(in_idx, input)| {
                    let utxo = undos.get(in_idx).expect("it should have utxo");
                    assert!(view.add_utxo(utxo.clone(), input.get_outpoint(), true).is_ok());
                });
            });

            // flush the view to the db.
            assert!(flush_to_base(view, &mut db).is_ok());

            // remove the block undo file
            assert!(db.del_undo_data(block.get_id()).is_ok());
            assert_eq!(db.get_undo_data(block.get_id()), Ok(None));
        }

        // check that all the expected_tx_inputs exists, and the same utxo is saved.
        expected_tx_inputs.iter().enumerate().for_each(|(idx, input)| {
            let res = db.get_utxo(input.get_outpoint());

            let expected_utxo = spent_utxos.get(idx);
            assert_eq!(res.as_ref(), expected_utxo);
        });

        // For error testing: create dummy tx_inputs for spending.
        {
            let num_of_txs = 5;
            let rnd = make_pseudo_rng().gen_range(num_of_txs..20);

            let tx_inputs: Vec<TxInput> = (0..rnd)
                .into_iter()
                .map(|i| {
                    let id: Id<Block> = Id::new(&H256::random());
                    let id = OutPointSourceId::BlockReward(id);

                    TxInput::new(id, i, vec![])
                })
                .collect();

            // let num_of_txs =
            //     usize::from_u32(num_of_txs).expect("conversion to usize should not fail");
            let id = db.get_best_block_hash().expect("it should return an id");

            // Create a dummy block.
            let block = create_block(id, tx_inputs, 0, num_of_txs as usize);

            // Create a view.
            let mut view = db.derive_cache();

            let tx = block.get_transactions().get(0).expect("should return a transaction");

            // try to spend that transaction
            assert!(view.spend_utxos(tx, BlockHeight::new(2)).is_err());
        }
    }

    #[test]
    fn test_utxo() {
        common::concurrency::model(move || {
            let utxos = create_utxo_entries(10);
            let new_best_block_hash = Id::new(&H256::random());

            let utxos = ConsumedUtxoCache {
                container: utxos,
                best_block: new_best_block_hash.clone(),
            };

            let mut db_interface = UtxoInMemoryDBInterface::new();
            let mut utxo_db = UtxoDB::new(&mut db_interface);

            // test batch_write
            let res = utxo_db.batch_write(utxos.clone());
            assert!(res.is_ok());

            // randomly get a key for checking
            let keys = utxos.container.keys().collect_vec();
            let rng = make_pseudo_rng().gen_range(0..keys.len());
            let outpoint = keys[rng].clone();

            // test the get_utxo
            let utxo_opt = utxo_db.get_utxo(&outpoint);

            let outpoint_key = &outpoint;
            let utxo_entry = utxos.container.get(outpoint_key).expect("an entry should be found");
            assert_eq!(utxo_entry.utxo(), utxo_opt);

            // check has_utxo
            assert!(utxo_db.has_utxo(&outpoint));

            //check the best block hash
            assert_eq!(utxo_db.get_best_block_hash(), Some(new_best_block_hash));

            // try to write a non-dirty utxo
            {
                let (utxo, outpoint) = create_utxo(1);
                let mut map = BTreeMap::new();
                let entry = UtxoEntry::new(utxo, true, false);
                map.insert(outpoint.clone(), entry);

                let new_hash = Id::new(&H256::random());
                let another_cache = ConsumedUtxoCache {
                    container: map,
                    best_block: new_hash,
                };

                utxo_db.batch_write(another_cache).expect("batch write should work");

                assert!(!utxo_db.has_utxo(&outpoint));
            }

            // write down a spent utxo.
            {
                let rng = make_pseudo_rng().gen_range(0..keys.len());
                let outpoint_key = keys[rng];
                let outpoint = outpoint_key;
                let utxo = utxos
                    .container
                    .get(outpoint_key)
                    .expect("entry should exist")
                    .utxo()
                    .expect("utxo should exist");

                let mut parent = UtxosCache::default();
                assert!(parent.add_utxo(utxo, outpoint, false).is_ok());
                parent.set_best_block(
                    utxo_db.get_best_block_hash().expect("best block should be there"),
                );

                let mut child = UtxosCache::new(&parent);
                assert!(child.spend_utxo(outpoint).is_ok());

                let res = flush_to_base(child, &mut utxo_db);
                assert!(res.is_ok());

                assert!(!utxo_db.has_utxo(outpoint));
            }
        });
    }
}
