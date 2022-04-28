#![allow(dead_code)]

use crate::{Error, Store, UndoRead, UndoWrite, UtxoRead, UtxoWrite};
use common::chain::block::Block;
use common::chain::OutPoint;
use common::primitives::Id;
use utxo::{utxo_storage::UtxosPersistentStorage, BlockUndo, Utxo};

#[derive(Clone)]
pub struct UtxoDBImpl {
    store: Store,
}

impl UtxoDBImpl {
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

impl UtxosPersistentStorage for UtxoDBImpl {
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
        self.store.set_best_block_for_utxos(block_id).map_err(|e| e.into())
    }
    fn get_best_block_id(&self) -> Result<Option<Id<Block>>, utxo::Error> {
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::store::test::create_rand_block_undo;
    use common::chain::{Destination, OutPoint, OutPointSourceId, TxOutput};
    use common::primitives::{Amount, BlockHeight, H256};
    use crypto::random::{make_pseudo_rng, Rng};

    fn create_utxo(block_height: u64) -> (Utxo, OutPoint) {
        // just a random value generated, and also a random `is_block_reward` value.
        let random_value = make_pseudo_rng().gen_range(0..u128::MAX);
        let output = TxOutput::new(Amount::from_atoms(random_value), Destination::PublicKey);
        let utxo = Utxo::new(output, true, BlockHeight::new(block_height));

        // create the id based on the `is_block_reward` value.
        let id = {
            let utxo_id: Id<Block> = Id::new(&H256::random());
            OutPointSourceId::BlockReward(utxo_id)
        };

        let outpoint = OutPoint::new(id, 0);

        (utxo, outpoint)
    }

    #[test]
    fn db_interface_test() {
        let store = Store::new_empty().expect("should create a store");
        let mut db_interface = UtxoDBImpl::new(store);

        // utxo checking
        let (utxo, outpoint) = create_utxo(1);
        assert!(db_interface.set_utxo(&outpoint, utxo.clone()).is_ok());
        assert_eq!(db_interface.get_utxo(&outpoint), Ok(Some(utxo)));
        assert!(db_interface.del_utxo(&outpoint).is_ok());

        // test block id
        let block_id: Id<Block> = Id::new(&H256::random());
        assert!(db_interface.set_best_block_id(&block_id).is_ok());

        let block_id = db_interface
            .get_best_block_id()
            .expect("query should not fail")
            .expect("should return the block id");

        // undo checking
        let undo = create_rand_block_undo(10, 10, BlockHeight::new(10));

        assert!(db_interface.set_undo_data(block_id.clone(), &undo).is_ok());
        assert_eq!(db_interface.get_undo_data(block_id.clone()), Ok(Some(undo)));
        assert!(db_interface.del_undo_data(block_id.clone()).is_ok());
    }
}
