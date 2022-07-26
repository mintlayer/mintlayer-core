// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(dead_code)]

use crate::{Error, Store, UndoRead, UndoWrite, UtxoRead, UtxoWrite};
use common::chain::{Block, GenBlock, OutPoint};
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
    fn set_best_block_id(&mut self, block_id: &Id<GenBlock>) -> Result<(), utxo::Error> {
        self.store.set_best_block_for_utxos(block_id).map_err(|e| e.into())
    }
    fn get_best_block_id(&self) -> Result<Option<Id<GenBlock>>, utxo::Error> {
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
    use common::chain::{Destination, OutPoint, OutPointSourceId, OutputPurpose, TxOutput};
    use common::primitives::{Amount, BlockHeight, H256};
    use crypto::key::{KeyKind, PrivateKey};
    use rstest::*;
    use test_utils::random::*;

    fn create_utxo(block_height: u64, output_value: u128) -> (Utxo, OutPoint) {
        // just a random value generated, and also a random `is_block_reward` value.
        let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let output = TxOutput::new(
            Amount::from_atoms(random_value),
            OutputPurpose::Transfer(Destination::PublicKey(pub_key)),
        );
        let utxo = Utxo::new(output, true, BlockHeight::new(block_height));

        // create the id based on the `is_block_reward` value.
        let id = OutPointSourceId::BlockReward(Id::new(H256::random()));

        let outpoint = OutPoint::new(id, 0);

        (utxo, outpoint)
    }

    #[cfg(not(loom))]
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn db_impl_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let store = Store::new_empty().expect("should create a store");
        let mut db_interface = UtxoDBImpl::new(store);

        // utxo checking
        let (utxo, outpoint) = create_utxo(1, rng.gen_range(0..u128::MAX));
        assert!(db_interface.set_utxo(&outpoint, utxo.clone()).is_ok());
        assert_eq!(db_interface.get_utxo(&outpoint), Ok(Some(utxo)));
        assert!(db_interface.del_utxo(&outpoint).is_ok());
        assert_eq!(db_interface.get_utxo(&outpoint), Ok(None));

        // test block id
        let block_id: Id<Block> = Id::new(H256::random());
        assert!(db_interface.set_best_block_id(&block_id.into()).is_ok());

        let block_id = Id::new(
            db_interface
                .get_best_block_id()
                .expect("query should not fail")
                .expect("should return the block id")
                .get(),
        );

        // undo checking
        let undo = create_rand_block_undo(&mut rng, 10, 10, BlockHeight::new(10));

        assert!(db_interface.set_undo_data(block_id, &undo).is_ok());
        assert_eq!(db_interface.get_undo_data(block_id), Ok(Some(undo)));
        assert!(db_interface.del_undo_data(block_id).is_ok());
        assert_eq!(db_interface.get_undo_data(block_id), Ok(None));
    }
}
