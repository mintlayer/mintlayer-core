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

#[cfg(test)]
mod test {
    use crate::internal::test::create_rand_block_undo;
    use common::chain::{Block, Destination, OutPoint, OutPointSourceId, OutputPurpose, TxOutput};
    use common::primitives::{Amount, BlockHeight, Id, H256};
    use crypto::key::{KeyKind, PrivateKey};
    use crypto::random::Rng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};
    use utxo::utxo_storage::UtxosDBMut;
    use utxo::utxo_storage::{UtxosStorageRead, UtxosStorageWrite};
    use utxo::Utxo;

    fn create_utxo(block_height: u64, output_value: u128) -> (Utxo, OutPoint) {
        // just a random value generated, and also a random `is_block_reward` value.
        let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let output = TxOutput::new(
            Amount::from_atoms(output_value),
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
        let mut store = crate::Store::new_empty().expect("should create a store");
        let mut db_interface = UtxosDBMut::new(&mut store);

        // utxo checking
        let (utxo, outpoint) = create_utxo(1, rng.gen_range(0..u128::MAX));
        assert!(db_interface.set_utxo(&outpoint, utxo.clone()).is_ok());
        assert_eq!(db_interface.get_utxo(&outpoint), Ok(Some(utxo)));
        assert!(db_interface.del_utxo(&outpoint).is_ok());
        assert_eq!(db_interface.get_utxo(&outpoint), Ok(None));

        // test block id
        let block_id: Id<Block> = Id::new(H256::random());
        assert!(db_interface.set_best_block_for_utxos(&block_id.into()).is_ok());

        let block_id = Id::new(
            db_interface
                .get_best_block_for_utxos()
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
