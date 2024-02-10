// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;
use common::chain::output_value::OutputValue;
use common::chain::transaction::signed_transaction::SignedTransaction;
use common::chain::{Block, Destination, OutPointSourceId, TxOutput, UtxoOutPoint};
use common::primitives::Id;
use common::primitives::{Amount, BlockHeight, Idable, H256};
use crypto::key::{KeyKind, PrivateKey};
use crypto::random::{CryptoRng, Rng};
use rstest::rstest;
use serialization::Encode;
use test_utils::random::{make_seedable_rng, Seed};
use utxo::{Utxo, UtxosBlockRewardUndo, UtxosBlockUndo, UtxosTxUndoWithSources};
use utxo::{UtxosStorageRead, UtxosStorageWrite};

type TestStore = crate::inmemory::Store;

#[test]
fn test_storage_get_default_version_in_tx() {
    utils::concurrency::model(|| {
        let store = TestStore::new_empty().unwrap();
        let vtx = store.transaction_ro().unwrap().get_storage_version().unwrap();
        assert_eq!(vtx, None, "Default storage version wrong");
    })
}

#[test]
#[cfg(not(loom))]
fn test_storage_manipulation() {
    use common::{
        chain::{
            block::{timestamp::BlockTimestamp, BlockReward, ConsensusData},
            Transaction,
        },
        primitives::{Id, H256},
    };

    // Prepare some test data
    let tx0 = Transaction::new(0xaabbccdd, vec![], vec![]).unwrap();
    let tx1 = Transaction::new(0xbbccddee, vec![], vec![]).unwrap();
    let signed_tx0 = SignedTransaction::new(tx0.clone(), vec![]).expect("invalid witness count");
    let signed_tx1 = SignedTransaction::new(tx1.clone(), vec![]).expect("invalid witness count");
    let block0 = Block::new(
        vec![signed_tx0.clone()],
        Id::new(H256::default()),
        BlockTimestamp::from_int_seconds(12),
        ConsensusData::None,
        BlockReward::new(Vec::new()),
    )
    .unwrap();
    let block1 = Block::new(
        vec![signed_tx1],
        Id::new(block0.get_id().to_hash()),
        BlockTimestamp::from_int_seconds(34),
        ConsensusData::None,
        BlockReward::new(Vec::new()),
    )
    .unwrap();

    // Set up the store
    let store = TestStore::new_empty().unwrap();
    let mut db_tx = store.transaction_rw(None).unwrap();

    // Storage version manipulation
    assert_eq!(db_tx.get_storage_version(), Ok(None));
    assert_eq!(
        db_tx.set_storage_version(ChainstateStorageVersion::new(0)),
        Ok(())
    );
    assert_eq!(
        db_tx.get_storage_version(),
        Ok(Some(ChainstateStorageVersion::new(0)))
    );

    // Store is now empty, the block is not there
    assert_eq!(db_tx.get_block(block0.get_id()), Ok(None));

    // Insert the first block and check it is there
    assert_eq!(db_tx.add_block(&block0), Ok(()));
    assert_eq!(&db_tx.get_block(block0.get_id()).unwrap().unwrap(), &block0);

    // Insert, remove, and reinsert the second block
    assert_eq!(db_tx.get_block(block1.get_id()), Ok(None));
    assert_eq!(db_tx.add_block(&block1), Ok(()));
    assert_eq!(&db_tx.get_block(block0.get_id()).unwrap().unwrap(), &block0);
    assert_eq!(db_tx.del_block(block1.get_id()), Ok(()));
    assert_eq!(db_tx.get_block(block1.get_id()), Ok(None));
    assert_eq!(db_tx.add_block(&block1), Ok(()));
    assert_eq!(&db_tx.get_block(block0.get_id()).unwrap().unwrap(), &block0);

    // Test the transaction extraction from a block
    let enc_tx0 = tx0.encode();
    let enc_block0 = block0.encode();
    let offset_tx0 = enc_block0
        .windows(enc_tx0.len())
        .enumerate()
        .find_map(|(i, d)| (d == enc_tx0).then_some(i))
        .unwrap();
    assert!(
        &enc_block0[offset_tx0..].starts_with(&enc_tx0),
        "Transaction format has changed, adjust the offset in this test",
    );

    // Test setting and retrieving best chain id
    assert_eq!(db_tx.get_best_block_id(), Ok(None));
    assert_eq!(db_tx.set_best_block_id(&block0.get_id().into()), Ok(()));
    assert_eq!(db_tx.get_best_block_id(), Ok(Some(block0.get_id().into())));
    assert_eq!(db_tx.set_best_block_id(&block1.get_id().into()), Ok(()));
    assert_eq!(db_tx.get_best_block_id(), Ok(Some(block1.get_id().into())));
}

#[test]
fn get_set_transactions() {
    utils::concurrency::model(|| {
        // Set up the store and initialize the version to 0
        let store = TestStore::new_empty().unwrap();
        let mut db_tx = store.transaction_rw(None).unwrap();

        assert_eq!(
            db_tx.set_storage_version(ChainstateStorageVersion::new(0)),
            Ok(())
        );

        db_tx.commit().unwrap();

        // Concurrently bump version and run a transaction that reads the version twice.
        let thr1 = {
            let store = Store::clone(&store);
            utils::thread::spawn(move || {
                let mut tx = store.transaction_rw(None).unwrap();
                tx.set_storage_version(ChainstateStorageVersion::new(1)).unwrap();
                tx.commit().unwrap();
            })
        };
        let thr0 = {
            let store = Store::clone(&store);
            utils::thread::spawn(move || {
                let tx = store.transaction_ro().unwrap();
                let v1 = tx.get_storage_version().unwrap().unwrap();
                let v2 = tx.get_storage_version().unwrap().unwrap();
                assert!(
                    [ChainstateStorageVersion::new(0), ChainstateStorageVersion::new(1)]
                        .contains(&v1)
                );
                assert_eq!(v1, v2, "Version query in a transaction inconsistent");
            })
        };

        let _ = thr0.join();
        let _ = thr1.join();

        let db_tx = store.transaction_ro().unwrap();

        assert_eq!(
            db_tx.get_storage_version(),
            Ok(Some(ChainstateStorageVersion::new(1)))
        );

        drop(db_tx);
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_storage_transactions(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        // Set up the store with empty utxo set
        let mut rng = make_seedable_rng(seed);
        let store = TestStore::new_empty().unwrap();
        assert!(store.transaction_ro().unwrap().read_utxo_set().unwrap().is_empty());

        let (utxo1, outpoint1) = create_rand_utxo(&mut rng, 1);
        let (utxo2, outpoint2) = create_rand_utxo(&mut rng, 1);

        let expected_utxo_set = BTreeMap::from_iter([
            (outpoint1.clone(), utxo1.clone()),
            (outpoint2.clone(), utxo2.clone()),
        ]);

        // Concurrently insert 2 utxo in two separate threads
        let thr0 = {
            let store = Store::clone(&store);
            utils::thread::spawn(move || {
                let mut tx = store.transaction_rw(None).unwrap();
                tx.set_utxo(&outpoint1, utxo1).unwrap();
                tx.commit().unwrap();
            })
        };
        let thr1 = {
            let store = Store::clone(&store);
            utils::thread::spawn(move || {
                let mut tx = store.transaction_rw(None).unwrap();
                tx.set_utxo(&outpoint2, utxo2).unwrap();
                tx.commit().unwrap();
            })
        };

        let _ = thr0.join();
        let _ = thr1.join();
        assert_eq!(
            store.transaction_ro().unwrap().read_utxo_set(),
            Ok(expected_utxo_set)
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_storage_transactions_with_result_check(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        // Set up the store with empty utxo set
        let mut rng = make_seedable_rng(seed);
        let store = TestStore::new_empty().unwrap();
        assert!(store.transaction_ro().unwrap().read_utxo_set().unwrap().is_empty());

        let (utxo1, outpoint1) = create_rand_utxo(&mut rng, 1);
        let (utxo2, outpoint2) = create_rand_utxo(&mut rng, 1);

        let expected_utxo_set = BTreeMap::from_iter([
            (outpoint1.clone(), utxo1.clone()),
            (outpoint2.clone(), utxo2.clone()),
        ]);

        // Concurrently insert 2 utxo in two separate threads
        let thr0 = {
            let store = Store::clone(&store);
            utils::thread::spawn(move || {
                let mut tx = store.transaction_rw(None).unwrap();
                assert!(tx.set_utxo(&outpoint1, utxo1).is_ok());
                assert!(tx.commit().is_ok());
            })
        };
        let thr1 = {
            let store = Store::clone(&store);
            utils::thread::spawn(move || {
                let mut tx = store.transaction_rw(None).unwrap();
                assert!(tx.set_utxo(&outpoint2, utxo2).is_ok());
                assert!(tx.commit().is_ok());
            })
        };

        let _ = thr0.join();
        let _ = thr1.join();
        assert_eq!(
            store.transaction_ro().unwrap().read_utxo_set(),
            Ok(expected_utxo_set)
        );
    })
}

/// returns a tuple of utxo and outpoint, for testing.
fn create_rand_utxo(rng: &mut (impl Rng + CryptoRng), block_height: u64) -> (Utxo, UtxoOutPoint) {
    // just a random value generated, and also a random `is_block_reward` value.
    let random_value = rng.gen_range(0..(u128::MAX - 1));
    let (_, pub_key) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let output = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(random_value)),
        Destination::PublicKey(pub_key),
    );

    // generate utxo
    let utxo = Utxo::new_for_blockchain(output, BlockHeight::new(block_height));
    let outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(rng))),
        0,
    );

    (utxo, outpoint)
}

/// returns a block undo with random utxos and TxUndos.
///
/// # Arguments
/// `max_lim_of_utxos` - sets the maximum limit of utxos of a random TxUndo.
/// `max_lim_of_tx_undos` - the maximum limit of TxUndos in the BlockUndo.
pub fn create_rand_block_undo(
    rng: &mut (impl Rng + CryptoRng),
    max_lim_of_utxos: u8,
    max_lim_of_tx_undos: u8,
) -> UtxosBlockUndo {
    let utxo_rng = rng.gen_range(1..max_lim_of_utxos);
    let reward_utxos = (0..utxo_rng)
        .enumerate()
        .map(|(i, _)| create_rand_utxo(rng, i as u64).0)
        .collect();
    let reward_undo = UtxosBlockRewardUndo::new(reward_utxos);

    let mut tx_undo = vec![];
    let undo_rng = rng.gen_range(1..max_lim_of_tx_undos);
    for _ in 0..undo_rng {
        let utxo_rng = rng.gen_range(1..max_lim_of_utxos);
        let tx_utxos = (0..utxo_rng)
            .enumerate()
            .map(|(i, _)| rng.gen::<bool>().then(|| create_rand_utxo(rng, i as u64).0))
            .collect();

        tx_undo.push(UtxosTxUndoWithSources::new(tx_utxos, vec![]));
    }

    let tx_undo = tx_undo
        .into_iter()
        .map(|u| (H256::random_using(rng).into(), u))
        .collect::<BTreeMap<_, _>>();

    UtxosBlockUndo::new(Some(reward_undo), tx_undo).unwrap()
}

#[cfg(not(loom))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn undo_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let block_undo0 = create_rand_block_undo(&mut rng, 10, 5);
    // create id:
    let id0: Id<Block> = Id::new(H256::random_using(&mut rng));

    // set up the store
    let store = TestStore::new_empty().unwrap();

    // store is empty, so no undo data should be found.
    assert_eq!(store.transaction_ro().unwrap().get_undo_data(id0), Ok(None));

    let mut db_tx = store.transaction_rw(None).unwrap();
    // add undo data and check if it is there
    assert_eq!(db_tx.set_undo_data(id0, &block_undo0), Ok(()));
    db_tx.commit().unwrap();

    assert_eq!(
        store.transaction_ro().unwrap().get_undo_data(id0).unwrap().unwrap(),
        block_undo0.clone()
    );

    // insert, remove, and reinsert the next block_undo

    let block_undo1 = create_rand_block_undo(&mut rng, 5, 10);
    // create id:
    let id1: Id<Block> = Id::new(H256::random_using(&mut rng));

    assert_eq!(store.transaction_ro().unwrap().get_undo_data(id1), Ok(None));

    let mut db_tx = store.transaction_rw(None).unwrap();
    assert_eq!(db_tx.set_undo_data(id1, &block_undo1), Ok(()));
    db_tx.commit().unwrap();

    assert_eq!(
        store.transaction_ro().unwrap().get_undo_data(id1).unwrap().unwrap(),
        block_undo1.clone()
    );

    assert_eq!(
        store.transaction_ro().unwrap().get_undo_data(id0).unwrap().unwrap(),
        block_undo0.clone()
    );

    let mut db_tx = store.transaction_rw(None).unwrap();
    assert_eq!(db_tx.del_undo_data(id1), Ok(()));
    db_tx.commit().unwrap();

    assert_eq!(store.transaction_ro().unwrap().get_undo_data(id1), Ok(None));
    assert_eq!(
        store.transaction_ro().unwrap().get_undo_data(id0).unwrap().unwrap(),
        block_undo0.clone()
    );

    let mut db_tx = store.transaction_rw(None).unwrap();
    assert_eq!(db_tx.set_undo_data(id1, &block_undo1), Ok(()));
    db_tx.commit().unwrap();

    assert_eq!(
        store.transaction_ro().unwrap().get_undo_data(id1).unwrap().unwrap(),
        block_undo1
    );
}

//#[cfg(not(loom))]
//#[rstest]
//#[trace]
//#[case(Seed::from_entropy())]
//fn utxo_db_impl_test(#[case] seed: Seed) {
//    let mut rng = make_seedable_rng(seed);
//    let store = crate::inmemory::Store::new_empty().expect("should create a store");
//
//    let mut db_tx = store.transaction_rw(None).expect("should create a transaction");
//    db_tx
//        .set_best_block_for_utxos(&H256::random_using(&mut rng).into())
//        .expect("Setting best block cannot fail");
//    db_tx.commit().expect("commit cannot fail");
//
//    // utxo checking
//    let (utxo, outpoint) = create_rand_utxo(&mut rng, 1);
//
//    let mut db_tx = store.transaction_rw(None).expect("should create a transaction");
//    {
//        let mut db_interface = utxo::UtxosDB::new(&mut db_tx);
//        assert!(db_interface.set_utxo(&outpoint, utxo.clone()).is_ok());
//    }
//    db_tx.commit().expect("commit cannot fail");
//
//    let db_tx = store.transaction_ro().expect("should create a transaction");
//    {
//        let db_interface = utxo::UtxosDB::new(&db_tx);
//        assert_eq!(db_interface.get_utxo(&outpoint), Ok(Some(utxo)));
//    }
//    drop(db_tx);
//
//    let mut db_tx = store.transaction_rw(None).expect("should create a transaction");
//    {
//        let mut db_interface = utxo::UtxosDB::new(&mut db_tx);
//        assert!(db_interface.del_utxo(&outpoint).is_ok());
//    }
//    db_tx.commit().expect("commit cannot fail");
//
//    let db_tx = store.transaction_ro().expect("should create a transaction");
//    {
//        let db_interface = utxo::UtxosDB::new(&db_tx);
//        assert_eq!(db_interface.get_utxo(&outpoint), Ok(None));
//    }
//    drop(db_tx);
//
//    // test block id
//    let block_id: Id<Block> = Id::new(H256::random_using(&mut rng));
//    let mut db_tx = store.transaction_rw(None).expect("should create a transaction");
//    assert!(db_tx.set_best_block_for_utxos(&block_id.into()).is_ok());
//    db_tx.commit().expect("commit cannot fail");
//
//    let db_tx = store.transaction_ro().expect("should create a transaction");
//    let block_id =
//        Id::new(db_tx.get_best_block_for_utxos().expect("query should not fail").to_hash());
//    drop(db_tx);
//
//    // undo checking
//    let undo = create_rand_block_undo(&mut rng, 10, 10);
//
//    let mut db_tx = store.transaction_rw(None).expect("should create a transaction");
//    {
//        let mut db_interface = utxo::UtxosDB::new(&mut db_tx);
//        assert!(db_interface.set_undo_data(block_id, &undo).is_ok());
//    }
//    db_tx.commit().expect("commit cannot fail");
//
//    let db_tx = store.transaction_ro().expect("should create a transaction");
//    {
//        let db_interface = utxo::UtxosDB::new(&db_tx);
//        assert_eq!(db_interface.get_undo_data(block_id), Ok(Some(undo)));
//    }
//    drop(db_tx);
//
//    let mut db_tx = store.transaction_rw(None).expect("should create a transaction");
//    {
//        let mut db_interface = utxo::UtxosDB::new(&mut db_tx);
//        assert!(db_interface.del_undo_data(block_id).is_ok());
//    }
//    db_tx.commit().expect("commit cannot fail");
//
//    let db_tx = store.transaction_ro().expect("should create a transaction");
//    {
//        let db_interface = utxo::UtxosDB::new(&db_tx);
//        assert_eq!(db_interface.get_undo_data(block_id), Ok(None));
//    }
//    drop(db_tx);
//}
