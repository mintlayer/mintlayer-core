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

use super::*;
use common::chain::{Destination, OutputPurpose, TxOutput};
use common::primitives::{Amount, H256};
use crypto::key::{KeyKind, PrivateKey};
use crypto::random::Rng;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};
use utxo::{BlockUndo, TxUndo};

type TestStore = Store<storage::inmemory::Store<Schema>>;

#[test]
fn test_storage_get_default_version_in_tx() {
    common::concurrency::model(|| {
        let store = TestStore::new_empty().unwrap();
        let vtx = store.transaction_ro().run(|tx| tx.get_storage_version()).unwrap();
        let vst = store.get_storage_version().unwrap();
        assert_eq!(vtx, 1, "Default storage version wrong");
        assert_eq!(vtx, vst, "Transaction and non-transaction inconsistency");
    })
}

#[test]
#[cfg(not(loom))]
fn test_storage_manipulation() {
    use common::{
        chain::{
            block::{timestamp::BlockTimestamp, ConsensusData},
            SpendablePosition,
        },
        primitives::H256,
    };

    // Prepare some test data
    let tx0 = Transaction::new(0xaabbccdd, vec![], vec![], 12).unwrap();
    let tx1 = Transaction::new(0xbbccddee, vec![], vec![], 34).unwrap();
    let block0 = Block::new(
        vec![tx0.clone()],
        Id::new(H256::default()),
        BlockTimestamp::from_int_seconds(12),
        ConsensusData::None,
    )
    .unwrap();
    let block1 = Block::new(
        vec![tx1.clone()],
        Id::new(block0.get_id().get()),
        BlockTimestamp::from_int_seconds(34),
        ConsensusData::None,
    )
    .unwrap();

    // Set up the store
    let mut store = TestStore::new_empty().unwrap();

    // Storage version manipulation
    assert_eq!(store.get_storage_version(), Ok(1));
    assert_eq!(store.set_storage_version(2), Ok(()));
    assert_eq!(store.get_storage_version(), Ok(2));

    // Storte is now empty, the block is not there
    assert_eq!(store.get_block(block0.get_id()), Ok(None));

    // Insert the first block and check it is there
    assert_eq!(store.add_block(&block0), Ok(()));
    assert_eq!(&store.get_block(block0.get_id()).unwrap().unwrap(), &block0);

    // Insert, remove, and reinsert the second block
    assert_eq!(store.get_block(block1.get_id()), Ok(None));
    assert_eq!(store.add_block(&block1), Ok(()));
    assert_eq!(&store.get_block(block0.get_id()).unwrap().unwrap(), &block0);
    assert_eq!(store.del_block(block1.get_id()), Ok(()));
    assert_eq!(store.get_block(block1.get_id()), Ok(None));
    assert_eq!(store.add_block(&block1), Ok(()));
    assert_eq!(&store.get_block(block0.get_id()).unwrap().unwrap(), &block0);

    // Test the transaction extraction from a block
    let enc_tx0 = tx0.encode();
    let enc_block0 = block0.encode();
    let offset_tx0 = enc_block0
        .windows(enc_tx0.len())
        .enumerate()
        .find_map(|(i, d)| (d == enc_tx0).then(|| i))
        .unwrap();
    assert!(
        &enc_block0[offset_tx0..].starts_with(&enc_tx0),
        "Transaction format has changed, adjust the offset in this test",
    );
    let pos_tx0 =
        TxMainChainPosition::new(block0.get_id(), offset_tx0 as u32, enc_tx0.len() as u32);
    assert_eq!(
        &store.get_mainchain_tx_by_position(&pos_tx0).unwrap().unwrap(),
        &tx0
    );

    // Test setting and retrieving best chain id
    assert_eq!(store.get_best_block_id(), Ok(None));
    assert_eq!(store.set_best_block_id(&block0.get_id().into()), Ok(()));
    assert_eq!(store.get_best_block_id(), Ok(Some(block0.get_id().into())));
    assert_eq!(store.set_best_block_id(&block1.get_id().into()), Ok(()));
    assert_eq!(store.get_best_block_id(), Ok(Some(block1.get_id().into())));

    // Chain index operations
    let idx_tx0 = TxMainChainIndex::new(pos_tx0.into(), 1).expect("Tx index creation failed");
    let out_id_tx0 = OutPointSourceId::from(tx0.get_id());
    assert_eq!(store.get_mainchain_tx_index(&out_id_tx0), Ok(None));
    assert_eq!(store.set_mainchain_tx_index(&out_id_tx0, &idx_tx0), Ok(()));
    assert_eq!(
        store.get_mainchain_tx_index(&out_id_tx0),
        Ok(Some(idx_tx0.clone()))
    );
    assert_eq!(store.del_mainchain_tx_index(&out_id_tx0), Ok(()));
    assert_eq!(store.get_mainchain_tx_index(&out_id_tx0), Ok(None));
    assert_eq!(store.set_mainchain_tx_index(&out_id_tx0, &idx_tx0), Ok(()));

    // Retrieve transactions by ID using the index
    assert_eq!(
        store.get_mainchain_tx_index(&OutPointSourceId::from(tx1.get_id())),
        Ok(None)
    );
    if let Ok(Some(index)) = store.get_mainchain_tx_index(&out_id_tx0) {
        if let SpendablePosition::Transaction(ref p) = index.position() {
            assert_eq!(store.get_mainchain_tx_by_position(p), Ok(Some(tx0)));
        } else {
            unreachable!();
        };
    } else {
        unreachable!();
    }
}

#[test]
fn get_set_transactions() {
    common::concurrency::model(|| {
        // Set up the store and initialize the version to 2
        let mut store = TestStore::new_empty().unwrap();
        assert_eq!(store.set_storage_version(2), Ok(()));

        // Concurrently bump version and run a transactiomn that reads the version twice.
        let thr1 = {
            let store = Store::clone(&store);
            common::thread::spawn(move || {
                let _ = store.transaction_rw().run(|tx| {
                    let v = tx.get_storage_version()?;
                    tx.set_storage_version(v + 1)?;
                    storage::commit(())
                });
            })
        };
        let thr0 = {
            let store = Store::clone(&store);
            common::thread::spawn(move || {
                let tx_result = store.transaction_ro().run(|tx| {
                    let v1 = tx.get_storage_version()?;
                    let v2 = tx.get_storage_version()?;
                    assert!([2, 3].contains(&v1));
                    assert_eq!(v1, v2, "Version query in a transaction inconsistent");
                    Ok(())
                });
                assert!(tx_result.is_ok());
            })
        };

        let _ = thr0.join();
        let _ = thr1.join();
        assert_eq!(store.get_storage_version(), Ok(3));
    })
}

#[test]
fn test_storage_transactions() {
    common::concurrency::model(|| {
        // Set up the store and initialize the version to 2
        let mut store = TestStore::new_empty().unwrap();
        assert_eq!(store.set_storage_version(2), Ok(()));

        // Concurrently bump version by 3 and 5 in two separate threads
        let thr0 = {
            let store = Store::clone(&store);
            common::thread::spawn(move || {
                let tx_result = store.transaction_rw().run(|tx| {
                    let v = tx.get_storage_version()?;
                    tx.set_storage_version(v + 3)?;
                    storage::commit(())
                });
                assert!(tx_result.is_ok());
            })
        };
        let thr1 = {
            let store = Store::clone(&store);
            common::thread::spawn(move || {
                let tx_result = store.transaction_rw().run(|tx| {
                    let v = tx.get_storage_version()?;
                    tx.set_storage_version(v + 5)?;
                    storage::commit(())
                });
                assert!(tx_result.is_ok());
            })
        };

        let _ = thr0.join();
        let _ = thr1.join();
        assert_eq!(store.get_storage_version(), Ok(10));
    })
}

#[test]
fn test_storage_transactions_with_result_check() {
    common::concurrency::model(|| {
        // Set up the store and initialize the version to 2
        let mut store = TestStore::new_empty().unwrap();
        assert_eq!(store.set_storage_version(2), Ok(()));

        // Concurrently bump version by 3 and 5 in two separate threads
        let thr0 = {
            let store = Store::clone(&store);
            common::thread::spawn(move || {
                let mut tx = store.transaction_rw();
                let v = tx.get_storage_version().unwrap();
                assert!(tx.set_storage_version(v + 3).is_ok());
                assert!(tx.commit().is_ok());
            })
        };
        let thr1 = {
            let store = Store::clone(&store);
            common::thread::spawn(move || {
                let mut tx = store.transaction_rw();
                let v = tx.get_storage_version().unwrap();
                assert!(tx.set_storage_version(v + 5).is_ok());
                assert!(tx.commit().is_ok());
            })
        };

        let _ = thr0.join();
        let _ = thr1.join();
        assert_eq!(store.get_storage_version(), Ok(10));
    })
}

/// returns a tuple of utxo and outpoint, for testing.
fn create_rand_utxo(rng: &mut impl Rng, block_height: u64) -> Utxo {
    // just a random value generated, and also a random `is_block_reward` value.
    let random_value = rng.gen_range(0..(u128::MAX - 1));
    let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let output = TxOutput::new(
        Amount::from_atoms(random_value),
        OutputPurpose::Transfer(Destination::PublicKey(pub_key)),
    );
    let is_block_reward = random_value % 3 == 0;

    // generate utxo
    Utxo::new(output, is_block_reward, BlockHeight::new(block_height))
}

/// returns a block undo with random utxos and TxUndos.
///
/// # Arguments
/// `max_lim_of_utxos` - sets the maximum limit of utxos of a random TxUndo.
/// `max_lim_of_tx_undos` - the maximum limit of TxUndos in the BlockUndo.
pub fn create_rand_block_undo(
    rng: &mut impl Rng,
    max_lim_of_utxos: u8,
    max_lim_of_tx_undos: u8,
    block_height: BlockHeight,
) -> BlockUndo {
    let mut counter: u64 = 0;

    let mut block_undo: Vec<TxUndo> = vec![];

    let undo_rng = rng.gen_range(1..max_lim_of_tx_undos);
    for _ in 0..undo_rng {
        let mut tx_undo = vec![];

        let utxo_rng = rng.gen_range(1..max_lim_of_utxos);
        for i in 0..utxo_rng {
            counter += u64::from(i);

            tx_undo.push(create_rand_utxo(rng, counter));
        }

        block_undo.push(TxUndo::new(tx_undo));
    }

    BlockUndo::new(block_undo, block_height)
}

#[cfg(not(loom))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn undo_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let block_undo0 = create_rand_block_undo(&mut rng, 10, 5, BlockHeight::new(1));
    // create id:
    let id0: Id<Block> = Id::new(H256::random());

    // set up the store
    let mut store = TestStore::new_empty().unwrap();

    // store is empty, so no undo data should be found.
    assert_eq!(store.get_undo_data(id0), Ok(None));

    // add undo data and check if it is there
    assert_eq!(store.set_undo_data(id0, &block_undo0), Ok(()));
    assert_eq!(
        store.get_undo_data(id0).unwrap().unwrap(),
        block_undo0.clone()
    );

    // insert, remove, and reinsert the next block_undo

    let block_undo1 = create_rand_block_undo(&mut rng, 5, 10, BlockHeight::new(2));
    // create id:
    let id1: Id<Block> = Id::new(H256::random());

    assert_eq!(store.get_undo_data(id1), Ok(None));
    assert_eq!(store.set_undo_data(id1, &block_undo1), Ok(()));
    assert_eq!(
        store.get_undo_data(id0).unwrap().unwrap(),
        block_undo0.clone()
    );
    assert_eq!(store.del_undo_data(id1), Ok(()));
    assert_eq!(store.get_undo_data(id1), Ok(None));
    assert_eq!(
        store.get_undo_data(id0).unwrap().unwrap(),
        block_undo0.clone()
    );
    assert_eq!(store.set_undo_data(id1, &block_undo1), Ok(()));
    assert_eq!(store.get_undo_data(id1).unwrap().unwrap(), block_undo1);
}
