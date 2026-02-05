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

// Timestamps are not important for these tests, just make something up
const DUMMY_TIME: BlockTimestamp = BlockTimestamp::from_int_seconds(1639975461);

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn basic_reorg(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();
    let mut tx_pool = setup_with_chainstate(tf.chainstate());
    let chainstate = tx_pool.chainstate_handle().shallow_clone();

    // Add the first transaction
    let tx1 = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
            empty_witness(&mut rng),
        )
        .add_anyone_can_spend_output(10_000_000)
        .build();
    let tx1_id = tx1.transaction().get_id();
    tx_pool
        .add_transaction_test(tx1.clone())
        .expect("adding tx1")
        .assert_in_mempool();

    // Add another transaction
    let tx2 = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(tx1_id), 0),
            empty_witness(&mut rng),
        )
        .add_anyone_can_spend_output(9_000_000)
        .build();
    let tx2_id = tx2.transaction().get_id();
    tx_pool
        .add_transaction_test(tx2.clone())
        .expect("adding tx2")
        .assert_in_mempool();

    // Check the transactions are there
    assert!(tx_pool.contains_transaction(&tx1_id));
    assert!(tx_pool.contains_transaction(&tx2_id));

    // Make sure adding a block does not reset mempool entry timestamp.
    let tx2_time = tx_pool.store.get_entry(&tx2_id).unwrap().creation_time();
    // TODO: Use proper time mocking here instead of sleep.
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Submit a block with tx1 and check the corresponding tx has been removed from mempool
    let block1 = make_test_block(vec![tx1], genesis.get_id(), DUMMY_TIME);
    let block1_id = block1.get_id();
    chainstate
        .call_mut(move |c| c.process_block(block1, BlockSource::Local))
        .await
        .unwrap()
        .expect("block1");
    tx_pool.on_new_tip(block1_id, BlockHeight::new(1)).unwrap();
    assert!(!tx_pool.contains_transaction(&tx1_id));
    assert!(tx_pool.contains_transaction(&tx2_id));

    let tx2_time_after_block = tx_pool.store.get_entry(&tx2_id).unwrap().creation_time();
    assert_eq!(tx2_time, tx2_time_after_block);

    // Submit a block with tx2 and check transactions are no longer in mempool
    let block2 = make_test_block(vec![tx2], block1_id, DUMMY_TIME);
    let block2_id = block2.get_id();
    chainstate
        .call_mut(move |c| c.process_block(block2, BlockSource::Local))
        .await
        .unwrap()
        .expect("block2");
    tx_pool.on_new_tip(block2_id, BlockHeight::new(2)).unwrap();
    assert!(!tx_pool.contains_transaction(&tx1_id));
    assert!(!tx_pool.contains_transaction(&tx2_id));

    // Submit two blocks on top of block1 and reorg out block2, causing tx2 to reappear in mempool
    let block3 = make_test_block(Vec::new(), block1_id, DUMMY_TIME);
    let block4 = make_test_block(Vec::new(), block3.get_id(), DUMMY_TIME);
    let block4_id = block4.get_id();
    for (block, name) in [(block3, "block3"), (block4, "block4")] {
        chainstate
            .call_mut(move |c| c.process_block(block, BlockSource::Local))
            .await
            .unwrap()
            .expect(name);
    }
    tx_pool.on_new_tip(block4_id, BlockHeight::new(3)).unwrap();
    assert!(!tx_pool.contains_transaction(&tx1_id));
    assert!(tx_pool.contains_transaction(&tx2_id));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tx_chain_in_block(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();
    let mut tx_pool = setup_with_chainstate(tf.chainstate());
    let chainstate = tx_pool.chainstate_handle().shallow_clone();

    // Add the first transaction
    let tx1 = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
            empty_witness(&mut rng),
        )
        .add_anyone_can_spend_output(10_000_000)
        .build();
    let tx1_id = tx1.transaction().get_id();
    tx_pool
        .add_transaction_test(tx1.clone())
        .expect("adding tx1")
        .assert_in_mempool();

    // Add another transaction
    let tx2 = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(tx1_id), 0),
            empty_witness(&mut rng),
        )
        .add_anyone_can_spend_output(9_000_000)
        .build();
    let tx2_id = tx2.transaction().get_id();
    tx_pool
        .add_transaction_test(tx2.clone())
        .expect("adding tx2")
        .assert_in_mempool();

    // Check the transactions are there
    assert!(tx_pool.contains_transaction(&tx1_id));
    assert!(tx_pool.contains_transaction(&tx2_id));

    // Submit a block with both transactions
    let block1 = make_test_block(vec![tx1, tx2], genesis.get_id(), DUMMY_TIME);
    let block1_id = block1.get_id();
    chainstate
        .call_mut(move |c| c.process_block(block1, BlockSource::Local))
        .await
        .unwrap()
        .expect("block1");
    tx_pool.on_new_tip(block1_id, BlockHeight::new(1)).unwrap();
    assert!(!tx_pool.contains_transaction(&tx1_id));
    assert!(!tx_pool.contains_transaction(&tx2_id));

    // Reorg the transactions out and check they are back in mempool
    let block2 = make_test_block(vec![], genesis.get_id(), DUMMY_TIME);
    let block3 = make_test_block(vec![], block2.get_id(), DUMMY_TIME);
    let block3_id = block3.get_id();
    for (block, name) in [(block2, "block2"), (block3, "block3")] {
        chainstate
            .call_mut(move |c| c.process_block(block, BlockSource::Local))
            .await
            .unwrap()
            .expect(name);
    }
    tx_pool.on_new_tip(block3_id, BlockHeight::new(2)).unwrap();
    assert!(tx_pool.contains_transaction(&tx1_id));
    assert!(tx_pool.contains_transaction(&tx2_id));
}
