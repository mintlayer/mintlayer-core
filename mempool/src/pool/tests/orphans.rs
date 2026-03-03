// Copyright (c) 2023 RBB S.r.l
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

use crate::tx_origin::LocalTxOrigin;
use common::primitives::id::hash_encoded;

use super::*;

#[rstest]
#[trace]
#[case::success(
    Seed::from_entropy(),
    Amount::from_atoms(100_000_000),
    Amount::from_atoms(90_000_000),
    true
)]
#[trace]
#[case::failure(
    Seed::from_entropy(),
    Amount::from_atoms(90_000_000),
    Amount::from_atoms(100_000_000),
    false
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_transactions_in_sequence(
    #[case] seed: Seed,
    #[case] amt0: Amount,
    #[case] amt1: Amount,
    #[case] expected_in_mempool: bool,
) {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis_id = tf.genesis().get_id();

    let tx0 = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(genesis_id.into(), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(amt0),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx0_id = tx0.transaction().get_id();

    let tx1 = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(tx0_id.into(), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(amt1),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx1_id = tx1.transaction().get_id();

    let mut mempool = setup_with_chainstate(tf.chainstate());

    // Add the second transaction first
    mempool.add_transaction_test(tx1).unwrap().assert_in_orphan_pool();
    assert!(mempool.contains_orphan_transaction(&tx1_id));
    assert!(!mempool.contains_transaction(&tx1_id));

    // Now add the first transaction
    let res = mempool.add_transaction_test(tx0);
    assert_eq!(res, Ok(TxStatus::InMempool));

    // Now the second tx (which we submitted first) should be either rejected or in mempool
    assert!(!mempool.contains_orphan_transaction(&tx1_id));
    assert_eq!(mempool.contains_transaction(&tx1_id), expected_in_mempool);
}

// Below, each test case encodes a sequence of transaction insertions.
//
// Each element of the Vec contains:
// 0. Transaction to be inserted (see the diagram below)
// 1. Expected state of the main (non-orphan) mempool. One bit per transaction, 1 = transaction is
//    expected in mempool, 0 = transaction is expected not to be in mempool. Note that the lowest
//    bit (rightmost digit) corresponds to transaction 0.
// 2. Expected state of the orphan pool. Same encoding as above.
//
// The transaction topology used by the test is as follows:
//
// (i = input, o = output, [n] = transaction number as referred to in the code)
//
//                                   +-------+
//                               +---i  [1]  o---+
//                   +-------+   |   +-------+   |   +-------+
// genesis UTXO -----i       o---+               +---i       o
//                   |  [0]  |                       |  [3]  |
//                   |       o---+               +---i       |
//                   +-------+   |   +-------+   |   +-------+
//                               +---i  [2]  o---+
//                                   +-------+
//
// This is a simple diamond transaction graph but it covers many interesting cases.
//
#[rstest]
#[trace]
#[case::topological_order(
    Seed::from_entropy(),
    vec![(0, 0b0001, 0b0000), (1, 0b0011, 0b0000), (2, 0b0111, 0b0000), (3, 0b1111, 0b0000)],
)]
#[trace]
#[case::op_branch_released_first(
    Seed::from_entropy(),
    vec![(1, 0b0000, 0b0010), (3, 0b0000, 0b1010), (0, 0b0011, 0b1000), (2, 0b1111, 0b0000)],
)]
#[trace]
#[case::one_orphan_then_mempool(
    Seed::from_entropy(),
    vec![(1, 0b0000, 0b0010), (0, 0b0011, 0b0000), (2, 0b0111, 0b0000), (3, 0b1111, 0b0000)],
)]
#[trace]
#[case::reverse_topological_order(
    Seed::from_entropy(),
    vec![(3, 0b0000, 0b1000), (2, 0b0000, 0b1100), (1, 0b0000, 0b1110), (0, 0b1111, 0b0000)],
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn diamond_graph(#[case] seed: Seed, #[case] insertion_plan: Vec<(usize, usize, usize)>) {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis_id = tf.genesis().get_id();

    // Set up the transactions

    let tx0 = make_tx(
        &mut rng,
        &[(OutPointSourceId::BlockReward(genesis_id.into()), 0)],
        &[100_000_000, 50_000_000],
    );
    let tx0_outpt = OutPointSourceId::Transaction(tx0.transaction().get_id());

    let tx1 = make_tx(&mut rng, &[(tx0_outpt.clone(), 0)], &[80_000_000]);
    let tx1_outpt = OutPointSourceId::Transaction(tx1.transaction().get_id());

    let tx2 = make_tx(&mut rng, &[(tx0_outpt, 1)], &[30_000_000]);
    let tx2_outpt = OutPointSourceId::Transaction(tx2.transaction().get_id());

    let tx3 = make_tx(&mut rng, &[(tx1_outpt, 0), (tx2_outpt, 0)], &[90_000_000]);

    let txs = [tx0, tx1, tx2, tx3];
    let tx_ids: Vec<_> = txs.iter().map(|tx| tx.transaction().get_id()).collect();

    // Set up mempool and execute the insertion plan
    let mut mempool = setup_with_chainstate(tf.chainstate());

    for (tx_no, expected_mempool, expected_orphans) in insertion_plan {
        let _ = mempool.add_transaction_test(txs[tx_no].clone()).expect("tx add");

        // Check the expected mempool state
        for (i, tx_id) in tx_ids.iter().enumerate() {
            let expected_mempool = (expected_mempool >> i) & 1 != 0;
            let expected_orphans = (expected_orphans >> i) & 1 != 0;
            assert_eq!(mempool.contains_transaction(tx_id), expected_mempool);
            assert_eq!(mempool.contains_orphan_transaction(tx_id), expected_orphans);
        }
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn orphan_conflicts_with_mempool_tx(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis_id = tf.genesis().get_id();

    // Set up the transactions

    let tx0 = make_tx(
        &mut rng,
        &[(OutPointSourceId::BlockReward(genesis_id.into()), 0)],
        &[100_000_000, 50_000_000],
    );
    let tx0_outpt = OutPointSourceId::Transaction(tx0.transaction().get_id());
    let dangling = OutPointSourceId::Transaction(Id::new(H256(rng.gen())));

    let tx1a = make_tx(&mut rng, &[(tx0_outpt.clone(), 0)], &[80_000_000]);
    let tx1b = make_tx(&mut rng, &[(dangling, 0), (tx0_outpt, 0)], &[30_000_000]);

    // Add the first two transactions into mempool
    let mut mempool = setup_with_chainstate(tf.chainstate());
    mempool.add_transaction_test(tx0).unwrap().assert_in_mempool();
    mempool.add_transaction_test(tx1a).unwrap().assert_in_mempool();

    // Check transaction that conflicts with one in mempool gets rejected instead of ending up in
    // the orphan pool.
    assert_eq!(
        mempool.add_transaction_test(tx1b),
        Err(OrphanPoolError::MempoolConflict.into()),
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_graph_subset_permutation(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let mut gen_origin = {
        let seed = Seed::from_u64(rng.gen());
        let mut rng = make_seedable_rng(seed);
        move || RemoteTxOrigin::new(p2p_types::PeerId::from_u64(rng.gen_range(1..=4)))
    };

    // Generate a valid graph of transactions
    let num_txs = rng.gen_range(15..90);
    let time = TimeGetter::default().get_time();
    let full_tx_sequence: Vec<_> =
        generate_transaction_graph(&mut rng, time).take(num_txs).collect();
    let all_tx_ids: Vec<_> = full_tx_sequence.iter().map(|tx| tx.tx_id()).collect();

    // Pick a subset of these transactions, taking each with 90% probability.
    let tx_subseq_0: Vec<_> =
        full_tx_sequence.iter().filter(|_| rng.gen_bool(0.9)).cloned().collect();

    // Take the same subsequence but with randomly shuffled order.
    // This means some transactions will be temporarily in the orphan pool.
    let tx_subseq_1 = {
        let mut subseq = tx_subseq_0.clone();
        let salt = rng.gen::<u64>();
        subseq.sort_unstable_by_key(|tx| hash_encoded(&(tx.tx_id(), salt)));
        subseq
    };

    let mut results: Vec<Vec<Option<TxStatus>>> = Vec::new();
    for tx_subseq in [tx_subseq_0, tx_subseq_1] {
        let tf = TestFramework::builder(&mut rng).build();
        let mut mempool = setup_with_chainstate(tf.chainstate());

        // Now add each transaction in the subsequence
        tx_subseq.iter().for_each(|tx| {
            // Add the transaction
            let tx = tx.transaction().clone();
            let _ = mempool.add_transaction_with_origin(tx, gen_origin().into()).expect("tx add");

            // Randomly perform 0, 1, or 2 work units
            for _ in 0..rng.gen_range(0..=2) {
                mempool.perform_work_unit();
            }
        });

        // Finish processing all the orphans in the work queue
        mempool.process_queue();

        log::info!(
            "Stats: count {}, memory {}, encoded size {}",
            mempool.tx_store().txs_by_id.len(),
            mempool.memory_usage(),
            mempool.tx_store().txs_by_id.values().map(|e| e.size().get()).sum::<usize>(),
        );

        // Check the final state of each transaction in the original sequence
        results.push(all_tx_ids.iter().map(|id| fetch_status(&mempool, id)).collect());
    }

    // Check the final outcome, i.e. which transactions end up in mempool versus orphan pool, is
    // independent of the order of insertion. This is only guaranteed if the orphan pool capacity
    // is not exhausted. Here, we are within the capacity.
    log::debug!("result = {:?}", results[0]);
    assert_eq!(results[0], results[1]);
}

#[rstest]
#[trace]
#[case::p2p(Seed::from_entropy(), LocalTxOrigin::P2p)]
#[trace]
#[case::mempool(Seed::from_entropy(), LocalTxOrigin::Mempool)]
#[trace]
#[case::block(Seed::from_entropy(), LocalTxOrigin::PastBlock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_origins_rejected(#[case] seed: Seed, #[case] origin: LocalTxOrigin) {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis_id = tf.genesis().get_id();

    // Set up the transactions

    let tx0 = make_tx(
        &mut rng,
        &[(OutPointSourceId::BlockReward(genesis_id.into()), 0)],
        &[100_000_000],
    );
    let tx0_outpt = OutPointSourceId::Transaction(tx0.transaction().get_id());

    let tx1 = make_tx(&mut rng, &[(tx0_outpt, 0)], &[80_000_000]);

    // Check the second transaction gets rejected by mempool
    let mut mempool = setup_with_chainstate(tf.chainstate());
    let res = mempool.add_transaction_with_origin(tx1, origin.into());
    assert!(res.is_err());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_orphan_does_not_block_good_one(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis_id = tf.genesis().get_id();

    let tx0 = make_tx(
        &mut rng,
        &[(OutPointSourceId::BlockReward(genesis_id.into()), 0)],
        &[100_000_000],
    );
    let tx0_outpt = OutPointSourceId::Transaction(tx0.transaction().get_id());

    let tx1_good = make_tx(&mut rng, &[(tx0_outpt.clone(), 0)], &[80_000_000]);
    let tx1_good_id = tx1_good.transaction().get_id();
    let tx1_bad = make_tx(&mut rng, &[(tx0_outpt, 0)], &[130_000_000]);
    let tx1_bad_id = tx1_bad.transaction().get_id();

    let mut mempool = setup_with_chainstate(tf.chainstate());
    mempool.add_transaction_test(tx1_bad).unwrap().assert_in_orphan_pool();
    mempool.add_transaction_test(tx1_good).unwrap().assert_in_orphan_pool();

    assert_eq!(mempool.orphans_count(), 2);

    mempool
        .add_transaction_with_origin(tx0, LocalTxOrigin::Mempool.into())
        .unwrap()
        .assert_in_mempool();

    assert!(mempool.has_work());
    mempool.process_queue();

    assert!(mempool.contains_transaction(&tx1_good_id));
    assert!(!mempool.contains_transaction(&tx1_bad_id));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn orphan_scheduling(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis_id = tf.genesis().get_id();

    let mut gen_origin = {
        let seed = Seed::from_u64(rng.gen());
        let mut rng = make_seedable_rng(seed);
        move || RemoteTxOrigin::new(p2p_types::PeerId::from_u64(rng.gen_range(1..=4)))
    };

    // Set up the transactions, similar to the diamond test above

    let tx0 = make_tx(
        &mut rng,
        &[(OutPointSourceId::BlockReward(genesis_id.into()), 0)],
        &[100_000_000, 50_000_000],
    );
    let tx0_id = tx0.transaction().get_id();
    let tx0_outpt = OutPointSourceId::Transaction(tx0_id);

    let tx1 = make_tx(
        &mut rng,
        &[(tx0_outpt.clone(), 0)],
        &[80_000_000, 10_000_000],
    );
    let tx1_id = tx1.transaction().get_id();
    let tx1_outpt = OutPointSourceId::Transaction(tx1_id);

    let tx2 = make_tx(&mut rng, &[(tx0_outpt, 1)], &[30_000_000]);
    let tx2_id = tx2.transaction().get_id();
    let tx2_outpt = OutPointSourceId::Transaction(tx2_id);

    let tx3 = make_tx(
        &mut rng,
        &[(tx1_outpt.clone(), 0), (tx2_outpt, 0)],
        &[90_000_000],
    );
    let tx3_id = tx3.transaction().get_id();

    let tx4 = make_tx(&mut rng, &[(tx1_outpt, 1)], &[9_000_000]);
    let tx4_id = tx4.transaction().get_id();

    // Set up mempool and insert the transactions in particular order
    let mut mempool = setup_with_chainstate(tf.chainstate());

    mempool
        .add_transaction_with_origin(tx3, gen_origin().into())
        .unwrap()
        .assert_in_orphan_pool();
    assert_eq!(mempool.work_queue_total_len(), 0);

    mempool
        .add_transaction_with_origin(tx2, gen_origin().into())
        .unwrap()
        .assert_in_orphan_pool();
    assert_eq!(mempool.work_queue_total_len(), 0);

    mempool
        .add_transaction_with_origin(tx0, gen_origin().into())
        .unwrap()
        .assert_in_mempool();
    assert_eq!(mempool.work_queue_total_len(), 1);

    // Handle the transaction from the queue, tx3 should be in the schedule queue afterwards
    mempool.perform_work_unit();
    assert!(mempool.contains_transaction(&tx2_id));
    assert!(mempool.contains_orphan_transaction(&tx3_id));
    assert_eq!(mempool.work_queue_total_len(), 1);

    // Check tx3, realize it's not ready yet
    mempool.perform_work_unit();
    assert!(mempool.contains_transaction(&tx2_id));
    assert!(mempool.contains_orphan_transaction(&tx3_id));
    assert_eq!(mempool.work_queue_total_len(), 0);

    // Submit tx4, should not really change much
    mempool
        .add_transaction_with_origin(tx4, gen_origin().into())
        .unwrap()
        .assert_in_orphan_pool();
    assert_eq!(mempool.work_queue_total_len(), 0);

    // Now submit tx1 which releases tx3 and tx4
    mempool
        .add_transaction_with_origin(tx1, gen_origin().into())
        .unwrap()
        .assert_in_mempool();
    assert_eq!(mempool.work_queue_total_len(), 2);

    // Process the remainder of the queue
    mempool.perform_work_unit();
    mempool.perform_work_unit();
    assert_eq!(mempool.work_queue_total_len(), 0);

    // Now all transactions should be in mempool
    for tx_id in [&tx0_id, &tx1_id, &tx2_id, &tx3_id, &tx4_id] {
        assert!(mempool.contains_transaction(tx_id));
    }
}
