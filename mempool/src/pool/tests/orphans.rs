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

    let mut mempool = setup_with_chainstate(tf.chainstate()).await;

    // Add the second transaction first
    let res = mempool.add_transaction(tx1, TxOrigin::TEST);
    assert_eq!(res, Ok(TxStatus::InOrphanPool));
    assert!(mempool.contains_orphan_transaction(&tx1_id));
    assert!(!mempool.contains_transaction(&tx1_id));

    // Now add the first transaction
    let res = mempool.add_transaction(tx0, TxOrigin::TEST);
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

    let txs = vec![tx0, tx1, tx2, tx3];
    let tx_ids: Vec<_> = txs.iter().map(|tx| tx.transaction().get_id()).collect();

    // Set up mempool and execute the insertion plan
    let mut mempool = setup_with_chainstate(tf.chainstate()).await;

    for (tx_no, expected_mempool, expected_orphans) in insertion_plan {
        let _ = mempool.add_transaction(txs[tx_no].clone(), TxOrigin::TEST).expect("tx add");

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
    let mut mempool = setup_with_chainstate(tf.chainstate()).await;
    assert_eq!(
        mempool.add_transaction(tx0, TxOrigin::TEST),
        Ok(TxStatus::InMempool)
    );
    assert_eq!(
        mempool.add_transaction(tx1a, TxOrigin::TEST),
        Ok(TxStatus::InMempool)
    );

    // Check transaction that conflicts with one in mempool gets rejected instead of ending up in
    // the orphan pool.
    assert_eq!(
        mempool.add_transaction(tx1b, TxOrigin::TEST),
        Err(OrphanPoolError::MempoolConflict.into()),
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_graph_subset_permutation(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    // Generate a valid graph of transactions
    let num_txs = rng.gen_range(15..40);
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
        let mut mempool = setup_with_chainstate(tf.chainstate()).await;

        // Now add each transaction in the subsequence
        tx_subseq.iter().for_each(|tx| {
            let tx = tx.transaction().clone();
            let _ = mempool.add_transaction(tx, TxOrigin::TEST).expect("tx add");
        });

        // Check the final state of each transaction in the original sequence
        results.push(all_tx_ids.iter().map(|id| TxStatus::fetch(&mempool, id)).collect());
    }

    // Check the final outcome, i.e. which transactions end up in mempool versus orphan pool, is
    // independent of the order of insertion. This is only guaranteed if the orphan pool capacity
    // is not exhausted. Here, we are within the capacity.
    log::debug!("result = {:?}", results[0]);
    assert_eq!(results[0], results[1]);
}
