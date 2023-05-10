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

fn tx_status<T>(mempool: &Mempool<T>, tx_id: &Id<Transaction>) -> Option<TxStatus> {
    let in_mempool = mempool.contains_transaction(tx_id);
    let in_orphan_pool = mempool.contains_orphan_transaction(tx_id);
    match (in_mempool, in_orphan_pool) {
        (false, false) => None,
        (false, true) => Some(TxStatus::InOrphanPool),
        (true, false) => Some(TxStatus::InMempool),
        (true, true) => panic!("Transaction both in mempool and orphan pool"),
    }
}

#[rstest]
#[case(
    Seed::from_entropy(),
    Amount::from_atoms(100_000_000),
    Amount::from_atoms(90_000_000),
    true
)]
#[case(
    Seed::from_entropy(),
    Amount::from_atoms(90_000_000),
    Amount::from_atoms(100_000_000),
    false
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn simple_sequence(
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
            TxInput::new(OutPointSourceId::BlockReward(genesis_id.into()), 0),
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
            TxInput::new(OutPointSourceId::Transaction(tx0_id), 0),
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
    let res = mempool.add_transaction(tx1);
    assert_eq!(res, Ok(TxStatus::InOrphanPool));
    assert!(mempool.contains_orphan_transaction(&tx1_id));
    assert!(!mempool.contains_transaction(&tx1_id));

    // Now add the first transaction
    let res = mempool.add_transaction(tx0);
    assert_eq!(res, Ok(TxStatus::InMempool));

    // Now the second tx (which we submitted first) should be either rejected or in mempool
    assert!(!mempool.contains_orphan_transaction(&tx1_id));
    assert_eq!(mempool.contains_transaction(&tx1_id), expected_in_mempool);
}

#[rstest]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sequence_permutation(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    // Generate a valid graph of transactions
    let full_tx_sequence: Vec<_> = {
        let tf = TestFramework::builder(&mut rng).build();
        let mut utxos = vec![(
            TxInput::new(
                OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                0,
            ),
            100_000_000_000_000_u128,
        )];
        let rng = &mut rng; // avoid moving rng into the closure below

        (0..rng.gen_range(15..40))
            .map(move |_| {
                let n_inputs = rng.gen_range(1..=std::cmp::min(3, utxos.len()));
                let n_outputs = rng.gen_range(1..=3);

                let mut builder = TransactionBuilder::new();
                let mut total = 0u128;
                let mut amts = Vec::new();

                for _ in 0..n_inputs {
                    let (outpt, amt) = utxos.swap_remove(rng.gen_range(0..utxos.len()));
                    total += amt;
                    builder = builder.add_input(outpt, empty_witness(rng));
                }

                for _ in 0..n_outputs {
                    let amt = rng.gen_range((total / 2)..(95 * total / 100));
                    total -= amt;
                    builder = builder.add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(amt)),
                        Destination::AnyoneCanSpend,
                    ));
                    amts.push(amt);
                }

                let tx = builder.build();
                let tx_id = tx.transaction().get_id();

                utxos.extend(amts.into_iter().enumerate().map(|(i, amt)| {
                    (
                        TxInput::new(OutPointSourceId::Transaction(tx_id), i as u32),
                        amt,
                    )
                }));

                tx
            })
            .collect()
    };

    let all_tx_ids: Vec<_> = full_tx_sequence.iter().map(|tx| tx.transaction().get_id()).collect();

    // Pick a subset of these transactions, taking each with 90% probability.
    let tx_subseq_0: Vec<_> = full_tx_sequence
        .iter()
        .filter(|_| rng.gen_range(0..100) < 90)
        .cloned()
        .collect();

    // Take the same subsequence but with randomly shuffled order.
    // This means some transactions will be temporarily in the orphan pool.
    let tx_subseq_1 = {
        let mut subseq = tx_subseq_0.clone();
        let salt = rng.gen::<u64>();
        subseq.sort_unstable_by_key(|tx| hash_encoded(&(tx, salt)));
        subseq
    };

    let mut results: Vec<Vec<Option<TxStatus>>> = Vec::new();
    for tx_subseq in [tx_subseq_0, tx_subseq_1] {
        let tf = TestFramework::builder(&mut rng).build();
        let mut mempool = setup_with_chainstate(tf.chainstate()).await;

        // Now add each transaction in the subsequence
        tx_subseq.into_iter().for_each(|tx| {
            mempool.add_transaction(tx).expect("tx add");
        });

        // Check the final state of each transaction in the original sequence
        results.push(all_tx_ids.iter().map(|id| tx_status(&mempool, id)).collect());
    }

    // Check the final outcome, i.e. which transactions end up in mempool versus orphan pool, is
    // independent of the order of insertion. This is only guaranteed if the orphan pool capacity
    // is not exhausted. Here, we are within the capacity.
    log::debug!("result = {:?}", results[0]);
    assert_eq!(results[0], results[1]);
}
