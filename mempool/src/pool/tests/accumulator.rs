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
use crate::tx_accumulator::DefaultTxAccumulator;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_order_respects_deps(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis_id = tf.genesis().get_id();

    let tx0 = make_tx(&mut rng, &[(genesis_id.into(), 0)], &[900_000_000_000]);
    let tx0_id = tx0.transaction().get_id();

    let tx1 = make_tx(&mut rng, &[(tx0_id.into(), 0)], &[800_000_000_000]);
    let tx1_id = tx1.transaction().get_id();

    let tx2 = make_tx(&mut rng, &[(tx1_id.into(), 0)], &[500_000_000_000]);
    let tx2_id = tx2.transaction().get_id();

    let mut mempool = setup_with_chainstate(tf.chainstate()).await;
    assert_eq!(
        mempool.add_transaction(tx0, TxOrigin::TEST),
        Ok(TxStatus::InMempool)
    );
    assert_eq!(
        mempool.add_transaction(tx1, TxOrigin::TEST),
        Ok(TxStatus::InMempool)
    );
    assert_eq!(
        mempool.add_transaction(tx2, TxOrigin::TEST),
        Ok(TxStatus::InMempool)
    );
    assert!(mempool.contains_transaction(&tx2_id));

    let accumulator = Box::new(DefaultTxAccumulator::new(1_000_000, genesis_id.into()));
    let accumulator = mempool.collect_txs(accumulator).unwrap();
    let tx_ids: Vec<_> =
        accumulator.transactions().iter().map(|tx| tx.transaction().get_id()).collect();

    assert_eq!(tx_ids, vec![tx0_id, tx1_id, tx2_id]);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_graph_respects_deps(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis_id = tf.genesis().get_id();
    let time = tf.genesis().timestamp();

    let txs: Vec<_> = generate_transaction_graph(&mut rng, time.as_duration_since_epoch())
        .take(15)
        .collect();

    let mut mempool = setup_with_chainstate(tf.chainstate()).await;

    for tx in &txs {
        let res = mempool.add_transaction(tx.transaction().clone(), TxOrigin::TEST);
        assert_eq!(res, Ok(TxStatus::InMempool));
    }

    let txs_by_id: BTreeMap<_, _> = txs.into_iter().map(|tx| (*tx.tx_id(), tx)).collect();

    let accumulator = Box::new(DefaultTxAccumulator::new(10_000_000, genesis_id.into()));
    let accumulator = mempool.collect_txs(accumulator).unwrap();
    let position_map: BTreeMap<Id<Transaction>, usize> = accumulator
        .transactions()
        .iter()
        .enumerate()
        .map(|(pos, tx)| (tx.transaction().get_id(), pos))
        .collect();

    for (tx_id, tx_pos) in position_map.iter() {
        let tx = txs_by_id[tx_id].transaction().transaction();
        tx.inputs()
            .iter()
            .filter_map(|i| i.utxo_outpoint().and_then(|o| o.tx_id().get_tx_id().cloned()))
            .for_each(|parent_tx_id| assert!(position_map[&parent_tx_id] < *tx_pos));
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn collect_transactions(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();
    let mut mempool = setup_with_chainstate(tf.chainstate()).await;

    let size_limit: usize = 1_000;
    let tx_accumulator = DefaultTxAccumulator::new(size_limit, mempool.best_block_id());
    let returned_accumulator = mempool.collect_txs(Box::new(tx_accumulator)).unwrap();
    let collected_txs = returned_accumulator.transactions();
    let expected_num_txs_collected: usize = 0;
    assert_eq!(collected_txs.len(), expected_num_txs_collected);

    let target_txs = 10;

    let mut tx_builder = TransactionBuilder::new().add_input(
        TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
        empty_witness(&mut rng),
    );
    for i in 0..target_txs {
        tx_builder = tx_builder.add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1000 * (target_txs + 1 - i))),
            Destination::AnyoneCanSpend,
        ))
    }
    let initial_tx = tx_builder.build();
    let initial_tx_id = initial_tx.transaction().get_id();
    mempool.add_transaction(initial_tx, TxOrigin::TEST)?.assert_in_mempool();
    for i in 0..target_txs {
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::Transaction(initial_tx_id), i as u32),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(0)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        mempool.add_transaction(tx.clone(), TxOrigin::TEST)?.assert_in_mempool();
    }

    let size_limit = 1_000;
    let tx_accumulator = DefaultTxAccumulator::new(size_limit, mempool.best_block_id());
    let returned_accumulator = mempool.collect_txs(Box::new(tx_accumulator)).unwrap();
    let collected_txs = returned_accumulator.transactions();
    log::debug!("ancestor index: {:?}", mempool.store.txs_by_ancestor_score);
    let expected_num_txs_collected = 6;
    assert_eq!(collected_txs.len(), expected_num_txs_collected);
    let total_tx_size: usize = collected_txs.iter().map(|tx| tx.encoded_size()).sum();
    assert!(total_tx_size <= size_limit);

    let tx_accumulator = DefaultTxAccumulator::new(0, mempool.best_block_id());
    let returned_accumulator = mempool.collect_txs(Box::new(tx_accumulator)).unwrap();
    let collected_txs = returned_accumulator.transactions();
    assert_eq!(collected_txs.len(), 0);

    let tx_accumulator = DefaultTxAccumulator::new(1, mempool.best_block_id());
    let returned_accumulator = mempool.collect_txs(Box::new(tx_accumulator)).unwrap();
    let collected_txs = returned_accumulator.transactions();
    assert_eq!(collected_txs.len(), 0);
    Ok(())
}
