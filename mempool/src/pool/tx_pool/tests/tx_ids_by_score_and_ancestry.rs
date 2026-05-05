// Copyright (c) 2026 RBB S.r.l
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

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tx_ids_by_score_and_ancestry(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = TestFramework::builder(&mut rng).build();
    let genesis_id = tf.genesis().get_id();

    let output_amount = 1000;
    let funding_tx = {
        let mut builder = TransactionBuilder::new().add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis_id.into()), 0),
            empty_witness(&mut rng),
        );

        for _ in 0..7 {
            builder = builder.add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(output_amount)),
                Destination::AnyoneCanSpend,
            ));
        }

        builder.build()
    };
    let funding_tx_id = funding_tx.transaction().get_id();
    tf.make_block_builder()
        .add_transaction(funding_tx)
        .build_and_process(&mut rng)
        .unwrap();

    let mut mempool = setup_with_chainstate_generic(
        tf.chainstate(),
        MempoolConfig {
            min_tx_relay_fee_rate: FeeRate::from_amount_per_kb(Amount::ZERO).into(),
        },
        Default::default(),
    );

    // Create 3 independent transactions paying different fees ("high", "mid" and "low").
    let high_fee = rng.random_range(800..900);
    let high_fee_tx = make_tx(
        &mut rng,
        &[(funding_tx_id.into(), 0)],
        &[output_amount - high_fee],
    );
    let high_fee_tx_id = high_fee_tx.transaction().get_id();
    let mid_fee = rng.random_range(700..800);
    let mid_fee_tx = make_tx(
        &mut rng,
        &[(funding_tx_id.into(), 1)],
        &[output_amount - mid_fee],
    );
    let mid_fee_tx_id = mid_fee_tx.transaction().get_id();
    let low_fee = rng.random_range(600..700);
    let low_fee_tx = make_tx(
        &mut rng,
        &[(funding_tx_id.into(), 2)],
        &[output_amount - low_fee],
    );
    let low_fee_tx_id = low_fee_tx.transaction().get_id();

    // Create a chain of transactions where the parent pays fee even lower than the "low" one
    // above, but descendants pay random fee that may be even higher than the "high" one.
    let tx_chain_root_fee = rng.random_range(1..600);
    let tx_chain_root_tx = make_tx(
        &mut rng,
        &[(funding_tx_id.into(), 3)],
        &[1, output_amount - tx_chain_root_fee - 1],
    );
    let tx_chain_root_tx_id = tx_chain_root_tx.transaction().get_id();

    let tx_chain_tx1_fee = rng.random_range(500..1000);
    let tx_chain_tx1 = make_tx(
        &mut rng,
        &[(funding_tx_id.into(), 4), (tx_chain_root_tx_id.into(), 0)],
        &[1, output_amount - tx_chain_tx1_fee],
    );
    let tx_chain_tx1_id = tx_chain_tx1.transaction().get_id();

    let tx_chain_tx2_fee = rng.random_range(500..1000);
    let tx_chain_tx2 = make_tx(
        &mut rng,
        &[(funding_tx_id.into(), 5), (tx_chain_tx1_id.into(), 0)],
        &[1, output_amount - tx_chain_tx2_fee],
    );
    let tx_chain_tx2_id = tx_chain_tx2.transaction().get_id();

    let tx_chain_tx3_fee = rng.random_range(500..1000);
    let tx_chain_tx3 = make_tx(
        &mut rng,
        &[(funding_tx_id.into(), 6), (tx_chain_tx2_id.into(), 0)],
        &[1, output_amount - tx_chain_tx3_fee],
    );
    let tx_chain_tx3_id = tx_chain_tx3.transaction().get_id();

    for tx in [
        high_fee_tx,
        mid_fee_tx,
        low_fee_tx,
        tx_chain_root_tx,
        tx_chain_tx1,
        tx_chain_tx2,
        tx_chain_tx3,
    ] {
        assert_eq!(mempool.add_transaction_test(tx), Ok(TxStatus::InMempool));
    }

    // The set contains all 3 independent txs, and only the start and end txs of the chain.
    let selected_tx_ids = std::collections::BTreeSet::from([
        high_fee_tx_id,
        mid_fee_tx_id,
        low_fee_tx_id,
        tx_chain_root_tx_id,
        tx_chain_tx3_id,
    ]);
    let result = mempool.get_best_tx_ids_by_score_and_ancestry(&selected_tx_ids, 1).unwrap();
    assert_eq!(result, [high_fee_tx_id]);

    let result = mempool.get_best_tx_ids_by_score_and_ancestry(&selected_tx_ids, 2).unwrap();
    assert_eq!(result, [high_fee_tx_id, mid_fee_tx_id]);

    let result = mempool.get_best_tx_ids_by_score_and_ancestry(&selected_tx_ids, 3).unwrap();
    assert_eq!(result, [high_fee_tx_id, mid_fee_tx_id, low_fee_tx_id]);

    let result = mempool.get_best_tx_ids_by_score_and_ancestry(&selected_tx_ids, 4).unwrap();
    assert_eq!(
        result,
        [high_fee_tx_id, mid_fee_tx_id, low_fee_tx_id, tx_chain_root_tx_id]
    );

    let result = mempool.get_best_tx_ids_by_score_and_ancestry(&selected_tx_ids, 5).unwrap();
    assert_eq!(
        result,
        [
            high_fee_tx_id,
            mid_fee_tx_id,
            low_fee_tx_id,
            tx_chain_root_tx_id,
            tx_chain_tx3_id
        ]
    );

    let result = mempool
        .get_best_tx_ids_by_score_and_ancestry(&selected_tx_ids, rng.random_range(6..100))
        .unwrap();
    assert_eq!(
        result,
        [
            high_fee_tx_id,
            mid_fee_tx_id,
            low_fee_tx_id,
            tx_chain_root_tx_id,
            tx_chain_tx3_id
        ]
    );
}
