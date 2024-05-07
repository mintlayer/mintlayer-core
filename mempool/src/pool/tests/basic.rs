// Copyright (c) 2024 RBB S.r.l
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
async fn one_ancestor_replaceability_signal_is_enough(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();
    let mut tx_builder = TransactionBuilder::new().add_input(
        TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
        empty_witness(&mut rng),
    );
    let num_outputs = 2;

    for _ in 0..num_outputs {
        tx_builder = tx_builder.add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(2_000)),
            anyonecanspend_address(),
        ));
    }
    let tx = tx_builder.build();

    let mut mempool = setup_with_chainstate(tf.chainstate());
    mempool.add_transaction_test(tx.clone())?.assert_in_mempool();

    let flags_replaceable = 1;
    let flags_irreplaceable = 0;

    let outpoint_source_id = OutPointSourceId::Transaction(tx.transaction().get_id());
    let ancestor_with_signal = tx_spend_input(
        mempool.tx_pool(),
        TxInput::from_utxo(outpoint_source_id.clone(), 0),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        None,
        flags_replaceable,
    )
    .await?;

    let ancestor_without_signal = tx_spend_input(
        mempool.tx_pool(),
        TxInput::from_utxo(outpoint_source_id, 1),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        None,
        flags_irreplaceable,
    )
    .await?;

    mempool.add_transaction_test(ancestor_with_signal.clone())?.assert_in_mempool();
    mempool
        .add_transaction_test(ancestor_without_signal.clone())?
        .assert_in_mempool();

    let input_with_replaceable_parent = TxInput::from_utxo(
        OutPointSourceId::Transaction(ancestor_with_signal.transaction().get_id()),
        0,
    );

    let input_with_irreplaceable_parent = TxInput::from_utxo(
        OutPointSourceId::Transaction(ancestor_without_signal.transaction().get_id()),
        0,
    );

    // TODO compute minimum necessary relay fee instead of just overestimating it
    let original_fee: Fee = Amount::from_atoms(200).into();
    let dummy_output = TxOutput::Transfer(
        OutputValue::Coin(*original_fee),
        Destination::AnyoneCanSpend,
    );
    let replaced_tx = tx_spend_several_inputs(
        mempool.tx_pool(),
        &[input_with_irreplaceable_parent.clone(), input_with_replaceable_parent],
        &[
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        ],
        original_fee,
        flags_irreplaceable,
    )
    .await?;
    let replaced_tx_id = replaced_tx.transaction().get_id();

    mempool.add_transaction_test(replaced_tx)?.assert_in_mempool();

    let replacing_tx = SignedTransaction::new(
        Transaction::new(
            flags_irreplaceable,
            vec![input_with_irreplaceable_parent],
            vec![dummy_output],
        )?,
        vec![InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec()))],
    )
    .expect("invalid witness count");

    let result = mempool.add_transaction_test(replacing_tx);
    if ENABLE_RBF {
        assert_eq!(result, Ok(TxStatus::InMempool));
        assert!(!mempool.contains_transaction(&replaced_tx_id));
    } else {
        assert_eq!(result, Err(Error::Orphan(OrphanPoolError::MempoolConflict)));
        assert!(mempool.contains_transaction(&replaced_tx_id));
    };

    mempool.tx_store().assert_valid();

    Ok(())
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spends_new_unconfirmed(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();
    let mut tx_builder = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
            empty_witness(&mut rng),
        )
        .with_flags(1);

    for _ in 0..2 {
        tx_builder = tx_builder.add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(999_999_999_000)),
            anyonecanspend_address(),
        ));
    }

    let tx = tx_builder.build();
    let outpoint_source_id = OutPointSourceId::Transaction(tx.transaction().get_id());
    let mut mempool = setup_with_chainstate(tf.chainstate());
    mempool.add_transaction_test(tx)?.assert_in_mempool();

    let input1 = TxInput::from_utxo(outpoint_source_id.clone(), 0);
    let input2 = TxInput::from_utxo(outpoint_source_id, 1);

    let flags = 0;
    let original_fee: Fee = Amount::from_atoms(100).into();
    let replaced_tx = tx_spend_input(
        mempool.tx_pool(),
        input1.clone(),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        original_fee,
        flags,
    )
    .await?;
    mempool.add_transaction_test(replaced_tx)?.assert_in_mempool();
    let relay_fee = get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE);
    let replacement_fee: Fee = (Amount::from_atoms(100) + relay_fee).unwrap().into();
    let incoming_tx = tx_spend_several_inputs(
        mempool.tx_pool(),
        &[input1, input2],
        &[
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        ],
        replacement_fee,
        flags,
    )
    .await?;

    let res = mempool.add_transaction_test(incoming_tx);
    assert_eq!(res, Err(Error::Orphan(OrphanPoolError::MempoolConflict)));
    mempool.tx_store().assert_valid();
    Ok(())
}
