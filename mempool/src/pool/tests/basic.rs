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

use std::time::Duration;

use tokio::sync::mpsc;

use chainstate::BlockSource;
use common::chain::block::timestamp::BlockTimestamp;

use crate::event::NewTip;

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

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reject_txs_during_ibd(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    // Set up chainstate, mempool, and mock time
    let tf = TestFramework::builder(&mut rng)
        .with_max_tip_age(Duration::from_secs(10).into())
        .with_initial_time_since_genesis(200)
        .build();
    let genesis_id = tf.genesis().get_id();
    let mock_time = tf.time_value.as_ref().unwrap().shallow_clone();
    let mock_clock = tf.time_getter.clone();

    let mut mempool = setup_with_chainstate_and_clock(tf.chainstate(), mock_clock);
    let chainstate = mempool.chainstate_handle().shallow_clone();

    assert!(mempool.is_initial_block_download());

    // A test transaction
    let tx1 = make_tx(&mut rng, &[(genesis_id.into(), 0)], &[1_000_000_000]);
    let tx1_id = tx1.transaction().get_id();

    // We should not be able to add the transaction yet
    let res = mempool.add_transaction_test(tx1.clone());
    assert_eq!(res, Err(TxValidationError::AddedDuringIBD.into()));
    assert!(!mempool.contains_transaction(&tx1_id));

    // Submit an "old" block
    let block1_time = BlockTimestamp::from_int_seconds(mock_time.fetch_add(15));
    let block1 = make_test_block(vec![], genesis_id, block1_time);
    let block1_id = block1.get_id();
    chainstate
        .call_mut(move |c| c.process_block(block1, BlockSource::Local))
        .await
        .unwrap()
        .unwrap();

    mempool
        .process_chainstate_event(ChainstateEvent::NewTip {
            id: block1_id,
            height: BlockHeight::new(1),
            is_initial_block_download: true,
        })
        .unwrap();
    assert!(mempool.is_initial_block_download());

    // We should not be able to add the transaction yet
    let res = mempool.add_transaction_test(tx1.clone());
    assert_eq!(res, Err(TxValidationError::AddedDuringIBD.into()));
    assert!(!mempool.contains_transaction(&tx1_id));

    // Submit a "fresh" block, but pass is_initial_block_download=true in the event.
    // Mempool should trust the event.
    let block2_time = BlockTimestamp::from_int_seconds(mock_time.fetch_add(3));
    let block2 = make_test_block(vec![], block1_id, block2_time);
    let block2_id = block2.get_id();
    chainstate
        .call_mut(move |c| c.process_block(block2, BlockSource::Local))
        .await
        .unwrap()
        .unwrap();
    mempool
        .process_chainstate_event(ChainstateEvent::NewTip {
            id: block2_id,
            height: BlockHeight::new(2),
            is_initial_block_download: true,
        })
        .unwrap();

    assert!(mempool.is_initial_block_download());

    // We should not be able to add the transaction yet
    let res = mempool.add_transaction_test(tx1.clone());
    assert_eq!(res, Err(TxValidationError::AddedDuringIBD.into()));
    assert!(!mempool.contains_transaction(&tx1_id));

    // Submit an "old" block, but pass is_initial_block_download=false in the event.
    // Mempool should trust the event.
    let block3_time = BlockTimestamp::from_int_seconds(mock_time.fetch_add(15));
    let block3 = make_test_block(vec![], block2_id, block3_time);
    let block3_id = block3.get_id();
    chainstate
        .call_mut(move |c| c.process_block(block3, BlockSource::Local))
        .await
        .unwrap()
        .unwrap();
    mempool
        .process_chainstate_event(ChainstateEvent::NewTip {
            id: block3_id,
            height: BlockHeight::new(3),
            is_initial_block_download: false,
        })
        .unwrap();

    assert!(!mempool.is_initial_block_download());

    // We should be able to add the transaction now
    let res = mempool.add_transaction_test(tx1);
    assert_eq!(res, Ok(TxStatus::InMempool));
    assert!(mempool.contains_transaction(&tx1_id));
}

// Check that during transition from in-ibd to after-ibd state certain parts of the mempool's
// internal state are correctly propagated, namely:
// 1) the max size;
// 2) the event broadcaster;
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ibd_transition(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    // Set up chainstate, mempool, and mock time
    let tf = TestFramework::builder(&mut rng)
        .with_max_tip_age(Duration::from_secs(10).into())
        .with_initial_time_since_genesis(200)
        .build();
    let genesis_id = tf.genesis().get_id();
    let mock_time = tf.time_value.as_ref().unwrap().shallow_clone();
    let mock_clock = tf.time_getter.clone();

    let mut mempool = setup_with_chainstate_and_clock(tf.chainstate(), mock_clock);
    let chainstate = mempool.chainstate_handle().shallow_clone();

    assert!(mempool.is_initial_block_download());
    assert_eq!(mempool.max_size().as_bytes(), MAX_MEMPOOL_SIZE_BYTES);

    // Modify max size.
    let new_max_size = MAX_MEMPOOL_SIZE_BYTES * 2;
    mempool.set_size_limit(MempoolMaxSize::from_bytes(new_max_size)).unwrap();
    assert_eq!(mempool.max_size().as_bytes(), new_max_size);

    // Subscribe to events both via subscribe_to_events and subscribe_to_event_broadcast.
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    mempool.subscribe_to_events(Arc::new(move |event| events_tx.send(event).unwrap()));
    let mut events_broadcast_rx = mempool.subscribe_to_event_broadcast();

    // Submit and process a block, passing false for is_initial_block_download.
    // The mempool should switch to the after-ibd state.
    let block_time = BlockTimestamp::from_int_seconds(mock_time.fetch_add(3));
    let block = make_test_block(vec![], genesis_id, block_time);
    let block_id = block.get_id();
    let block_height = BlockHeight::new(1);
    chainstate
        .call_mut(move |c| c.process_block(block, BlockSource::Local))
        .await
        .unwrap()
        .unwrap();
    mempool
        .process_chainstate_event(ChainstateEvent::NewTip {
            id: block_id,
            height: block_height,
            is_initial_block_download: false,
        })
        .unwrap();

    // The mempool is no longer in ibd.
    assert!(!mempool.is_initial_block_download());

    // Check that max_size is still correct
    assert_eq!(mempool.max_size().as_bytes(), new_max_size);

    // Make and add a transaction
    let tx = make_tx(&mut rng, &[(genesis_id.into(), 0)], &[1_000_000_000]);
    let tx_id = tx.transaction().get_id();
    let res = mempool.add_transaction_test(tx);
    assert_eq!(res, Ok(TxStatus::InMempool));
    assert!(mempool.contains_transaction(&tx_id));

    // Check that the new tip event was sent.
    let expected_event = MempoolEvent::NewTip(NewTip::new(block_id, block_height));

    let event = events_rx.recv().await;
    assert_eq!(event.as_ref(), Some(&expected_event));

    let event = events_broadcast_rx.recv().await;
    assert_eq!(event.as_ref(), Some(&expected_event));
}
