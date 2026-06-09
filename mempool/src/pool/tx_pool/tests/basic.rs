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

use mempool_types::tx_origin::LocalTxOrigin;

use crate::pool::tx_pool::store::{StoreHashSet, TxMempoolEntryWithAncestors};

use super::*;

#[test]
fn dummy_size() {
    log::debug!("1, 1: {}", estimate_tx_size(1, 1));
    log::debug!("1, 2: {}", estimate_tx_size(1, 2));
    log::debug!("1, 400: {}", estimate_tx_size(1, 400));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[test]
fn real_size(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();
    let mut tx_builder = TransactionBuilder::new().add_input(
        TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
        empty_witness(&mut rng),
    );

    for _ in 0..400 {
        tx_builder = tx_builder.add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1)),
            anyonecanspend_address(),
        ));
    }

    let tx = tx_builder.build();
    log::debug!("real size of tx {}", tx.encoded_size());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_single_tx() -> anyhow::Result<()> {
    let mut mempool = setup();

    let outpoint_source_id = mempool.chain_config.genesis_block_id().into();

    let flags = 0;
    let input = TxInput::from_utxo(outpoint_source_id, 0);
    let relay_fee: Fee = get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE).into();
    let tx = tx_spend_input(
        &mempool,
        input,
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        relay_fee,
        flags,
    )
    .await?;

    let tx_clone = tx.clone();
    let tx_id = tx.transaction().get_id();
    mempool.add_transaction_test(tx)?.assert_in_mempool();
    assert!(mempool.contains_transaction(&tx_id));
    let all_txs = mempool.get_all();
    assert_eq!(all_txs, vec![tx_clone]);
    mempool.store.remove_tx(&tx_id, MempoolRemovalReason::Block);
    assert!(!mempool.contains_transaction(&tx_id));
    let all_txs = mempool.get_all();
    assert_eq!(all_txs, Vec::<SignedTransaction>::new());
    mempool.store.assert_valid();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_tx_with_fee_rate_below_minimum() {
    let min_relay_fee_rate = FeeRate::from_amount_per_kb(Amount::from_atoms(123));
    let mut mempool = setup_with_min_tx_relay_fee_rate(min_relay_fee_rate);

    async fn make_tx(
        tx_pool: &TxPool<StoreMemoryUsageEstimator>,
        relay_fee: Fee,
    ) -> SignedTransaction {
        let outpoint_source_id = tx_pool.chain_config.genesis_block_id().into();
        let flags = 0;
        let input = TxInput::from_utxo(outpoint_source_id, 0);

        tx_spend_input(
            tx_pool,
            input,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
            relay_fee,
            flags,
        )
        .await
        .unwrap()
    }

    let estimated_tx_size = make_tx(&mempool, Amount::ZERO.into()).await.encoded_size();
    let min_relay_fee = min_relay_fee_rate.compute_fee(estimated_tx_size).unwrap();

    // Tx1's fee is below the minimum, so it must be rejected.
    let tx1_relay_fee = (min_relay_fee - Amount::from_atoms(1).into()).unwrap();
    let tx1 = make_tx(&mempool, tx1_relay_fee).await;

    let err = mempool.add_transaction_test(tx1).unwrap_err();
    assert!(matches!(
        err,
        Error::Policy(MempoolPolicyError::InsufficientFeesToRelay {
            tx_fee: _,
            min_relay_fee: _
        })
    ));

    // Tx2's fee is exactly the minimum, so it must be accepted.
    let tx2 = make_tx(&mempool, min_relay_fee).await;
    let tx_status = mempool.add_transaction_test(tx2).unwrap();
    assert_eq!(tx_status, TxStatus::InMempool);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn txs_sorted(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();
    let mut mempool = setup_with_chainstate(tf.chainstate());
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
    mempool.add_transaction_test(initial_tx)?.assert_in_mempool();
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
        mempool.add_transaction_test(tx.clone())?.assert_in_mempool();
    }

    let mut fees = Vec::new();
    for tx in mempool.get_all() {
        fees.push(try_get_fee(&mempool, &tx).await)
    }
    let mut fees_sorted = fees.clone();
    fees_sorted.sort();
    assert_eq!(fees, fees_sorted);
    mempool.store.assert_valid();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tx_no_inputs() {
    let mut mempool = setup();
    let tx = TransactionBuilder::new().build();
    let res = mempool.add_transaction_test(tx);

    assert_eq!(
        res,
        Err(MempoolPolicyError::NoInputs.into()),
        "Should have failed with no inputs, got {res:?} instead"
    );
    mempool.store.assert_valid();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tx_no_outputs(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();
    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
            empty_witness(&mut rng),
        )
        .build();
    let mut mempool = setup_with_chainstate(tf.chainstate());
    assert_eq!(
        mempool.add_transaction_test(tx),
        Err(MempoolPolicyError::NoOutputs.into())
    );
    mempool.store.assert_valid();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tx_duplicate_inputs() -> anyhow::Result<()> {
    let mut mempool = setup();

    let outpoint_source_id = OutPointSourceId::from(mempool.chain_config.genesis_block_id());
    let input = TxInput::from_utxo(outpoint_source_id.clone(), 0);
    let witness = b"attempted_double_spend".to_vec();
    let duplicate_input = TxInput::from_utxo(outpoint_source_id, 0);
    let flags = 0;
    let outputs = tx_spend_input(
        &mempool,
        input.clone(),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        None,
        flags,
    )
    .await?
    .transaction()
    .outputs()
    .to_owned();
    let inputs = vec![input, duplicate_input];
    let tx = SignedTransaction::new(
        Transaction::new(flags, inputs, outputs)?,
        vec![
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
            InputWitness::NoSignature(Some(witness)),
        ],
    )
    .expect("invalid witness count");

    assert!(matches!(
        mempool.add_transaction_test(tx),
        Err(Error::Validity(_)),
    ));
    mempool.store.assert_valid();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tx_already_in_mempool() -> anyhow::Result<()> {
    let mut mempool = setup();

    let outpoint_source_id = OutPointSourceId::from(mempool.chain_config.genesis_block_id());
    let input = TxInput::from_utxo(outpoint_source_id, 0);

    let flags = 0;
    let tx = tx_spend_input(
        &mempool,
        input,
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        None,
        flags,
    )
    .await?;

    mempool.add_transaction_test(tx.clone())?.assert_in_mempool();
    assert_eq!(
        mempool.add_transaction_test(tx),
        Ok(TxStatus::InMempoolDuplicate),
    );
    mempool.store.assert_valid();
    Ok(())
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outpoint_not_found(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let chainstate = tf.chainstate();
    let mut mempool = setup_with_chainstate(chainstate);

    let outpoint_source_id = OutPointSourceId::from(mempool.chain_config.genesis_block_id());

    let good_input = TxInput::from_utxo(outpoint_source_id.clone(), 0);
    let flags = 0;
    let outputs = tx_spend_input(
        &mempool,
        good_input,
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        None,
        flags,
    )
    .await?
    .transaction()
    .outputs()
    .to_owned();

    let bad_outpoint_index = 1;
    let bad_input = TxInput::from_utxo(outpoint_source_id, bad_outpoint_index);

    let inputs = vec![bad_input];
    let tx = SignedTransaction::new(
        Transaction::new(flags, inputs, outputs)?,
        vec![InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec()))],
    )
    .expect("invalid witness count");

    let error = match mempool.add_transaction_test(tx) {
        Err(Error::Validity(TxValidationError::TxValidation(e))) => e,
        res => panic!("Unexpected result {res:?}"),
    };
    assert_eq!(OrphanType::from_error(error), Ok(OrphanType::MissingUtxo));
    mempool.store.assert_valid();

    Ok(())
}

// Create a tx bigger than `ChainConfig::max_tx_size_for_mempool`.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tx_bigger_than_block_size(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();

    let output = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(100)),
        Destination::AnyoneCanSpend,
    );
    let output_size = output.encoded_size();
    let outputs_count =
        tf.chainstate.get_chain_config().max_tx_size_for_mempool() / output_size + 1;
    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
            empty_witness(&mut rng),
        )
        .add_output_n_times(outputs_count, &output)
        .build();
    let mut mempool = setup_with_chainstate(tf.chainstate());

    assert_eq!(
        mempool.add_transaction_test(tx),
        Err(MempoolPolicyError::TxSizeExceedsMaxBlockSize.into())
    );
    mempool.store.assert_valid();
    Ok(())
}

// Create a tx bigger than the cluster size specified in the mempool config.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tx_bigger_than_cluster_size(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();

    let max_cluster_size = rng.random_range(10_000..500_000);
    let output = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(100)),
        Destination::AnyoneCanSpend,
    );
    let output_size = output.encoded_size();
    let outputs_count = max_cluster_size / output_size + 1;
    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
            empty_witness(&mut rng),
        )
        .add_output_n_times(outputs_count, &output)
        .build();
    let tx_size = tx.encoded_size();
    let mempool_config = MempoolConfig {
        min_tx_relay_fee_rate: TEST_MIN_TX_RELAY_FEE_RATE.into(),
        max_cluster_size_bytes: max_cluster_size.into(),

        max_cluster_tx_count: Default::default(),
    };
    let mut mempool =
        setup_with_chainstate_generic(tf.chainstate(), mempool_config, Default::default());

    assert_eq!(
        mempool.add_transaction_test(tx),
        Err(MempoolPolicyError::TxSizeExceedsMaxClusterSize {
            tx_size,
            limit: max_cluster_size
        }
        .into())
    );
    mempool.store.assert_valid();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tx_mempool_entry() -> anyhow::Result<()> {
    use common::primitives::time;
    let mut mempool = setup();
    // Input different flag values just to make the hashes of these dummy transactions
    // different
    let txs = (1..=6)
        .map(|i| {
            SignedTransaction::new(
                Transaction::new(i, vec![], vec![]).unwrap_or_else(|_| panic!("tx {i}")),
                vec![],
            )
            .expect("invalid witness count")
        })
        .collect::<Vec<_>>();
    let fee = Amount::from_atoms(1).into();

    // Generation 1
    let tx1_parents = StoreHashSet::default();
    let entry_1_ancestors = BTreeSet::default();
    let entry1 = TxMempoolEntry::new_from_data(
        txs.first().unwrap().clone(),
        fee,
        tx1_parents,
        entry_1_ancestors,
        time::get_time(),
    )
    .unwrap();
    let tx2_parents = StoreHashSet::default();
    let entry_2_ancestors = BTreeSet::default();
    let entry2 = TxMempoolEntry::new_from_data(
        txs.get(1).unwrap().clone(),
        fee,
        tx2_parents,
        entry_2_ancestors,
        time::get_time(),
    )
    .unwrap();

    // Generation 2
    let tx3_parents = vec![*entry1.tx_id(), *entry2.tx_id()].into_iter().collect();
    let tx3_ancestors = vec![entry1.clone(), entry2.clone()].into_iter().collect();
    let entry3 = TxMempoolEntry::new_from_data(
        txs.get(2).unwrap().clone(),
        fee,
        tx3_parents,
        tx3_ancestors,
        time::get_time(),
    )
    .unwrap();

    // Generation 3
    let tx4_parents = vec![*entry3.tx_id()].into_iter().collect();
    let tx4_ancestors = vec![entry1.clone(), entry2.clone(), entry3.clone()].into_iter().collect();
    let tx5_parents = vec![*entry3.tx_id()].into_iter().collect();
    let tx5_ancestors = vec![entry1.clone(), entry2.clone(), entry3.clone()].into_iter().collect();
    let entry4 = TxMempoolEntry::new_from_data(
        txs.get(3).unwrap().clone(),
        fee,
        tx4_parents,
        tx4_ancestors,
        time::get_time(),
    )
    .unwrap();
    let entry5 = TxMempoolEntry::new_from_data(
        txs.get(4).unwrap().clone(),
        fee,
        tx5_parents,
        tx5_ancestors,
        time::get_time(),
    )
    .unwrap();

    // Generation 4
    let tx6_parents = vec![*entry3.tx_id(), *entry4.tx_id(), *entry5.tx_id()].into_iter().collect();
    let tx6_ancestors =
        vec![entry1.clone(), entry2.clone(), entry3.clone(), entry4.clone(), entry5.clone()]
            .into_iter()
            .collect();
    let entry6 = TxMempoolEntry::new_from_data(
        txs.get(5).unwrap().clone(),
        fee,
        tx6_parents,
        tx6_ancestors,
        time::get_time(),
    )
    .unwrap();

    let entries = vec![entry1, entry2, entry3, entry4, entry5, entry6];
    let ids = entries.iter().map(|entry| *entry.tx_id()).collect::<Vec<_>>();

    for entry in entries.into_iter() {
        let entry_with_ancestors =
            TxMempoolEntryWithAncestors::new_from_existing_entry(&mempool.store, entry);
        mempool.store.add_tx_entry(entry_with_ancestors)?;
    }

    #[allow(clippy::get_first)]
    let entry1 = mempool.store.get_entry(ids.get(0).expect("index")).expect("entry");
    let entry2 = mempool.store.get_entry(ids.get(1).expect("index")).expect("entry");
    let entry3 = mempool.store.get_entry(ids.get(2).expect("index")).expect("entry");
    let entry4 = mempool.store.get_entry(ids.get(3).expect("index")).expect("entry");
    let entry5 = mempool.store.get_entry(ids.get(4).expect("index")).expect("entry");
    let entry6 = mempool.store.get_entry(ids.get(5).expect("index")).expect("entry");
    assert_eq!(entry1.collect_ancestors(&mempool.store).len(), 0);
    assert_eq!(entry2.collect_ancestors(&mempool.store).len(), 0);
    assert_eq!(entry3.collect_ancestors(&mempool.store).len(), 2);
    assert_eq!(entry4.collect_ancestors(&mempool.store).len(), 3);
    assert_eq!(entry5.collect_ancestors(&mempool.store).len(), 3);
    assert_eq!(entry6.collect_ancestors(&mempool.store).len(), 5);

    assert_eq!(entry1.fees_with_ancestors(), Amount::from_atoms(1).into());
    assert_eq!(entry2.fees_with_ancestors(), Amount::from_atoms(1).into());
    assert_eq!(entry3.fees_with_ancestors(), Amount::from_atoms(3).into());
    assert_eq!(entry4.fees_with_ancestors(), Amount::from_atoms(4).into());
    assert_eq!(entry5.fees_with_ancestors(), Amount::from_atoms(4).into());
    assert_eq!(entry6.fees_with_ancestors(), Amount::from_atoms(6).into());

    assert_eq!(entry1.count_with_descendants(), 5);
    assert_eq!(entry2.count_with_descendants(), 5);
    assert_eq!(entry3.count_with_descendants(), 4);
    assert_eq!(entry4.count_with_descendants(), 2);
    assert_eq!(entry5.count_with_descendants(), 2);
    assert_eq!(entry6.count_with_descendants(), 1);

    assert_eq!(entry1.fees_with_descendants(), Amount::from_atoms(5).into());
    assert_eq!(entry2.fees_with_descendants(), Amount::from_atoms(5).into());
    assert_eq!(entry3.fees_with_descendants(), Amount::from_atoms(4).into());
    assert_eq!(entry4.fees_with_descendants(), Amount::from_atoms(2).into());
    assert_eq!(entry5.fees_with_descendants(), Amount::from_atoms(2).into());
    assert_eq!(entry6.fees_with_descendants(), Amount::from_atoms(1).into());

    Ok(())
}

async fn test_bip125_max_replacements(
    seed: Seed,
    num_potential_replacements: usize,
) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();
    let mut tx_builder = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
            empty_witness(&mut rng),
        )
        .with_flags(1);

    for _ in 0..(num_potential_replacements - 1) {
        tx_builder = tx_builder.add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(999_999_999_000_000_000)),
            anyonecanspend_address(),
        ));
    }

    let tx = tx_builder.build();
    let mut mempool = setup_with_chainstate(tf.chainstate());
    let input = tx.transaction().inputs().first().expect("one input").clone();
    let outputs = tx.transaction().outputs().to_owned();
    let tx_id = tx.transaction().get_id();
    mempool.add_transaction_test(tx)?.assert_in_mempool();

    let flags = 0;
    let outpoint_source_id = OutPointSourceId::Transaction(tx_id);
    let fee = 2_000;
    for (index, _) in outputs.iter().enumerate() {
        let input = TxInput::from_utxo(outpoint_source_id.clone(), index.try_into().unwrap());
        let tx = tx_spend_input(
            &mempool,
            input,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
            Fee::new(Amount::from_atoms(fee)),
            flags,
        )
        .await?;
        mempool.add_transaction_test(tx)?.assert_in_mempool();
    }
    let mempool_size_before_replacement = mempool.store.txs_by_id.len();

    let replacement_fee = (Amount::from_atoms(1_000_000_000_000_000) * fee).map(Fee::from);
    let replacement_tx = tx_spend_input(
        &mempool,
        input,
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        replacement_fee,
        flags,
    )
    .await?;
    mempool.add_transaction_test(replacement_tx)?.assert_in_mempool();
    let mempool_size_after_replacement = mempool.store.txs_by_id.len();

    assert_eq!(
        mempool_size_after_replacement,
        mempool_size_before_replacement - num_potential_replacements + 1
    );
    Ok(())
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "RBF not implemented"]
async fn too_many_conflicts(#[case] seed: Seed) -> anyhow::Result<()> {
    let num_potential_replacements = MAX_BIP125_REPLACEMENT_CANDIDATES + 1;
    let err: Error = test_bip125_max_replacements(seed, num_potential_replacements)
        .await
        .expect_err("expected error TooManyPotentialReplacements")
        .downcast()
        .expect("failed to downcast");
    assert_eq!(
        err,
        MempoolPolicyError::from(MempoolConflictError::TooManyReplacements).into(),
    );
    Ok(())
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "RBF not implemented"]
async fn not_too_many_conflicts(#[case] seed: Seed) -> anyhow::Result<()> {
    let num_potential_replacements = MAX_BIP125_REPLACEMENT_CANDIDATES;
    test_bip125_max_replacements(seed, num_potential_replacements).await
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rolling_fee(#[case] seed: Seed) -> anyhow::Result<()> {
    let mock_time = Arc::new(SeqCstAtomicU64::new(0));
    let mock_clock = mocked_time_getter_seconds(Arc::clone(&mock_time));
    let mut mock_usage = MockMemoryUsageEstimator::new();
    // Add parent
    // Add first child
    mock_usage.expect_estimate_memory_usage().times(2).return_const(0usize);
    // Add second child, triggering the trimming process
    mock_usage
        .expect_estimate_memory_usage()
        .times(1)
        .return_const(MAX_MEMPOOL_SIZE_BYTES + 1);
    // After removing one entry, cause the code to exit the loop by showing a small usage
    mock_usage.expect_estimate_memory_usage().return_const(0usize);

    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();
    let mut tx_builder = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
            empty_witness(&mut rng),
        )
        .with_flags(1);

    let num_outputs = 3;
    for _ in 0..num_outputs {
        tx_builder = tx_builder.add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(999_999_999_000)),
            anyonecanspend_address(),
        ));
    }
    let parent = tx_builder.build();
    let parent_id = parent.transaction().get_id();

    let chainstate = tf.chainstate();
    let chain_config = Arc::clone(chainstate.get_chain_config());
    let chainstate_interface = start_chainstate(chainstate);

    let num_inputs = 1;

    // Use a higher than default fee because we don't want this transaction to be evicted during
    // the trimming process
    log::debug!("parent_id: {}", parent_id.to_hash());
    log::debug!("before adding parent");
    let mut tx_pool = TxPool::new(
        Arc::clone(&chain_config),
        create_mempool_config(),
        chainstate_interface,
        mock_clock,
        mock_usage,
    );
    tx_pool.add_transaction_test(parent.clone())?.assert_in_mempool();
    log::debug!("after adding parent");

    let flags = 0;
    let outpoint_source_id = OutPointSourceId::Transaction(parent_id);

    // child_0 has the lower fee so it will be evicted when memory usage is too high
    let child_0 = tx_spend_input(
        &tx_pool,
        TxInput::from_utxo(outpoint_source_id.clone(), 0),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        None,
        flags,
    )
    .await?;
    let child_0_id = child_0.transaction().get_id();
    log::debug!("child_0_id {}", child_0_id.to_hash());

    let big_fee: Fee = (get_relay_fee_from_tx_size(estimate_tx_size(num_inputs, num_outputs))
        + Amount::from_atoms(100))
    .unwrap()
    .into();
    let child_1 = tx_spend_input(
        &tx_pool,
        TxInput::from_utxo(outpoint_source_id.clone(), 1),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        big_fee,
        flags,
    )
    .await?;
    let child_1_id = child_1.transaction().get_id();
    log::debug!("child_1_id {}", child_1_id.to_hash());
    tx_pool.add_transaction_test(child_0.clone())?.assert_in_mempool();
    log::debug!("added child_0");
    tx_pool.add_transaction_test(child_1)?.assert_in_mempool();
    log::debug!("added child_1");

    assert_eq!(tx_pool.store.txs_by_id.len(), 2);
    assert!(tx_pool.contains_transaction(&child_1_id));
    assert!(!tx_pool.contains_transaction(&child_0_id));
    let rolling_fee = tx_pool.get_minimum_rolling_fee();
    let child_0_fee = try_get_fee(&tx_pool, &child_0).await;
    log::debug!("FeeRate of child_0 {:?}", child_0_fee);
    assert_eq!(
        rolling_fee,
        (INCREMENTAL_RELAY_FEE_RATE
            + FeeRate::from_total_tx_fee(
                child_0_fee,
                NonZeroUsize::new(child_0.encoded_size()).unwrap()
            )?)
        .unwrap()
    );
    assert_eq!(
        rolling_fee,
        FeeRate::from_amount_per_kb(Amount::from_atoms(3629))
    );
    log::debug!(
        "minimum rolling fee after child_0's eviction {:?}",
        rolling_fee
    );
    assert_eq!(
        rolling_fee,
        (FeeRate::from_total_tx_fee(
            try_get_fee(&tx_pool, &child_0).await,
            NonZeroUsize::new(child_0.encoded_size()).unwrap()
        )? + INCREMENTAL_RELAY_FEE_RATE)
            .unwrap()
    );

    // Now that the minimum rolling fee has been bumped up, a low-fee tx will not pass
    // validation
    let child_2 = tx_spend_input(
        &tx_pool,
        TxInput::from_utxo(outpoint_source_id.clone(), 2),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        None,
        flags,
    )
    .await?;
    log::debug!(
        "before child2: fee = {:?}, size = {}, minimum fee rate = {:?}",
        try_get_fee(&tx_pool, &child_2).await,
        child_2.encoded_size(),
        tx_pool.get_minimum_rolling_fee()
    );
    let res = tx_pool.add_transaction_test(child_2);
    log::debug!("result of adding child2 {:?}", res);
    assert!(matches!(
        res,
        Err(Error::Policy(
            MempoolPolicyError::RollingFeeThresholdNotMet { .. }
        ))
    ));

    // We provide a sufficient fee for the tx to pass the minimum rolling fee requirement
    let child_2_high_fee = tx_spend_input(
        &tx_pool,
        TxInput::from_utxo(outpoint_source_id, 2),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        tx_pool.get_minimum_rolling_fee().compute_fee(estimate_tx_size(1, 1)).unwrap(),
        flags,
    )
    .await?;
    let child_2_high_fee_id = child_2_high_fee.transaction().get_id();
    let child_2_high_fee_outpt =
        UtxoOutPoint::new(OutPointSourceId::Transaction(child_2_high_fee_id), 0);
    log::debug!("before child2_high_fee");
    tx_pool.add_transaction_test(child_2_high_fee.clone())?.assert_in_mempool();

    assert!(tx_pool.contains_transaction(&child_2_high_fee_id));
    assert!(
        tx_pool
            .chainstate_handle()
            .call({
                let outpt = child_2_high_fee_outpt.clone();
                move |c| c.utxo(&outpt).unwrap().is_none()
            })
            .await
            .unwrap()
    );

    // TODO The commented out part only applies if RBF is active

    // We simulate a block being accepted so the rolling fee will begin to decay
    let block = Block::new(
        vec![parent, child_2_high_fee],
        genesis.get_id().into(),
        BlockTimestamp::from_int_seconds(1639975461),
        ConsensusData::None,
        BlockReward::new(vec![]),
    )
    .map_err(|_| anyhow::Error::msg("block creation error"))?;
    let block_id = block.get_id();

    tx_pool
        .chainstate_handle
        .call_mut(|this| this.process_block(block, BlockSource::Local))
        .await??;
    tx_pool.on_new_tip(block_id, BlockHeight::new(1)).unwrap();

    assert!(!tx_pool.contains_transaction(&child_2_high_fee_id));
    assert!(
        tx_pool
            .chainstate_handle()
            .call(move |c| c.utxo(&child_2_high_fee_outpt).unwrap().is_some())
            .await
            .unwrap()
    );

    // Because the rolling fee is only updated when we attempt to add a tx to the mempool we need
    // to submit a "dummy" tx to trigger these updates.

    // Since memory usage is now zero, it is less than 1/4 of the max size
    // and ROLLING_FEE_BASE_HALFLIFE / 4 is the time it will take for the fee to halve
    // We are going to submit dummy txs to the mempool incrementing time by this halflife
    // between txs. Finally, when the fee rate falls under INCREMENTAL_RELAY_THRESHOLD, we
    // observer that it is set to zero
    let halflife = ROLLING_FEE_BASE_HALFLIFE / 4;
    mock_time.store(mock_time.load() + halflife.as_secs());
    let dummy_tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(child_2_high_fee_id), 0),
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(499999999105 - 84)),
            Destination::AnyoneCanSpend,
        ))
        .build();
    log::debug!(
        "First attempt to add dummy which pays a fee of {:?}",
        try_get_fee(&tx_pool, &dummy_tx).await
    );
    let res = tx_pool.add_transaction_test(dummy_tx.clone());

    log::debug!("Result of first attempt to add dummy: {res:?}");
    assert!(matches!(
        res,
        Err(Error::Policy(
            MempoolPolicyError::RollingFeeThresholdNotMet { .. }
        )),
    ));
    log::debug!(
        "minimum rolling fee after first attempt to add dummy: {:?}",
        tx_pool.get_minimum_rolling_fee()
    );
    assert_eq!(
        tx_pool.get_minimum_rolling_fee(),
        rolling_fee / NonZeroUsize::new(2).expect("nonzero")
    );

    mock_time.store(mock_time.load() + halflife.as_secs());
    log::debug!("Second attempt to add dummy");
    tx_pool.add_transaction_test(dummy_tx)?.assert_in_mempool();
    log::debug!(
        "minimum rolling fee after first second to add dummy: {:?}",
        tx_pool.get_minimum_rolling_fee()
    );
    assert_eq!(
        tx_pool.get_minimum_rolling_fee(),
        rolling_fee / NonZeroUsize::new(4).expect("nonzero")
    );
    log::debug!(
        "After successful addition of dummy, rolling fee rate is {:?}",
        tx_pool.get_minimum_rolling_fee()
    );

    // Add another dummy until rolling feerate drops to zero
    mock_time.store(mock_time.load() + halflife.as_secs());

    let another_dummy = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(child_1_id), 0),
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(499999999105 - 77)),
            Destination::AnyoneCanSpend,
        ))
        .build();

    tx_pool.add_transaction_test(another_dummy)?.assert_in_mempool();
    assert_eq!(
        tx_pool.get_minimum_rolling_fee(),
        FeeRate::from_amount_per_kb(Amount::from_atoms(0))
    );

    tx_pool.store.assert_valid();
    Ok(())
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn different_size_txs(#[case] seed: Seed) -> anyhow::Result<()> {
    use std::time::Instant;

    let mut rng = make_seedable_rng(seed);
    let mut tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();

    let mut tx_builder = TransactionBuilder::new().add_input(
        TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
        empty_witness(&mut rng),
    );
    for _ in 0..10_000 {
        tx_builder = tx_builder.add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1_000)),
            Destination::AnyoneCanSpend,
        ))
    }
    let initial_tx = tx_builder.build();
    let block = tf.make_block_builder().add_transaction(initial_tx.clone()).build(&mut rng);
    tf.process_block(block, BlockSource::Local).expect("process_block");
    let chainstate = tf.chainstate();
    let mut mempool = setup_with_chainstate(chainstate);

    let target_txs = 10;
    for i in 0..target_txs {
        let tx_i_start = Instant::now();
        let num_inputs = 10 * (i + 1);
        let num_outputs = 10 * (i + 1);
        let mut tx_builder = TransactionBuilder::new();
        for j in 0..num_inputs {
            tx_builder = tx_builder.add_input(
                TxInput::from_utxo(
                    OutPointSourceId::Transaction(initial_tx.transaction().get_id()),
                    100 * i + j,
                ),
                empty_witness(&mut rng),
            );
        }
        log::debug!(
            "time spent building inputs of tx {} {:?}",
            i,
            tx_i_start.elapsed()
        );

        let before_outputs = Instant::now();
        for _ in 0..num_outputs {
            tx_builder = tx_builder.add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(100)),
                Destination::AnyoneCanSpend,
            ))
        }
        log::debug!(
            "time spent building outputs of tx {} {:?}",
            i,
            before_outputs.elapsed()
        );
        let tx = tx_builder.build();
        let before_adding_tx_i = Instant::now();
        mempool.add_transaction_test(tx)?.assert_in_mempool();
        log::debug!(
            "time spent adding tx {}: {:?}",
            i,
            before_adding_tx_i.elapsed()
        );
        log::debug!("Added tx {}", i);
    }

    mempool.store.assert_valid();
    Ok(())
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ancestor_score(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();

    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(10_000)),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(10_000)),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_id = tx.transaction().get_id();

    let mut mempool = setup_with_chainstate(tf.chainstate());
    mempool.add_transaction_test(tx)?.assert_in_mempool();

    let outpoint_source_id = OutPointSourceId::Transaction(tx_id);

    let flags = 0;

    let tx_b_fee: Fee = get_relay_fee_from_tx_size(estimate_tx_size(1, 2)).into();
    let tx_a_fee: Fee = (tx_b_fee + Amount::from_atoms(1000).into()).unwrap();
    let tx_c_fee: Fee = (tx_a_fee + Amount::from_atoms(1000).into()).unwrap();
    let tx_a = tx_spend_input(
        &mempool,
        TxInput::from_utxo(outpoint_source_id.clone(), 0),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        tx_a_fee,
        flags,
    )
    .await?;
    let tx_a_id = tx_a.transaction().get_id();
    log::debug!("tx id is: {}", tx_id);
    log::debug!("tx_a_id : {}", tx_a_id.to_hash());
    log::debug!("tx_a fee : {:?}", try_get_fee(&mempool, &tx_a).await);
    mempool.add_transaction_test(tx_a)?.assert_in_mempool();

    let tx_b = tx_spend_input(
        &mempool,
        TxInput::from_utxo(outpoint_source_id, 1),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        tx_b_fee,
        flags,
    )
    .await?;
    let tx_b_id = tx_b.transaction().get_id();
    log::debug!("tx_b_id : {}", tx_b_id.to_hash());
    log::debug!("tx_b fee : {:?}", try_get_fee(&mempool, &tx_b).await);
    mempool.add_transaction_test(tx_b)?.assert_in_mempool();

    let tx_c = tx_spend_input(
        &mempool,
        TxInput::from_utxo(OutPointSourceId::Transaction(tx_b_id), 0),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        tx_c_fee,
        flags,
    )
    .await?;
    let tx_c_id = tx_c.transaction().get_id();
    log::debug!("tx_c_id : {}", tx_c_id.to_hash());
    log::debug!("tx_c fee : {:?}", try_get_fee(&mempool, &tx_c).await);
    mempool.add_transaction_test(tx_c)?.assert_in_mempool();

    let entry_tx = mempool.store.txs_by_id.get(&tx_id).expect("tx");
    let entry_tx_id = *entry_tx.tx_id();
    log::debug!(
        "at first, entry tx has score {:?}",
        entry_tx.ancestor_score()
    );
    let entry_a = mempool.store.txs_by_id.get(&tx_a_id).expect("tx_a").deref().clone();
    log::debug!("AT FIRST, entry a has score {:?}", entry_a.ancestor_score());
    let entry_b = mempool.store.txs_by_id.get(&tx_b_id).expect("tx_b").deref();
    log::debug!("AT FIRST, entry b has score {:?}", entry_b.ancestor_score());
    let entry_c = mempool.store.txs_by_id.get(&tx_c_id).expect("tx_c").deref().clone();
    log::debug!(
        "AT FIRST, entry c looks like {:?} and has score {:?}",
        entry_c,
        entry_c.ancestor_score()
    );
    assert_eq!(
        entry_a.fees_with_ancestors(),
        (entry_a.fee() + entry_tx.fee()).unwrap()
    );
    assert_eq!(
        entry_b.fees_with_ancestors(),
        (entry_b.fee() + entry_tx.fee()).unwrap()
    );
    log::debug!(
        "BEFORE REMOVAL raw txs_by_ancestor_score {:?}",
        mempool.store.txs_by_ancestor_score
    );
    check_txs_sorted_by_ancestor_score(&mempool);

    mempool.store.remove_tx(&entry_tx_id, MempoolRemovalReason::Block);
    log::debug!(
        "AFTER REMOVAL raw txs_by_ancestor_score {:?}",
        mempool.store.txs_by_ancestor_score
    );
    let entry_a = mempool.store.txs_by_id.get(&tx_a_id).expect("tx_a");
    log::debug!(
        "AFTER removing tx, entry a has score {:?}",
        entry_a.ancestor_score()
    );
    let entry_b = mempool.store.txs_by_id.get(&tx_b_id).expect("tx_b");
    log::debug!(
        "AFTER removing tx, entry b has score {:?}",
        entry_b.ancestor_score()
    );
    let entry_c = mempool.store.txs_by_id.get(&tx_c_id).expect("tx_b");
    log::debug!(
        "AFTER removing tx, entry c looks like {:?} and has score {:?}",
        entry_c,
        entry_c.ancestor_score()
    );

    check_txs_sorted_by_ancestor_score(&mempool);
    mempool.store.assert_valid();

    Ok(())
}

fn check_txs_sorted_by_ancestor_score<E>(tx_pool: &TxPool<E>) {
    let txs_by_ancestor_score = tx_pool
        .store
        .txs_by_descendant_score
        .iter()
        .map(|(_score, id)| id)
        .collect::<Vec<_>>();
    for i in 0..(txs_by_ancestor_score.len() - 1) {
        log::debug!("i =  {}", i);
        let tx_id = txs_by_ancestor_score.get(i).unwrap();
        let next_tx_id = txs_by_ancestor_score.get(i + 1).unwrap();
        let entry_score = tx_pool.store.txs_by_id.get(*tx_id).unwrap().descendant_score();
        let next_entry_score = tx_pool.store.txs_by_id.get(*next_tx_id).unwrap().descendant_score();
        log::debug!("entry_score: {:?}", entry_score);
        log::debug!("next_entry_score: {:?}", next_entry_score);
        assert!(entry_score <= next_entry_score)
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn descendant_score(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();

    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(10_000)),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(10_000)),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_id = tx.transaction().get_id();

    let mut mempool = setup_with_chainstate(tf.chainstate());
    mempool.add_transaction_test(tx)?.assert_in_mempool();

    let outpoint_source_id = OutPointSourceId::Transaction(tx_id);

    let flags = 0;

    let tx_b_fee: Fee = get_relay_fee_from_tx_size(estimate_tx_size(1, 2)).into();
    let tx_a_fee = (tx_b_fee + Amount::from_atoms(1000).into()).unwrap();
    let tx_c_fee = (tx_a_fee + Amount::from_atoms(1000).into()).unwrap();
    let tx_a = tx_spend_input(
        &mempool,
        TxInput::from_utxo(outpoint_source_id.clone(), 0),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        tx_a_fee,
        flags,
    )
    .await?;
    let tx_a_id = tx_a.transaction().get_id();
    log::debug!("tx_a_id : {}", tx_a_id.to_hash());
    log::debug!("tx_a fee : {:?}", try_get_fee(&mempool, &tx_a).await);
    mempool.add_transaction_test(tx_a)?.assert_in_mempool();

    let tx_b = tx_spend_input(
        &mempool,
        TxInput::from_utxo(outpoint_source_id, 1),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        tx_b_fee,
        flags,
    )
    .await?;
    let tx_b_id = tx_b.transaction().get_id();
    log::debug!("tx_b_id : {}", tx_b_id.to_hash());
    log::debug!("tx_b fee : {:?}", try_get_fee(&mempool, &tx_b).await);
    mempool.add_transaction_test(tx_b)?.assert_in_mempool();

    let tx_c = tx_spend_input(
        &mempool,
        TxInput::from_utxo(OutPointSourceId::Transaction(tx_b_id), 0),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        tx_c_fee,
        flags,
    )
    .await?;
    let tx_c_id = tx_c.transaction().get_id();
    log::debug!("tx_c_id : {}", tx_c_id.to_hash());
    log::debug!("tx_c fee : {:?}", try_get_fee(&mempool, &tx_c).await);
    mempool.add_transaction_test(tx_c)?.assert_in_mempool();

    let entry_a = mempool.store.txs_by_id.get(&tx_a_id).expect("tx_a");
    log::debug!("entry a has score {:?}", entry_a.descendant_score());
    let entry_b = mempool.store.txs_by_id.get(&tx_b_id).expect("tx_b");
    log::debug!("entry b has score {:?}", entry_b.descendant_score());
    let entry_c = mempool.store.txs_by_id.get(&tx_c_id).expect("tx_c").deref().clone();
    log::debug!("entry c has score {:?}", entry_c.descendant_score());
    assert_eq!(entry_a.fee(), entry_a.fees_with_descendants());
    assert_eq!(
        entry_b.fees_with_descendants(),
        (entry_b.fee() + entry_c.fee()).unwrap()
    );
    log::debug!(
        "raw_txs_by_descendant_score {:?}",
        mempool.store.txs_by_descendant_score
    );
    check_txs_sorted_by_descendant_sore(&mempool);

    mempool.store.remove_tx(entry_c.tx_id(), MempoolRemovalReason::Block);
    let entry_b = mempool.store.txs_by_id.get(&tx_b_id).expect("tx_b");
    assert_eq!(entry_b.fees_with_descendants(), entry_b.fee());

    check_txs_sorted_by_descendant_sore(&mempool);
    mempool.store.assert_valid();

    Ok(())
}

fn check_txs_sorted_by_descendant_sore<M>(tx_pool: &TxPool<M>) {
    let txs_by_descendant_score = tx_pool
        .store
        .txs_by_descendant_score
        .iter()
        .map(|(_score, id)| id)
        .collect::<Vec<_>>();
    for i in 0..(txs_by_descendant_score.len() - 1) {
        log::debug!("i =  {}", i);
        let tx_id = txs_by_descendant_score.get(i).unwrap();
        let next_tx_id = txs_by_descendant_score.get(i + 1).unwrap();
        let entry_score = tx_pool.store.txs_by_id.get(*tx_id).unwrap().descendant_score();
        let next_entry_score = tx_pool.store.txs_by_id.get(*next_tx_id).unwrap().descendant_score();
        log::debug!("entry_score: {:?}", entry_score);
        log::debug!("next_entry_score: {:?}", next_entry_score);
        assert!(entry_score <= next_entry_score)
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mempool_full_mock(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();

    let mut mock_usage = MockMemoryUsageEstimator::new();
    mock_usage
        .expect_estimate_memory_usage()
        .times(1)
        .return_const(MAX_MEMPOOL_SIZE_BYTES + 1);

    let chainstate = tf.chainstate();
    let chain_config = Arc::clone(chainstate.get_chain_config());
    let chainstate_handle = start_chainstate(chainstate);

    let mut tx_pool = TxPool::new(
        chain_config,
        create_mempool_config(),
        chainstate_handle,
        Default::default(),
        mock_usage,
    );

    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(100)),
            Destination::AnyoneCanSpend,
        ))
        .build();
    log::debug!(
        "mempool_full: tx has id {}",
        tx.transaction().get_id().to_hash()
    );
    let res = tx_pool.add_transaction_test(tx);
    assert_eq!(res, Err(MempoolPolicyError::MempoolFull.into()));
    tx_pool.store.assert_valid();
    Ok(())
}

#[rstest]
#[case(Seed::from_entropy())]
#[trace]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mempool_full_real(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let num_txs = rng.random_range(5..20);
    let time = TimeGetter::default().get_time();
    let txs: Vec<_> = generate_transaction_graph(&mut rng, time).take(num_txs).collect();

    let encoded_size: usize = txs.iter().map(|tx| tx.transaction().encoded_size()).sum();

    // Get total memory size without memory limit
    let memory_size = {
        let mut storage = MempoolStore::new(Default::default());
        for entry in &txs {
            storage.add_transaction(entry.clone()).expect("tx insertion to succeed");
            log::trace!("Storage mem usage updated: {}", storage.memory_usage());
        }

        // Dump some stats. Useful for rough insights into the overhead taken up by mempool
        // metadata compared to "raw" encoded transaction size.
        log::debug!(
            "STATS: {} txs, {} ins, {} outs, {}B encoded, {}B mem consumption",
            num_txs,
            txs.iter().map(|tx| tx.transaction().inputs().len()).sum::<usize>(),
            txs.iter().map(|tx| tx.transaction().outputs().len()).sum::<usize>(),
            encoded_size,
            storage.memory_usage(),
        );

        storage.memory_usage()
    };

    assert!(memory_size >= encoded_size);

    // Set up mempool such that exactly one of the transactions does not fit
    let tf = TestFramework::builder(&mut rng).build();
    let mut mempool = setup_with_chainstate(tf.chainstate());
    mempool.max_size = MempoolMaxSize::from_bytes(memory_size - 1);

    // Attempt to add all the transactions but one
    let (last_tx, initial_txs) = txs.split_last().unwrap();
    for tx in initial_txs {
        mempool.add_transaction_bare(tx.tx_entry().clone()).unwrap().assert_in_mempool();
        log::trace!("Mempool mem usage updated: {}", mempool.memory_usage());
    }
    assert_eq!(mempool.store.txs_by_id.len(), num_txs - 1);

    // Add the last transaction, check the memory limit kicked in and the total number of
    // transactions has not increased.
    let _ = mempool.add_transaction_bare(last_tx.tx_entry().clone());
    assert!(mempool.store.txs_by_id.len() < num_txs);

    // Bump the memory limit again, and re-insert the evicted transaction(s). Also reset the
    // rolling fee since recently evicted transactions bump it up.
    // Note: since the switch to using hashbrown tables in the mempool store, simply resetting
    // `mempool.max_size` back to `memory_size` may not be enough for the previously evicted
    // txs to fit back in. This is because hashbrown tables are probing tables that leave tombstones
    // during element removal and tombstones may not always be reused during insertion. In such a
    // case insertion will eat up one additional capacity element, and if the capacity is already at
    // the maximum, reallocation will occur, doubling the number of buckets, which will contribute
    // to the current mempool size and will cause some of the previously fitting txs to be evicted.
    mempool.max_size = MempoolMaxSize::from_bytes(memory_size * 2);
    mempool.drop_rolling_fee();

    for tx in txs {
        if mempool.contains_transaction(tx.tx_id()) {
            continue;
        }
        mempool.add_transaction_bare(tx.into_tx_entry()).unwrap().assert_in_mempool();
    }

    assert_eq!(mempool.store.txs_by_id.len(), num_txs, "Some txs missing");
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_empty_bags_in_indices(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();
    let mut tx_builder = TransactionBuilder::new().add_input(
        TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
        empty_witness(&mut rng),
    );

    let num_outputs = 100;
    for _ in 0..num_outputs {
        tx_builder = tx_builder.add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(2_000)),
            anyonecanspend_address(),
        ));
    }
    let parent = tx_builder.build();
    let num_child_txs = num_outputs;

    let mempool_config = MempoolConfig {
        min_tx_relay_fee_rate: TEST_MIN_TX_RELAY_FEE_RATE.into(),
        // Make sure we don't hit the max cluster tx count limit.
        max_cluster_tx_count: (num_child_txs + 1).into(),
        max_cluster_size_bytes: Default::default(),
    };
    let mut mempool =
        setup_with_chainstate_generic(tf.chainstate(), mempool_config, Default::default());

    let parent_id = parent.transaction().get_id();

    let outpoint_source_id = OutPointSourceId::Transaction(parent.transaction().get_id());
    mempool.add_transaction_test(parent)?.assert_in_mempool();

    let flags = 0;
    let fee = get_relay_fee_from_tx_size(estimate_tx_size(1, num_outputs));
    let mut txs = Vec::new();
    for i in 0..num_child_txs {
        txs.push(
            tx_spend_input(
                &mempool,
                TxInput::from_utxo(outpoint_source_id.clone(), u32::try_from(i).unwrap()),
                empty_witness(&mut rng),
                Fee::new((fee + Amount::from_atoms(i as u128)).unwrap()),
                flags,
            )
            .await?,
        )
    }
    let ids = txs.iter().map(|tx| tx.transaction().get_id()).collect::<Vec<_>>();

    for tx in txs {
        mempool.add_transaction_test(tx)?.assert_in_mempool();
    }

    mempool.store.remove_tx(&parent_id, MempoolRemovalReason::Block);
    for id in ids {
        mempool.store.remove_tx(&id, MempoolRemovalReason::Block);
    }
    assert!(mempool.store.txs_by_descendant_score.is_empty());
    assert!(mempool.store.txs_by_creation_time.is_empty());
    mempool.store.assert_valid();
    Ok(())
}

// If use_cluster_size_limit is false, the max cluster size will be set to some artificially large
// value, so the test tx size values will be checked against `ChainConfig::max_tx_size_for_mempool`.
// Otherwise, `ChainConfig::max_tx_size_for_mempool` will be set to some artificially large value
// and the max cluster size will be set to the default value of `ChainConfig::max_tx_size_for_mempool`,
// so the test tx size values will be checked against the max cluster size.
#[rstest]
#[case(Seed::from_entropy(), 300, true)]
#[case(Seed::from_entropy(), 1_000, true)]
#[case(Seed::from_entropy(), 10_000, true)]
#[case(Seed::from_entropy(), 100_000, true)]
#[case(Seed::from_entropy(), 900_000, true)]
#[case(Seed::from_entropy(), 1_000_000, true)]
#[case::one_below(Seed::from_entropy(), 1_047_576, true)]
#[case::at_limit(Seed::from_entropy(), 1_047_576, true)]
#[case::just_above(Seed::from_entropy(), 1_047_577, false)]
#[case::one_below_block_limit(Seed::from_entropy(), 1_048_575, false)]
#[case::at_block_limit(Seed::from_entropy(), 1_048_576, false)]
#[trace]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_tx_size(
    #[case] seed: Seed,
    #[case] tx_size: usize,
    #[case] accept: bool,
    #[values(false, true)] use_cluster_size_limit: bool,
) {
    let mut rng = make_seedable_rng(seed);

    let default_max_tx_size_from_blocks =
        chain::config::create_unit_test_config().max_tx_size_for_mempool();

    // Note: we can't modify `max_tx_size_for_mempool` directly, but its value depends on the "max_block_size_"
    // values, so we modify them instead.
    let large_limit = default_max_tx_size_from_blocks * 2;
    let (max_block_size_with_standard_txs, max_block_size_with_smart_contracts, max_cluster_size) =
        if use_cluster_size_limit {
            (
                Some(large_limit),
                Some(large_limit),
                default_max_tx_size_from_blocks,
            )
        } else {
            (None, None, large_limit)
        };

    let tf = {
        let mut chain_config_builder =
            chain::config::create_unit_test_config_builder().data_deposit_max_size(Some(2_000_000));

        if let Some(max_block_size_with_standard_txs) = max_block_size_with_standard_txs {
            chain_config_builder = chain_config_builder
                .max_block_size_with_standard_txs(max_block_size_with_standard_txs);
        }

        if let Some(max_block_size_with_smart_contracts) = max_block_size_with_smart_contracts {
            chain_config_builder = chain_config_builder
                .max_block_size_with_smart_contracts(max_block_size_with_smart_contracts);
        }

        TestFramework::builder(&mut rng)
            .with_chain_config(chain_config_builder.build())
            .build()
    };

    let transaction = {
        let genesis = tf.genesis();
        let tx_builder = TransactionBuilder::new().add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
            empty_witness(&mut rng),
        );

        // Here we try to calculate the size of data to add to the transaction output so that the
        // size of the full transaction matches the size required by the test.
        let data_size = tx_size - 147;
        let data_size = data_size - serialization::Compact::<u64>(data_size as u64).encoded_size();
        let data = (0..data_size).map(|_| rng.random()).collect();

        let tx_builder = tx_builder.add_output(TxOutput::DataDeposit(data));
        let transaction = tx_builder.build();

        // Check the transaction actually has the desired size. Failure of this assertion means the
        // calculation above has to be adjusted.
        assert_eq!(
            transaction.encoded_size(),
            tx_size,
            "Data size not calculated correctly to create a transaction of given size"
        );

        transaction
    };

    let mempool_config = MempoolConfig {
        min_tx_relay_fee_rate: TEST_MIN_TX_RELAY_FEE_RATE.into(),
        max_cluster_size_bytes: max_cluster_size.into(),

        max_cluster_tx_count: Default::default(),
    };
    let mut mempool =
        setup_with_chainstate_generic(tf.chainstate(), mempool_config, Default::default());
    let result = mempool.add_transaction_test(transaction);

    let expected_err = if use_cluster_size_limit {
        MempoolPolicyError::TxSizeExceedsMaxClusterSize {
            tx_size,
            limit: max_cluster_size,
        }
    } else {
        MempoolPolicyError::TxSizeExceedsMaxBlockSize
    };
    let expected = match accept {
        true => Ok(TxStatus::InMempool),
        false => Err(Error::Policy(expected_err)),
    };

    assert_eq!(
        result, expected,
        "tx_size: {tx_size}, max tx size: {default_max_tx_size_from_blocks}"
    );
}

// Check that values returned by `get_initial_fee_rate` and `get_initial_fee_rate_points` are
// the same that `get_fee_rate` and `get_fee_rate_points` return for a freshly constructed tx pool.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_values(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let tf = TestFramework::builder(&mut rng).build();

    let mempool_config = MempoolConfig {
        min_tx_relay_fee_rate: FeeRate::from_atoms_per_kb(
            rng.random_range(100_000..100_000_000_000_000),
        )
        .into(),
        max_cluster_tx_count: Default::default(),
        max_cluster_size_bytes: Default::default(),
    };
    let tx_pool =
        setup_with_chainstate_generic(tf.chainstate(), mempool_config.clone(), Default::default());

    let initial_fee_rate =
        TxPool::<StoreMemoryUsageEstimator>::get_initial_fee_rate(&mempool_config);
    let fee_rate = tx_pool.get_fee_rate(rng.random_range(1..100));
    assert_eq!(initial_fee_rate, fee_rate);

    let initial_fee_rate_points =
        TxPool::<StoreMemoryUsageEstimator>::get_initial_fee_rate_points(&mempool_config).unwrap();
    let fee_rate_points = tx_pool
        .get_fee_rate_points(NonZeroUsize::new(rng.random_range(1..100)).unwrap())
        .unwrap();
    assert_eq!(initial_fee_rate_points, fee_rate_points);
}

// Originally, when adding a transaction, a recursive function was used to collect its ancestors,
// which could potentially result in a stack overflow.
// Here we create a long chain of transactions and use a small stack size, the combination that
// would crash the original implementation. Two cases exist:
// a) The default cluster tx count limit is used; adding the tx that violates the limit should fail.
// b) A huge cluster tx count limit is used; all txs should be added successfully.
// In either case, the test shouldn't crash.
#[rstest]
#[case(Seed::from_entropy())]
#[trace]
fn stack_overflow_on_transaction_addition(
    #[case] seed: Seed,
    #[values(false, true)] unlimited_cluster_tx_count: bool,
) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        // Use a small stack - 256Kb. Note that the underlying OS may have a minimum stack size
        // (and different OSs have different minimums), so this value is not a guarantee and the
        // actual stack may be bigger, but it's unlikely that the minimum is more than 128Kb (but
        // we can't use 128Kb here because in debug builds it's not enough to even start the test).
        .thread_stack_size(256 * 1024)
        .enable_all()
        .build()
        .unwrap();

    let test_body = move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id();

        // With the original recursive implementation, about 900 txs were enough to crash the test
        // in debug builds and 2200 in release builds (with 256Kb of stack).
        // We use bigger values just in case, but not too big, because the test will become too slow
        // in the unlimited cluster size case.
        let chain_len: usize = if cfg!(debug_assertions) { 2000 } else { 5_000 };

        let mut amount = 1_000_000;
        let funding_tx = make_tx(
            &mut rng,
            &[(OutPointSourceId::BlockReward(genesis_id.into()), 0)],
            &[amount],
        );
        let funding_tx_id = funding_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(funding_tx)
            .build_and_process(&mut rng)
            .unwrap();

        let max_cluster_tx_count = if unlimited_cluster_tx_count {
            usize::MAX
        } else {
            *MaxClusterTxCount::default()
        };

        let mut mempool = setup_with_chainstate_generic(
            tf.chainstate(),
            MempoolConfig {
                min_tx_relay_fee_rate: FeeRate::from_amount_per_kb(Amount::ZERO).into(),
                max_cluster_size_bytes: usize::MAX.into(),
                max_cluster_tx_count: max_cluster_tx_count.into(),
            },
            Default::default(),
        );

        if unlimited_cluster_tx_count {
            // Disable heavy checks because this case is already pretty slow.
            mempool.disable_heavy_validity_checks();
        }

        let mut prev_source: OutPointSourceId = funding_tx_id.into();
        let mut tx_ids = BTreeSet::new();

        for i in 0..chain_len {
            let tx = make_tx(&mut rng, &[(prev_source, 0)], &[amount - 1]);
            amount -= 1;
            let tx_id = tx.transaction().get_id();
            prev_source = tx_id.into();

            let result = mempool.add_transaction_test(tx);

            if unlimited_cluster_tx_count || i < max_cluster_tx_count {
                assert_eq!(result, Ok(TxStatus::InMempool));
                tx_ids.insert(tx_id);
            } else {
                assert_eq!(
                    result,
                    Err(Error::Policy(
                        MempoolPolicyError::ClusterMaxTxCountLimitViolated {
                            limit: max_cluster_tx_count
                        }
                    ))
                );
                break;
            }
        }

        let actual_tx_ids = mempool
            .get_all()
            .iter()
            .map(|tx| tx.transaction().get_id())
            .collect::<BTreeSet<_>>();
        assert_eq!(actual_tx_ids, tx_ids);
    };

    runtime.block_on(async move {
        // Note: need to use `spawn` or `spawn_blocking` here, to make sure the stack size actually
        // applies (the `runtime.block_on` itself waits on the test thread, which has the default
        // stack size).
        tokio::task::spawn_blocking(move || {
            test_body();
        })
        .await
        .unwrap();
    });
}

// Note: this is not a real test; it's just a piece of code to estimate the maximum number
// of transactions that can fit into a store of the default size. I.e. it fills the store
// with txs of minimally possible size, stops when it's full and prints the count.
// In the end, it removes all txs from the store and prints the resulting memory usage, which
// will be the capacity overhead introduced by the 2 hashbrown tables.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn estimate_max_tx_count_in_store() {
    let make_minimal_tx = |input| {
        let tx = Transaction::new(
            0,
            vec![input],
            vec![TxOutput::Transfer(OutputValue::Coin(Amount::ZERO), Destination::AnyoneCanSpend)],
        )
        .unwrap();
        SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]).unwrap()
    };

    let fake_source = OutPointSourceId::Transaction(Id::new(common::primitives::H256::zero()));
    let minimal_tx = make_minimal_tx(TxInput::from_utxo(fake_source.clone(), 0));
    log::info!("minimal tx size = {}", minimal_tx.encoded_size());

    let time = TimeGetter::default().get_time();
    let origin = TxOrigin::Local(LocalTxOrigin::P2p);
    let options = TxOptions::default_for(origin);
    let fee = Amount::from_atoms(1_000_000).into();

    let mut storage = MempoolStore::new(Default::default());
    storage.disable_heavy_validity_checks();

    loop {
        let tx_count = storage.txs_by_id.len();

        let tx = make_minimal_tx(TxInput::from_utxo(fake_source.clone(), tx_count as u32));
        let entry = TxEntry::new(tx, time, origin, options.clone());
        storage.add_transaction(TxEntryWithFee::new(entry, fee)).unwrap();

        if storage.memory_usage() > MAX_MEMPOOL_SIZE_BYTES {
            log::info!("max tx count: {tx_count}",);
            break;
        }
    }

    let tx_ids = storage.txs_by_id.keys().copied().collect::<Vec<_>>();

    for tx_id in tx_ids {
        storage.remove_tx(&tx_id, MempoolRemovalReason::Expiry);
    }

    assert!(storage.txs_by_id.is_empty());

    // After all txs have been removed, the only thing that can occupy storage is allocated capacity
    // of containers that have it, which at the moment of writing this are the 2 hash tables -
    // `txs_by_id` and `seq_nos_by_tx`.
    // Note though that this value will not exactly represent what will happen in the actual app,
    // because in `cfg(test)` builds AssertDropPolicy is used as StrictDropPolicy, which contains
    // an additional bool, which will turn into 8 extra bytes for each bucket of `txs_by_id`, due
    // to alignment.
    log::info!(
        "memory usage after store cleanup: {}",
        storage.memory_usage()
    );
}
