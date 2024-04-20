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

use common::chain::output_value::OutputValue;
use randomness::{CryptoRng, Rng};

use super::*;

async fn test_replace_tx(
    rng: &mut (impl Rng + CryptoRng),
    original_fee: Fee,
    replacement_fee: Fee,
) -> Result<(), Error> {
    log::debug!(
        "tx_replace_tx: original_fee: {:?}, replacement_fee {:?}",
        original_fee,
        replacement_fee
    );
    let tf = TestFramework::builder(rng).build();
    let genesis = tf.genesis();

    let outpoint_source_id = OutPointSourceId::BlockReward(genesis.get_id().into());

    let input = TxInput::from_utxo(outpoint_source_id, 0);
    let flags = 1;

    let mut mempool = setup_with_chainstate(tf.chainstate());
    let original = tx_spend_input(
        &mempool,
        input.clone(),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        original_fee,
        flags,
    )
    .await
    .expect("should be able to spend here");
    let original_id = original.transaction().get_id();
    log::debug!(
        "created a tx with fee {:?}",
        try_get_fee(&mempool, &original).await
    );
    mempool.add_transaction_test(original)?.assert_in_mempool();

    let flags = 0;
    let replacement = tx_spend_input(
        &mempool,
        input,
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        replacement_fee,
        flags,
    )
    .await
    .expect("should be able to spend here");
    log::debug!(
        "created a replacement with fee {:?}",
        try_get_fee(&mempool, &replacement).await
    );
    mempool.add_transaction_test(replacement)?.assert_in_mempool();
    assert!(!mempool.contains_transaction(&original_id));
    mempool.store.assert_valid();

    Ok(())
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "RBF not implemented"]
async fn try_replace_irreplaceable(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();
    let outpoint_source_id = OutPointSourceId::BlockReward(genesis.get_id().into());

    let input = TxInput::from_utxo(outpoint_source_id, 0);
    let flags = 0;
    let original_fee: Fee = get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE).into();
    let mut mempool = setup_with_chainstate(tf.chainstate());
    let original = tx_spend_input(
        &mempool,
        input.clone(),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        original_fee,
        flags,
    )
    .await
    .expect("should be able to spend here");
    let original_id = original.transaction().get_id();
    mempool.add_transaction_test(original)?.assert_in_mempool();

    let flags = 0;
    let replacement_fee = (original_fee + Fee::new(Amount::from_atoms(1000))).unwrap();
    let replacement = tx_spend_input(
        &mempool,
        input,
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        replacement_fee,
        flags,
    )
    .await
    .expect("should be able to spend here");
    assert_eq!(
        mempool.add_transaction_test(replacement.clone()),
        Err(MempoolPolicyError::from(MempoolConflictError::Irreplacable).into())
    );

    mempool.store.remove_tx(&original_id, MempoolRemovalReason::Block);
    mempool.add_transaction_test(replacement)?.assert_in_mempool();
    mempool.store.assert_valid();

    Ok(())
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "RBF not implemented"]
async fn tx_replace(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let relay_fee = get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE);
    let replacement_fee: Fee = (relay_fee + Amount::from_atoms(100)).unwrap().into();
    test_replace_tx(&mut rng, Fee::new(Amount::from_atoms(100)), replacement_fee).await?;
    let res = test_replace_tx(&mut rng, Fee::new(Amount::from_atoms(300)), replacement_fee).await;
    assert!(matches!(
        res,
        Err(Error::Policy(
            MempoolPolicyError::InsufficientFeesToRelayRBF
        ))
    ));
    let res = test_replace_tx(
        &mut rng,
        Amount::from_atoms(100).into(),
        Amount::from_atoms(100).into(),
    )
    .await;
    assert!(matches!(
        res,
        Err(Error::Policy(
            MempoolPolicyError::ReplacementFeeLowerThanOriginal { .. }
        ))
    ));
    let res = test_replace_tx(
        &mut rng,
        Amount::from_atoms(100).into(),
        Amount::from_atoms(90).into(),
    )
    .await;
    assert!(matches!(
        res,
        Err(Error::Policy(
            MempoolPolicyError::ReplacementFeeLowerThanOriginal { .. }
        ))
    ));
    Ok(())
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "RBF not implemented"]
async fn tx_replace_child(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();
    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(2_000)),
            Destination::AnyoneCanSpend,
        ))
        .with_flags(1)
        .build();
    let mut mempool = setup_with_chainstate(tf.chainstate());
    mempool.add_transaction_test(tx.clone())?.assert_in_mempool();

    let outpoint_source_id = OutPointSourceId::Transaction(tx.transaction().get_id());
    let child_tx_input = TxInput::from_utxo(outpoint_source_id, 0);
    // We want to test that even though child_tx doesn't signal replaceability directly, it is replaceable because its parent signalled replaceability
    // replaced
    let flags = 0;
    let child_tx = tx_spend_input(
        &mempool,
        child_tx_input.clone(),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        Fee::new(Amount::from_atoms(100)),
        flags,
    )
    .await?;
    mempool.add_transaction_test(child_tx)?.assert_in_mempool();

    let relay_fee = get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE);
    let replacement_fee: Fee = (relay_fee + Amount::from_atoms(100)).unwrap().into();
    let replacement_tx = tx_spend_input(
        &mempool,
        child_tx_input,
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        replacement_fee,
        flags,
    )
    .await?;
    mempool.add_transaction_test(replacement_tx)?.assert_in_mempool();
    mempool.store.assert_valid();
    Ok(())
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "RBF not implemented"]
async fn pays_more_than_conflicts_with_descendants(#[case] seed: Seed) -> anyhow::Result<()> {
    let mut rng = make_seedable_rng(seed);
    let tf = TestFramework::builder(&mut rng).build();
    let genesis = tf.genesis();
    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1_000)),
            Destination::AnyoneCanSpend,
        ))
        .with_flags(1)
        .build();
    let mut mempool = setup_with_chainstate(tf.chainstate());
    let tx_id = tx.transaction().get_id();
    mempool.add_transaction_test(tx)?.assert_in_mempool();

    let outpoint_source_id = OutPointSourceId::Transaction(tx_id);
    let input = TxInput::from_utxo(outpoint_source_id, 0);

    let rbf = 1;
    let no_rbf = 0;

    // Create transaction that we will attempt to replace
    let original_fee: Fee = Amount::from_atoms(100).into();
    let replaced_tx = tx_spend_input(
        &mempool,
        input.clone(),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        original_fee,
        rbf,
    )
    .await?;
    let replaced_tx_fee = try_get_fee(&mempool, &replaced_tx).await;
    let replaced_id = replaced_tx.transaction().get_id();
    mempool.add_transaction_test(replaced_tx)?.assert_in_mempool();

    // Create some children for this transaction
    let descendant_outpoint_source_id = OutPointSourceId::Transaction(replaced_id);

    let descendant1_fee: Fee = Amount::from_atoms(100).into();
    let descendant1 = tx_spend_input(
        &mempool,
        TxInput::from_utxo(descendant_outpoint_source_id.clone(), 0),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        descendant1_fee,
        no_rbf,
    )
    .await?;
    let descendant1_id = descendant1.transaction().get_id();
    mempool.add_transaction_test(descendant1)?.assert_in_mempool();

    let descendant2_fee: Fee = Amount::from_atoms(100).into();
    let descendant2 = tx_spend_input(
        &mempool,
        TxInput::from_utxo(descendant_outpoint_source_id, 1),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        descendant2_fee,
        no_rbf,
    )
    .await?;
    let descendant2_id = descendant2.transaction().get_id();
    mempool.add_transaction_test(descendant2)?.assert_in_mempool();

    //Create a new incoming transaction that conflicts with `replaced_tx` because it spends
    //`input`. It will be rejected because its fee exactly equals (so is not greater than) the
    //sum of the fees of the conflict together with its descendants
    let insufficient_rbf_fee = [replaced_tx_fee, descendant1_fee, descendant2_fee]
        .into_iter()
        .sum::<Option<_>>()
        .unwrap();
    let incoming_tx = tx_spend_input(
        &mempool,
        input.clone(),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        insufficient_rbf_fee,
        no_rbf,
    )
    .await?;

    assert_eq!(
        mempool.add_transaction_test(incoming_tx),
        Err(MempoolPolicyError::TransactionFeeLowerThanConflictsWithDescendants.into())
    );

    let relay_fee = get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE);
    let sufficient_rbf_fee = insufficient_rbf_fee + relay_fee.into();
    let incoming_tx = tx_spend_input(
        &mempool,
        input,
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        sufficient_rbf_fee,
        no_rbf,
    )
    .await?;
    mempool.add_transaction_test(incoming_tx)?.assert_in_mempool();

    assert!(!mempool.contains_transaction(&replaced_id));
    assert!(!mempool.contains_transaction(&descendant1_id));
    assert!(!mempool.contains_transaction(&descendant2_id));
    mempool.store.assert_valid();
    Ok(())
}
