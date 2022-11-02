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

use common::chain::tokens::OutputValue;

use super::*;

async fn test_replace_tx(original_fee: Amount, replacement_fee: Amount) -> Result<(), Error> {
    log::debug!(
        "tx_replace_tx: original_fee: {:?}, replacement_fee {:?}",
        original_fee,
        replacement_fee
    );
    let tf = TestFramework::default();
    let genesis = tf.genesis();

    let outpoint_source_id = OutPointSourceId::BlockReward(genesis.get_id().into());

    let input = TxInput::new(outpoint_source_id, 0);
    let flags = 1;
    let locktime = 0;

    let mut mempool = setup_with_chainstate(tf.chainstate()).await;
    let original = tx_spend_input(
        &mempool,
        input.clone(),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        original_fee,
        flags,
        locktime,
    )
    .await
    .expect("should be able to spend here");
    let original_id = original.transaction().get_id();
    log::debug!(
        "created a tx with fee {:?}",
        mempool.try_get_fee(&original).await
    );
    mempool.add_transaction(original).await?;

    let flags = 0;
    let replacement = tx_spend_input(
        &mempool,
        input,
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        replacement_fee,
        flags,
        locktime,
    )
    .await
    .expect("should be able to spend here");
    log::debug!(
        "created a replacement with fee {:?}",
        mempool.try_get_fee(&replacement).await
    );
    mempool.add_transaction(replacement).await?;
    assert!(!mempool.contains_transaction(&original_id));
    mempool.store.assert_valid();

    Ok(())
}

#[tokio::test]
async fn try_replace_irreplaceable() -> anyhow::Result<()> {
    let tf = TestFramework::default();
    let genesis = tf.genesis();
    let outpoint_source_id = OutPointSourceId::BlockReward(genesis.get_id().into());

    let input = TxInput::new(outpoint_source_id, 0);
    let flags = 0;
    let locktime = 0;
    let original_fee = Amount::from_atoms(get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE));
    let mut mempool = setup_with_chainstate(tf.chainstate()).await;
    let original = tx_spend_input(
        &mempool,
        input.clone(),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        original_fee,
        flags,
        locktime,
    )
    .await
    .expect("should be able to spend here");
    let original_id = original.transaction().get_id();
    mempool.add_transaction(original).await?;

    let flags = 0;
    let replacement_fee = (original_fee + Amount::from_atoms(1000)).unwrap();
    let replacement = tx_spend_input(
        &mempool,
        input,
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        replacement_fee,
        flags,
        locktime,
    )
    .await
    .expect("should be able to spend here");
    assert!(matches!(
        mempool.add_transaction(replacement.clone()).await,
        Err(Error::TxValidationError(
            TxValidationError::ConflictWithIrreplaceableTransaction
        ))
    ));

    mempool.store.remove_tx(&original_id, MempoolRemovalReason::Block);
    mempool.add_transaction(replacement).await?;
    mempool.store.assert_valid();

    Ok(())
}

#[tokio::test]
async fn tx_replace() -> anyhow::Result<()> {
    let relay_fee = get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE);
    let replacement_fee = Amount::from_atoms(relay_fee + 100);
    test_replace_tx(Amount::from_atoms(100), replacement_fee).await?;
    let res = test_replace_tx(Amount::from_atoms(300), replacement_fee).await;
    assert!(matches!(
        res,
        Err(Error::TxValidationError(
            TxValidationError::InsufficientFeesToRelayRBF
        ))
    ));
    let res = test_replace_tx(Amount::from_atoms(100), Amount::from_atoms(100)).await;
    assert!(matches!(
        res,
        Err(Error::TxValidationError(
            TxValidationError::ReplacementFeeLowerThanOriginal { .. }
        ))
    ));
    let res = test_replace_tx(Amount::from_atoms(100), Amount::from_atoms(90)).await;
    assert!(matches!(
        res,
        Err(Error::TxValidationError(
            TxValidationError::ReplacementFeeLowerThanOriginal { .. }
        ))
    ));
    Ok(())
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn tx_replace_child(#[case] seed: Seed) -> anyhow::Result<()> {
    let tf = TestFramework::default();
    let mut rng = make_seedable_rng(seed);
    let genesis = tf.genesis();
    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::new(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(2_000)),
            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
        ))
        .with_flags(1)
        .build();
    let mut mempool = setup_with_chainstate(tf.chainstate()).await;
    mempool.add_transaction(tx.clone()).await?;

    let outpoint_source_id = OutPointSourceId::Transaction(tx.transaction().get_id());
    let child_tx_input = TxInput::new(outpoint_source_id, 0);
    // We want to test that even though child_tx doesn't signal replaceability directly, it is replaceable because its parent signalled replaceability
    // replaced
    let flags = 0;
    let locktime = 0;
    let child_tx = tx_spend_input(
        &mempool,
        child_tx_input.clone(),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        Amount::from_atoms(100),
        flags,
        locktime,
    )
    .await?;
    mempool.add_transaction(child_tx).await?;

    let relay_fee = get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE);
    let replacement_fee = Amount::from_atoms(relay_fee + 100);
    let replacement_tx = tx_spend_input(
        &mempool,
        child_tx_input,
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        replacement_fee,
        flags,
        locktime,
    )
    .await?;
    mempool.add_transaction(replacement_tx).await?;
    mempool.store.assert_valid();
    Ok(())
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn pays_more_than_conflicts_with_descendants(#[case] seed: Seed) -> anyhow::Result<()> {
    let tf = TestFramework::default();
    let mut rng = make_seedable_rng(seed);
    let genesis = tf.genesis();
    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::new(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(1_000)),
            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
        ))
        .with_flags(1)
        .build();
    let mut mempool = setup_with_chainstate(tf.chainstate()).await;
    let tx_id = tx.transaction().get_id();
    mempool.add_transaction(tx).await?;

    let outpoint_source_id = OutPointSourceId::Transaction(tx_id);
    let input = TxInput::new(outpoint_source_id, 0);

    let locktime = 0;
    let rbf = 1;
    let no_rbf = 0;

    // Create transaction that we will attempt to replace
    let original_fee = Amount::from_atoms(100);
    let replaced_tx = tx_spend_input(
        &mempool,
        input.clone(),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        original_fee,
        rbf,
        locktime,
    )
    .await?;
    let replaced_tx_fee = mempool.try_get_fee(&replaced_tx).await?;
    let replaced_id = replaced_tx.transaction().get_id();
    mempool.add_transaction(replaced_tx).await?;

    // Create some children for this transaction
    let descendant_outpoint_source_id = OutPointSourceId::Transaction(replaced_id);

    let descendant1_fee = Amount::from_atoms(100);
    let descendant1 = tx_spend_input(
        &mempool,
        TxInput::new(descendant_outpoint_source_id.clone(), 0),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        descendant1_fee,
        no_rbf,
        locktime,
    )
    .await?;
    let descendant1_id = descendant1.transaction().get_id();
    mempool.add_transaction(descendant1).await?;

    let descendant2_fee = Amount::from_atoms(100);
    let descendant2 = tx_spend_input(
        &mempool,
        TxInput::new(descendant_outpoint_source_id, 1),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        descendant2_fee,
        no_rbf,
        locktime,
    )
    .await?;
    let descendant2_id = descendant2.transaction().get_id();
    mempool.add_transaction(descendant2).await?;

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
        locktime,
    )
    .await?;

    assert!(matches!(
        mempool.add_transaction(incoming_tx).await,
        Err(Error::TxValidationError(
            TxValidationError::TransactionFeeLowerThanConflictsWithDescendants
        ))
    ));

    let relay_fee = get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE);
    let sufficient_rbf_fee = insufficient_rbf_fee + Amount::from_atoms(relay_fee);
    let incoming_tx = tx_spend_input(
        &mempool,
        input,
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        sufficient_rbf_fee,
        no_rbf,
        locktime,
    )
    .await?;
    mempool.add_transaction(incoming_tx).await?;

    assert!(!mempool.contains_transaction(&replaced_id));
    assert!(!mempool.contains_transaction(&descendant1_id));
    assert!(!mempool.contains_transaction(&descendant2_id));
    mempool.store.assert_valid();
    Ok(())
}
