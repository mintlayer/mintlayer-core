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

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn descendant_of_expired_entry(#[case] seed: Seed) -> anyhow::Result<()> {
    let mock_time = Arc::new(AtomicU64::new(0));
    let mock_time_clone = Arc::clone(&mock_time);
    let mock_clock = TimeGetter::new(Arc::new(move || {
        Duration::from_secs(mock_time_clone.load(Ordering::SeqCst))
    }));
    logging::init_logging::<&str>(None);

    let tf = TestFramework::default();
    let genesis = tf.genesis();
    let mut rng = make_seedable_rng(seed);

    let parent = TransactionBuilder::new()
        .add_input(
            TxInput::new(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(1_000)),
            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
        ))
        .add_output(TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(1_000)),
            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
        ))
        .build();

    let parent_id = parent.transaction().get_id();

    let chainstate = tf.chainstate();
    let (_sender, receiver) = mpsc::unbounded_channel();
    let mut mempool = Mempool::new(
        chainstate.get_chain_config(),
        start_chainstate(chainstate).await,
        mock_clock,
        SystemUsageEstimator {},
        receiver,
    );
    mempool.add_transaction(parent).await?;

    let flags = 0;
    let locktime = 0;
    let outpoint_source_id = OutPointSourceId::Transaction(parent_id);
    let child = tx_spend_input(
        &mempool,
        TxInput::new(outpoint_source_id, 0),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        None,
        flags,
        locktime,
    )
    .await?;
    let child_id = child.transaction().get_id();
    mock_time.store(DEFAULT_MEMPOOL_EXPIRY.as_secs() + 1, Ordering::SeqCst);

    assert!(matches!(
        mempool.add_transaction(child).await,
        Err(Error::TxValidationError(
            TxValidationError::DescendantOfExpiredTransaction
        ))
    ));

    assert!(!mempool.contains_transaction(&parent_id));
    assert!(!mempool.contains_transaction(&child_id));
    mempool.store.assert_valid();
    Ok(())
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn only_expired_entries_removed(#[case] seed: Seed) -> anyhow::Result<()> {
    let tf = TestFramework::default();
    let mut rng = make_seedable_rng(seed);
    let genesis = tf.genesis();
    let num_outputs = 2;
    let mut tx_builder = TransactionBuilder::new().add_input(
        TxInput::new(OutPointSourceId::BlockReward(genesis.get_id().into()), 0),
        empty_witness(&mut rng),
    );

    for _ in 0..num_outputs {
        tx_builder = tx_builder.add_output(TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(999_999_999_000)),
            OutputPurpose::Transfer(anyonecanspend_address()),
        ));
    }
    let parent = tx_builder.build();

    let mock_time = Arc::new(AtomicU64::new(0));
    let mock_time_clone = Arc::clone(&mock_time);
    let mock_clock = TimeGetter::new(Arc::new(move || {
        Duration::from_secs(mock_time_clone.load(Ordering::SeqCst))
    }));
    let chainstate = tf.chainstate();
    let config = chainstate.get_chain_config();
    let chainstate_interface = start_chainstate(chainstate).await;

    let (_sender, receiver) = mpsc::unbounded_channel();
    let mut mempool = Mempool::new(
        config,
        chainstate_interface,
        mock_clock,
        SystemUsageEstimator {},
        receiver,
    );

    let parent_id = parent.transaction().get_id();
    mempool.add_transaction(parent.clone()).await?;

    let flags = 0;
    let locktime = 0;
    let outpoint_source_id = OutPointSourceId::Transaction(parent_id);
    let child_0 = tx_spend_input(
        &mempool,
        TxInput::new(outpoint_source_id.clone(), 0),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        None,
        flags,
        locktime,
    )
    .await?;

    let child_1 = tx_spend_input(
        &mempool,
        TxInput::new(outpoint_source_id, 1),
        InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        None,
        flags,
        locktime,
    )
    .await?;
    let child_1_id = child_1.transaction().get_id();

    let expired_tx_id = child_0.transaction().get_id();
    mempool.add_transaction(child_0).await?;

    // Simulate the parent being added to a block
    // We have to do this because if we leave this parent in the mempool then it will be
    // expired, and so removed along with both its children, and thus the addition of child_1 to
    // the mempool will fail
    let block = Block::new(
        vec![parent],
        genesis.get_id().into(),
        BlockTimestamp::from_int_seconds(1639975461),
        ConsensusData::None,
        BlockReward::new(vec![]),
    )
    .map_err(|_| anyhow::Error::msg("block creation error"))?;
    mempool.store.remove_tx(&parent_id, MempoolRemovalReason::Block);

    mempool
        .chainstate_handle
        .call_mut(|this| this.process_block(block, BlockSource::Local))
        .await??;
    mock_time.store(DEFAULT_MEMPOOL_EXPIRY.as_secs() + 1, Ordering::SeqCst);

    mempool.add_transaction(child_1).await?;
    assert!(!mempool.contains_transaction(&expired_tx_id));
    assert!(mempool.contains_transaction(&child_1_id));
    mempool.store.assert_valid();
    Ok(())
}
