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

use std::sync::Arc;
use std::{sync::atomic::Ordering, time::Duration};

use chainstate::chainstate_interface::ChainstateInterface;
use chainstate::{
    make_chainstate, BlockError, BlockSource, ChainstateConfig, ChainstateError, CheckBlockError,
    CheckBlockTransactionsError, ConnectTransactionError, OrphanCheckError, TxIndexError,
};
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestBlockInfo, TestFramework, TestStore,
    TransactionBuilder,
};
use chainstate_types::{GenBlockIndex, PropertyQueryError};
use common::chain::OutPoint;
use common::chain::{signed_transaction::SignedTransaction, Transaction};
use common::primitives::BlockDistance;
use common::{
    chain::{
        block::{consensus_data::PoWData, timestamp::BlockTimestamp, ConsensusData},
        config::{create_unit_test_config, Builder as ConfigBuilder},
        timelock::OutputTimeLock,
        tokens::OutputValue,
        Block, ConsensusUpgrade, Destination, GenBlock, NetUpgrades, OutPointSourceId,
        OutputPurpose, OutputSpentState, TxInput, TxOutput, UpgradeVersion,
    },
    primitives::{Amount, BlockHeight, Compact, Id, Idable},
    time_getter::TimeGetter,
    Uint256,
};
use consensus::{ConsensusPoWError, ConsensusVerificationError};
use crypto::{
    key::{KeyKind, PrivateKey},
    random::Rng,
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};
use utxo::UtxoSource;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn invalid_block_reward_types(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let chain_config = ConfigBuilder::test_chain()
            .empty_consensus_reward_maturity_distance(50.into())
            .build();
        let mut tf = TestFramework::builder().with_chain_config(chain_config).build();

        let coins = OutputValue::Coin(Amount::from_atoms(10));
        let destination = Destination::PublicKey(PrivateKey::new(KeyKind::RistrettoSchnorr).1);

        // Case 1: reward is a simple transfer
        let block = tf
            .make_block_builder()
            .with_reward(vec![TxOutput::new(
                coins.clone(),
                OutputPurpose::Transfer(destination.clone()),
            )])
            .add_test_transaction(&mut rng)
            .build();

        let block_id = block.get_id();
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::InvalidBlockRewardOutputType(block_id)
            ))
        );

        // Case 2: reward is locked until height
        let block = tf
            .make_block_builder()
            .with_reward(vec![TxOutput::new(
                coins.clone(),
                OutputPurpose::LockThenTransfer(
                    destination.clone(),
                    OutputTimeLock::UntilHeight(BlockHeight::max()),
                ),
            )])
            .add_test_transaction(&mut rng)
            .build();

        let block_id = block.get_id();
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::InvalidBlockRewardMaturityTimelockType(block_id)
            ))
        );

        // Case 3: reward is locked until a specific time
        let block = tf
            .make_block_builder()
            .with_reward(vec![TxOutput::new(
                coins.clone(),
                OutputPurpose::LockThenTransfer(
                    destination.clone(),
                    OutputTimeLock::UntilTime(BlockTimestamp::from_int_seconds(u64::MAX)),
                ),
            )])
            .add_test_transaction(&mut rng)
            .build();

        let block_id = block.get_id();
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::InvalidBlockRewardMaturityTimelockType(block_id)
            ))
        );

        // Case 4: reward is locked for an amount of seconds
        let block = tf
            .make_block_builder()
            .with_reward(vec![TxOutput::new(
                coins.clone(),
                OutputPurpose::LockThenTransfer(
                    destination.clone(),
                    OutputTimeLock::ForSeconds(u64::MAX),
                ),
            )])
            .add_test_transaction(&mut rng)
            .build();

        let block_id = block.get_id();
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::InvalidBlockRewardMaturityTimelockType(block_id)
            ))
        );

        // Case 5: reward is locked for an invalid number
        let block = tf
            .make_block_builder()
            .with_reward(vec![TxOutput::new(
                coins.clone(),
                OutputPurpose::LockThenTransfer(
                    destination.clone(),
                    OutputTimeLock::ForBlockCount(u64::MAX),
                ),
            )])
            .add_test_transaction(&mut rng)
            .build();

        let block_id = block.get_id();
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::InvalidBlockRewardMaturityDistanceValue(block_id, u64::MAX)
            ))
        );

        // Case 6: reward is locked for less than the required number of blocks
        let reward_lock_distance: i64 = tf
            .chainstate
            .get_chain_config()
            .empty_consensus_reward_maturity_distance()
            .into();

        let block = tf
            .make_block_builder()
            .with_reward(vec![TxOutput::new(
                coins.clone(),
                OutputPurpose::LockThenTransfer(
                    destination.clone(),
                    OutputTimeLock::ForBlockCount(reward_lock_distance as u64 - 1),
                ),
            )])
            .add_test_transaction(&mut rng)
            .build();

        let block_id = block.get_id();
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::InvalidBlockRewardMaturityDistance(
                    block_id,
                    BlockDistance::new(reward_lock_distance - 1),
                    BlockDistance::new(reward_lock_distance)
                ),
            ))
        );

        // Case 7: reward is a stake lock
        let block = tf
            .make_block_builder()
            .with_reward(vec![TxOutput::new(
                coins.clone(),
                OutputPurpose::StakeLock(destination.clone()),
            )])
            .add_test_transaction(&mut rng)
            .build();

        assert!(matches!(
            tf.process_block(block, BlockSource::Local),
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::InvalidBlockRewardOutputType(_))
            ))
        ));

        // Case 8: the correct, working case
        let reward_lock_distance: i64 = tf
            .chainstate
            .get_chain_config()
            .empty_consensus_reward_maturity_distance()
            .into();

        let block = tf
            .make_block_builder()
            .with_reward(vec![TxOutput::new(
                coins,
                OutputPurpose::LockThenTransfer(
                    destination,
                    OutputTimeLock::ForBlockCount(reward_lock_distance as u64),
                ),
            )])
            .add_test_transaction(&mut rng)
            .build();

        let block_id = block.get_id();
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap().unwrap().block_id(),
            &block_id
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn orphans_chains(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::default();
        assert_eq!(tf.best_block_id(), tf.genesis().get_id());

        // Prepare, but not process the block.
        let missing_block = tf.make_block_builder().add_test_transaction(&mut rng).build();

        // Create and process orphan blocks.
        const MAX_ORPHANS_COUNT_IN_TEST: usize = 100;
        let mut current_block = missing_block.clone();
        for orphan_count in 1..MAX_ORPHANS_COUNT_IN_TEST {
            current_block = tf
                .make_block_builder()
                .with_parent(current_block.get_id().into())
                .add_test_transaction_from_block(&current_block, &mut rng)
                .build();
            assert_eq!(
                tf.process_block(current_block.clone(), BlockSource::Local).unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::OrphanCheckFailed(
                    OrphanCheckError::LocalOrphan
                ))
            );
            // The genesis block is still the best one, because we are processing orphan blocks.
            assert_eq!(tf.best_block_id(), tf.genesis().get_id());
            assert!(tf.chainstate.is_already_an_orphan(&current_block.get_id()));
            assert_eq!(tf.chainstate.orphans_count(), orphan_count);
        }

        // now we submit the missing block (at height 1), and we expect all blocks to be processed
        let last_block_index =
            tf.process_block(missing_block, BlockSource::Local).unwrap().unwrap();
        assert_eq!(
            last_block_index.block_height(),
            (MAX_ORPHANS_COUNT_IN_TEST as u64).into()
        );
        let current_best = tf
            .best_block_id()
            .classify(&tf.chainstate.get_chain_config())
            .chain_block_id()
            .unwrap();
        assert_eq!(
            tf.block_index(&current_best.into()).block_height(),
            (MAX_ORPHANS_COUNT_IN_TEST as u64).into()
        );
        // There should be no more orphan blocks left.
        assert_eq!(tf.chainstate.orphans_count(), 0);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_inputs_simple(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::default();

        // Check that genesis utxos are present in the utxo set
        let genesis_id = tf.genesis().get_id();
        for (idx, txo) in tf.genesis().utxos().iter().enumerate() {
            let idx = idx as u32;
            let utxo = tf.chainstate.utxo(&OutPoint::new(genesis_id.into(), idx)).unwrap().unwrap();
            assert!(!utxo.is_block_reward());
            assert_eq!(utxo.output(), txo);
            assert_eq!(utxo.source(), &UtxoSource::Blockchain(BlockHeight::new(0)));
        }

        // Create a new block
        let block = tf.make_block_builder().add_test_transaction(&mut rng).build();

        // Check that all tx not in the main chain
        for tx in block.transactions() {
            assert_eq!(
                tf.chainstate.get_mainchain_tx_index(&tx.transaction().get_id().into()).unwrap(),
                None
            );
        }

        // Process the second block
        tf.process_block(block.clone(), BlockSource::Local).unwrap();
        assert_eq!(tf.best_block_id(), <Id<GenBlock>>::from(block.get_id()));

        // Check that the transactions are in the main-chain and ensure that the connected previous
        // outputs are spent.
        for tx in block.transactions() {
            let tx_id = tx.transaction().get_id();
            // All inputs must spend a corresponding output
            for tx_in in tx.transaction().inputs() {
                let outpoint = tx_in.outpoint();
                let prev_out_tx_index =
                    tf.chainstate.get_mainchain_tx_index(&outpoint.tx_id()).unwrap().unwrap();
                assert_eq!(
                    prev_out_tx_index.get_spent_state(outpoint.output_index()).unwrap(),
                    OutputSpentState::SpentBy(tx_id.into())
                );
                assert_eq!(tf.chainstate.utxo(outpoint), Ok(None))
            }
            // All the outputs of this transaction should be unspent
            let tx_index = tf.chainstate.get_mainchain_tx_index(&tx_id.into()).unwrap().unwrap();
            for (idx, txo) in tx.transaction().outputs().iter().enumerate() {
                let idx = idx as u32;
                assert_eq!(
                    tx_index.get_spent_state(idx).unwrap(),
                    OutputSpentState::Unspent
                );
                let utxo = tf.chainstate.utxo(&OutPoint::new(tx_id.into(), idx)).unwrap().unwrap();
                assert!(!utxo.is_block_reward());
                assert_eq!(utxo.output(), txo);
                assert_eq!(utxo.source(), &UtxoSource::Blockchain(BlockHeight::new(1)));
            }
        }
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn transaction_processing_order(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::default();

        // Transaction that spends the genesis reward
        let tx1 = SignedTransaction::new(
            Transaction::new(
                0,
                vec![TxInput::new(tf.genesis().get_id().into(), 0)],
                vec![TxOutput::new(
                    tf.genesis().utxos()[0].value().clone(),
                    OutputPurpose::Transfer(anyonecanspend_address()),
                )],
                0,
            )
            .unwrap(),
            vec![empty_witness(&mut rng)],
        )
        .expect("invalid witness count");

        // Transaction that spends tx1
        let tx2 = SignedTransaction::new(
            Transaction::new(
                0,
                vec![TxInput::new(tx1.transaction().get_id().into(), 0)],
                vec![TxOutput::new(
                    tx1.transaction().outputs()[0].value().clone(),
                    OutputPurpose::Transfer(anyonecanspend_address()),
                )],
                0,
            )
            .unwrap(),
            vec![empty_witness(&mut rng)],
        )
        .expect("invalid witness count");

        // Create a new block with tx2 appearing before tx1
        let block = tf.make_block_builder().add_transaction(tx2).add_transaction(tx1).build();

        // Processing this block should cause an error
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TxIndexError(TxIndexError::MissingOutputOrSpent)
            ))
        );
    });
}

// Produce and process some blocks.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn straight_chain(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::default();

        let genesis_index = tf
            .chainstate
            .get_gen_block_index(&tf.genesis().get_id().into())
            .unwrap()
            .unwrap();

        assert_eq!(tf.best_block_id(), tf.genesis().get_id());
        assert_eq!(genesis_index.chain_trust(), &Uint256::from_u64(0));
        assert_eq!(genesis_index.block_height(), BlockHeight::new(0));

        let chain_config_clone = tf.chainstate.get_chain_config();
        let mut block_index =
            GenBlockIndex::Genesis(Arc::clone(chain_config_clone.genesis_block()));
        let mut prev_block = TestBlockInfo::from_genesis(&tf.genesis());

        for _ in 0..rng.gen_range(100..200) {
            assert_eq!(tf.chainstate.get_best_block_id().unwrap(), prev_block.id);
            let prev_block_id = block_index.block_id();
            let best_block_id = tf.best_block_id();
            assert_eq!(best_block_id, block_index.block_id());
            let new_block = tf
                .make_block_builder()
                .with_parent(prev_block.id)
                .add_test_transaction_with_parent(prev_block.id, &mut rng)
                .build();
            let new_block_index =
                tf.process_block(new_block.clone(), BlockSource::Peer).unwrap().unwrap();

            assert_eq!(new_block_index.prev_block_id(), &prev_block_id);
            assert!(new_block_index.chain_trust() > block_index.chain_trust());
            assert_eq!(
                new_block_index.block_height(),
                block_index.block_height().next_height()
            );

            block_index = GenBlockIndex::Block(new_block_index);
            prev_block = TestBlockInfo::from_block(&new_block);
        }
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_ancestor_invalid_height(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = TestFramework::default();
    let height = 1;
    tf.create_chain(&tf.genesis().get_id().into(), height, &mut rng).unwrap();

    let invalid_height = height + 1;
    assert_eq!(
        ChainstateError::FailedToReadProperty(PropertyQueryError::GetAncestorError(
            GetAncestorError::InvalidAncestorHeight {
                ancestor_height: u64::try_from(invalid_height).unwrap().into(),
                block_height: u64::try_from(height).unwrap().into(),
            }
        )),
        tf.chainstate
            .get_ancestor(
                &tf.best_block_index(),
                u64::try_from(invalid_height).unwrap().into()
            )
            .unwrap_err()
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_ancestor(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = TestFramework::default();

    // We will create two chains that split at height 100
    const SPLIT_HEIGHT: usize = 100;
    const ANCESTOR_HEIGHT: usize = 50;
    const FIRST_CHAIN_HEIGHT: usize = 500;
    const SECOND_CHAIN_LENGTH: usize = 300;
    tf.create_chain(&tf.genesis().get_id().into(), SPLIT_HEIGHT, &mut rng)
        .expect("Chain creation to succeed");

    let ancestor = GenBlockIndex::Block(tf.index_at(ANCESTOR_HEIGHT).clone());
    assert_eq!(
        ancestor.block_height(),
        BlockHeight::from(ANCESTOR_HEIGHT as u64)
    );

    let split = GenBlockIndex::Block(tf.index_at(SPLIT_HEIGHT).clone());
    assert_eq!(split.block_height(), BlockHeight::from(SPLIT_HEIGHT as u64));

    // we aggressively test the simple ancestor calculation for all previous heights up to genesis
    for i in 1..=split.block_height().into() {
        assert_eq!(
            <Id<GenBlock>>::from(*tf.index_at(i as usize).block_id()),
            tf.chainstate
                .get_ancestor(&split, i.into())
                .unwrap_or_else(|_| panic!("Ancestor of height {} not reached", i))
                .block_id()
        );
    }

    // Create the first chain and test get_ancestor for this chain's  last block
    tf.create_chain(
        &split.block_id(),
        FIRST_CHAIN_HEIGHT - SPLIT_HEIGHT,
        &mut rng,
    )
    .expect("second chain");
    let last_block_in_first_chain = tf.best_block_index();

    const ANCESTOR_IN_FIRST_CHAIN_HEIGHT: usize = 400;
    let ancestor_in_first_chain =
        GenBlockIndex::Block(tf.index_at(ANCESTOR_IN_FIRST_CHAIN_HEIGHT).clone());
    assert_eq!(
        ancestor_in_first_chain.block_height(),
        BlockHeight::from(ANCESTOR_IN_FIRST_CHAIN_HEIGHT as u64),
    );

    assert_eq!(
        last_block_in_first_chain.block_id(),
        tf.chainstate
            .get_ancestor(
                &last_block_in_first_chain,
                u64::try_from(FIRST_CHAIN_HEIGHT).unwrap().into()
            )
            .expect("ancestor")
            .block_id()
    );

    assert_eq!(
        ancestor.block_id(),
        tf.chainstate
            .get_ancestor(
                &last_block_in_first_chain,
                u64::try_from(ANCESTOR_HEIGHT).unwrap().into()
            )
            .expect("ancestor")
            .block_id()
    );

    assert_eq!(
        ancestor_in_first_chain.block_id(),
        tf.chainstate
            .get_ancestor(
                &last_block_in_first_chain,
                u64::try_from(ANCESTOR_IN_FIRST_CHAIN_HEIGHT).unwrap().into()
            )
            .expect("ancestor in first chain")
            .block_id()
    );

    // Create a second chain and test get_ancestor for this chain's last block
    let last_block_in_second_chain = tf
        .create_chain(
            &split.block_id(),
            SECOND_CHAIN_LENGTH - SPLIT_HEIGHT,
            &mut rng,
        )
        .expect("second chain");
    assert_eq!(
        ancestor.block_id(),
        tf.chainstate
            .get_ancestor(
                &tf.block_index(&last_block_in_second_chain),
                u64::try_from(ANCESTOR_HEIGHT).unwrap().into()
            )
            .expect("ancestor")
            .block_id()
    );
}

// Create two chains that split at height 100.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn last_common_ancestor(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = TestFramework::default();

    const SPLIT_HEIGHT: usize = 100;
    const FIRST_CHAIN_HEIGHT: usize = 500;
    const SECOND_CHAIN_LENGTH: usize = 300;

    tf.create_chain(&tf.genesis().get_id().into(), SPLIT_HEIGHT, &mut rng)
        .expect("Chain creation to succeed");
    let config_clone = tf.chainstate.get_chain_config();
    let genesis = GenBlockIndex::Genesis(Arc::clone(config_clone.genesis_block()));
    let split = GenBlockIndex::Block(tf.index_at(SPLIT_HEIGHT).clone());

    // First branch of fork
    tf.create_chain(
        &split.block_id(),
        FIRST_CHAIN_HEIGHT - SPLIT_HEIGHT,
        &mut rng,
    )
    .expect("Chain creation to succeed");
    let last_block_in_first_chain = tf.best_block_index();

    // Second branch of fork
    let last_block_in_second_chain = tf
        .create_chain(
            &split.block_id(),
            SECOND_CHAIN_LENGTH - SPLIT_HEIGHT,
            &mut rng,
        )
        .unwrap();
    let last_block_in_second_chain = tf.block_index(&last_block_in_second_chain);

    assert_eq!(
        tf.chainstate
            .last_common_ancestor(&last_block_in_first_chain, &last_block_in_second_chain)
            .unwrap()
            .block_id(),
        split.block_id()
    );

    assert_eq!(
        tf.chainstate
            .last_common_ancestor(&last_block_in_second_chain, &last_block_in_first_chain)
            .unwrap()
            .block_id(),
        split.block_id()
    );

    assert_eq!(
        tf.chainstate
            .last_common_ancestor(&last_block_in_first_chain, &last_block_in_first_chain)
            .unwrap()
            .block_id(),
        last_block_in_first_chain.block_id()
    );

    assert_eq!(
        tf.chainstate.last_common_ancestor(&genesis, &split).unwrap().block_id(),
        genesis.block_id()
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn consensus_type(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let ignore_consensus = BlockHeight::new(0);
    let pow = BlockHeight::new(5);
    let ignore_again = BlockHeight::new(10);
    let pow_again = BlockHeight::new(15);

    let min_difficulty =
        Uint256([0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF]);

    let upgrades = vec![
        (
            ignore_consensus,
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            pow,
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoW {
                initial_difficulty: min_difficulty.into(),
            }),
        ),
        (
            ignore_again,
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            pow_again,
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoW {
                initial_difficulty: min_difficulty.into(),
            }),
        ),
    ];

    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid netupgrades");
    // Internally this calls Consensus::new, which processes the genesis block
    // This should succeed because config::Builder by default uses create_mainnet_genesis to
    // create the genesis_block, and this function creates a genesis block with
    // ConsensusData::None, which agrees with the net_upgrades we defined above.
    let chain_config = ConfigBuilder::test_chain().net_upgrades(net_upgrades).build();
    let mut tf = TestFramework::builder().with_chain_config(chain_config).build();

    let reward_lock_distance: i64 = tf
        .chainstate
        .get_chain_config()
        .get_proof_of_work_config()
        .reward_maturity_distance()
        .into();

    // The next block will have height 1. At this height, we are still under IgnoreConsensus, so
    // processing a block with PoWData will fail
    assert!(matches!(
        tf.make_block_builder()
            .add_test_transaction(&mut rng)
            .with_consensus_data(ConsensusData::PoW(PoWData::new(Compact(0), 0)))
            .build_and_process()
            .unwrap_err(),
        ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
            CheckBlockError::ConsensusVerificationFailed(
                ConsensusVerificationError::ConsensusTypeMismatch(..)
            )
        ))
    ));

    // Create 4 more blocks with Consensus Nonw
    tf.create_chain(&tf.genesis().get_id().into(), 4, &mut rng)
        .expect("chain creation");

    // The next block will be at height 5, so it is expected to be a PoW block. Let's crate a block
    // with ConsensusData::None and see that adding it fails
    assert!(matches!(
        tf.make_block_builder()
            .add_test_transaction(&mut rng)
            .build_and_process()
            .unwrap_err(),
        ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
            CheckBlockError::ConsensusVerificationFailed(
                ConsensusVerificationError::ConsensusTypeMismatch(..)
            )
        ))
    ));

    // Mine blocks 5-9 with minimal difficulty, as expected by net upgrades
    for i in 5..10 {
        let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let prev_block = tf.block(*tf.index_at(i - 1).block_id());
        let mut mined_block = tf
            .make_block_builder()
            .with_parent(prev_block.get_id().into())
            .with_reward(vec![TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(10)),
                OutputPurpose::LockThenTransfer(
                    Destination::PublicKey(pub_key),
                    OutputTimeLock::ForBlockCount(reward_lock_distance as u64),
                ),
            )])
            .add_test_transaction_from_block(&prev_block, &mut rng)
            .build();
        let bits = min_difficulty.into();
        assert!(consensus::pow::mine(&mut mined_block, u128::MAX, bits)
            .expect("Unexpected conversion error"));
        tf.process_block(mined_block, BlockSource::Local).unwrap();
    }

    // Block 10 should ignore consensus according to net upgrades. The following Pow block should
    // fail.
    let prev_block = tf.block(*tf.index_at(9).block_id());
    let mut mined_block = tf
        .make_block_builder()
        .with_parent(prev_block.get_id().into())
        .add_test_transaction_from_block(&prev_block, &mut rng)
        .build();
    let bits = min_difficulty.into();
    assert!(consensus::pow::mine(&mut mined_block, u128::MAX, bits)
        .expect("Unexpected conversion error"));

    assert!(matches!(
        tf.process_block(mined_block, BlockSource::Local).unwrap_err(),
        ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
            CheckBlockError::ConsensusVerificationFailed(
                ConsensusVerificationError::ConsensusTypeMismatch(..)
            )
        ))
    ));

    // Create blocks 10-14 without consensus data as required by net_upgrades
    tf.create_chain(&prev_block.get_id().into(), 5, &mut rng)
        .expect("chain creation");

    // At height 15 we are again proof of work, ignoring consensus should fail
    let prev_block = tf.block(*tf.index_at(14).block_id());
    assert!(matches!(
        tf.make_block_builder()
            .with_parent(prev_block.get_id().into())
            .add_test_transaction_from_block(&prev_block, &mut rng)
            .build_and_process()
            .unwrap_err(),
        ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
            CheckBlockError::ConsensusVerificationFailed(
                ConsensusVerificationError::ConsensusTypeMismatch(..)
            )
        ))
    ));

    let reward_lock_distance: i64 = tf
        .chainstate
        .get_chain_config()
        .get_proof_of_work_config()
        .reward_maturity_distance()
        .into();

    // Mining should work
    for i in 15..20 {
        let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let prev_block = tf.block(*tf.index_at(i - 1).block_id());
        let mut mined_block = tf
            .make_block_builder()
            .with_parent(prev_block.get_id().into())
            .with_reward(vec![TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(10)),
                OutputPurpose::LockThenTransfer(
                    Destination::PublicKey(pub_key),
                    OutputTimeLock::ForBlockCount(reward_lock_distance as u64),
                ),
            )])
            .add_test_transaction_from_block(&prev_block, &mut rng)
            .build();
        let bits = min_difficulty.into();
        assert!(consensus::pow::mine(&mut mined_block, u128::MAX, bits)
            .expect("Unexpected conversion error"));
        tf.process_block(mined_block, BlockSource::Local).unwrap();
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn pow(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let ignore_consensus = BlockHeight::new(0);
    let pow_consensus = BlockHeight::new(1);
    let difficulty =
        Uint256([0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x0FFFFFFFFFFFFFFF]);

    let upgrades = vec![
        (
            ignore_consensus,
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            pow_consensus,
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoW {
                initial_difficulty: difficulty.into(),
            }),
        ),
    ];

    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid netupgrades");
    // Internally this calls Consensus::new, which processes the genesis block
    // This should succeed because TestChainConfig by default uses create_mainnet_genesis to
    // create the genesis_block, and this function creates a genesis block with
    // ConsensusData::None, which agrees with the net_upgrades we defined above.
    let chain_config = ConfigBuilder::test_chain().net_upgrades(net_upgrades).build();
    let mut tf = TestFramework::builder().with_chain_config(chain_config).build();

    let reward_lock_distance: i64 = tf
        .chainstate
        .get_chain_config()
        .get_proof_of_work_config()
        .reward_maturity_distance()
        .into();

    // Let's create a block with random (invalid) PoW data and see that it fails the consensus
    // checks
    let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let mut random_invalid_block = tf
        .make_block_builder()
        .with_reward(vec![TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(10)),
            OutputPurpose::LockThenTransfer(
                Destination::PublicKey(pub_key),
                OutputTimeLock::ForBlockCount(reward_lock_distance as u64),
            ),
        )])
        .add_test_transaction(&mut rng)
        .build();
    make_invalid_pow_block(&mut random_invalid_block, u128::MAX, difficulty.into())
        .expect("generate invalid block");
    assert!(matches!(
        tf.process_block(random_invalid_block.clone(), BlockSource::Local),
        Err(ChainstateError::ProcessBlockError(
            BlockError::CheckBlockFailed(CheckBlockError::ConsensusVerificationFailed(
                ConsensusVerificationError::PoWError(ConsensusPoWError::InvalidPoW(_))
            ))
        ))
    ));

    // Now let's actually mine the block, i.e. find valid PoW and see that consensus checks pass
    let mut valid_block = random_invalid_block;
    let bits = difficulty.into();
    assert!(consensus::pow::mine(&mut valid_block, u128::MAX, bits)
        .expect("Unexpected conversion error"));
    tf.process_block(valid_block.clone(), BlockSource::Local).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn read_block_reward_from_storage(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let ignore_consensus = BlockHeight::new(0);
    let pow_consensus = BlockHeight::new(1);
    let difficulty =
        Uint256([0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x0FFFFFFFFFFFFFFF]);

    let upgrades = vec![
        (
            ignore_consensus,
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            pow_consensus,
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoW {
                initial_difficulty: difficulty.into(),
            }),
        ),
    ];

    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid netupgrades");
    // Internally this calls Consensus::new, which processes the genesis block
    // This should succeed because TestChainConfig by default uses create_mainnet_genesis to
    // create the genesis_block, and this function creates a genesis block with
    // ConsensusData::None, which agrees with the net_upgrades we defined above.
    let chain_config = ConfigBuilder::test_chain().net_upgrades(net_upgrades).build();
    let mut tf = TestFramework::builder().with_chain_config(chain_config).build();

    let reward_lock_distance: i64 = tf
        .chainstate
        .get_chain_config()
        .get_proof_of_work_config()
        .reward_maturity_distance()
        .into();

    let block_reward_output_count = rng.gen::<usize>() % 20;
    let expected_block_reward = (0..block_reward_output_count)
        .map(|_| {
            let amount = Amount::from_atoms(rng.gen::<u128>() % 50);
            let pub_key = PrivateKey::new(KeyKind::RistrettoSchnorr).1;
            TxOutput::new(
                OutputValue::Coin(amount),
                OutputPurpose::LockThenTransfer(
                    Destination::PublicKey(pub_key),
                    OutputTimeLock::ForBlockCount(reward_lock_distance as u64),
                ),
            )
        })
        .collect::<Vec<_>>();

    // We generate a PoW block, then use its reward to test the storage of block rewards
    let block = {
        let mut random_invalid_block = tf
            .make_block_builder()
            .with_reward(expected_block_reward.clone())
            .add_test_transaction(&mut rng)
            .build();
        make_invalid_pow_block(&mut random_invalid_block, u128::MAX, difficulty.into())
            .expect("generate invalid block");

        let mut valid_block = random_invalid_block;
        let bits = difficulty.into();
        assert!(consensus::pow::mine(&mut valid_block, u128::MAX, bits)
            .expect("Unexpected conversion error"));
        valid_block
    };
    tf.process_block(block, BlockSource::Local).unwrap();

    let block_index = tf.chainstate.get_best_block_index().unwrap();
    let block_index = match block_index {
        GenBlockIndex::Block(bi) => bi,
        GenBlockIndex::Genesis(_) => unreachable!(),
    };

    {
        let block_reward = tf.chainstate.get_block_reward(&block_index).unwrap().unwrap();

        assert_eq!(block_reward.outputs(), expected_block_reward);
    }

    {
        let block_reward = tf.chainstate.get_block_reward(&block_index).unwrap().unwrap();

        assert_eq!(block_reward.outputs(), expected_block_reward);
    }
}

#[test]
fn blocks_from_the_future() {
    utils::concurrency::model(|| {
        // In this test, processing a few correct blocks in a single chain
        let config = create_unit_test_config();

        // current time is genesis time
        let current_time = Arc::new(std::sync::atomic::AtomicU64::new(
            config.genesis_block().timestamp().as_int_seconds() as u64,
        ));
        let chainstate_current_time = Arc::clone(&current_time);
        let time_getter = TimeGetter::new(Arc::new(move || {
            Duration::from_secs(chainstate_current_time.load(Ordering::SeqCst))
        }));
        let mut tf = TestFramework::builder()
            .with_chain_config(config)
            .with_time_getter(time_getter)
            .build();

        {
            // ensure no blocks are in chain, so that median time can be the genesis time
            let current_height: u64 =
                tf.chainstate.get_best_block_index().unwrap().block_height().into();
            assert_eq!(current_height, 0);
        }

        {
            // constrain the test to protect this test becoming legacy by changing the definition of median time for genesis
            assert_eq!(
                tf.chainstate.calculate_median_time_past(&tf.genesis().get_id().into()).unwrap(),
                tf.chainstate.get_chain_config().genesis_block().timestamp()
            );
        }

        {
            // submit a block on the threshold of being rejected for being from the future
            let max_future_offset =
                tf.chainstate.get_chain_config().max_future_block_time_offset().as_secs();

            tf.make_block_builder()
                .with_timestamp(BlockTimestamp::from_int_seconds(
                    current_time.load(Ordering::SeqCst) + max_future_offset,
                ))
                .build_and_process()
                .unwrap()
                .unwrap();
        }

        {
            // submit a block a second after the allowed threshold in the future
            let max_future_offset =
                tf.chainstate.get_chain_config().max_future_block_time_offset().as_secs();

            assert_eq!(
                tf.make_block_builder()
                    .with_timestamp(BlockTimestamp::from_int_seconds(
                        current_time.load(Ordering::SeqCst) + max_future_offset + 1,
                    ))
                    .build_and_process()
                    .unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                    CheckBlockError::BlockFromTheFuture
                ))
            );
        }

        {
            // submit a block one second before genesis in time
            assert_eq!(
                tf.make_block_builder()
                    .with_timestamp(BlockTimestamp::from_int_seconds(
                        current_time.load(Ordering::SeqCst) - 1
                    ))
                    .build_and_process()
                    .unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                    CheckBlockError::BlockTimeOrderInvalid
                ))
            );
        }
    });
}

#[test]
fn mainnet_initialization() {
    let chain_config = Arc::new(common::chain::config::create_mainnet());
    let chainstate_config = ChainstateConfig::new();
    let storage = TestStore::new_empty().unwrap();
    make_chainstate(
        chain_config,
        chainstate_config,
        storage,
        None,
        Default::default(),
    )
    .unwrap();
}

#[test]
fn empty_inputs_in_tx() {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();

        let first_tx = TransactionBuilder::new().build();
        let first_tx_id = first_tx.transaction().get_id();

        let block = tf.make_block_builder().with_transactions(vec![first_tx]).build();
        let block_id = block.get_id();
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::EmptyInputsOutputsInTransactionInBlock(
                        first_tx_id,
                        block_id
                    )
                )
            ))
        );
        assert_eq!(tf.best_block_id(), tf.genesis().get_id());
    });
}

#[test]
fn empty_outputs_in_tx() {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();

        let first_tx = TransactionBuilder::new()
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(1)),
                OutputPurpose::Transfer(anyonecanspend_address()),
            ))
            .build();
        let first_tx_id = first_tx.transaction().get_id();

        let block = tf.make_block_builder().with_transactions(vec![first_tx]).build();
        let block_id = block.get_id();
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::EmptyInputsOutputsInTransactionInBlock(
                        first_tx_id,
                        block_id
                    )
                )
            ))
        );
        assert_eq!(tf.best_block_id(), tf.genesis().get_id());
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn burn_inputs_in_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();

        let mut rng = make_seedable_rng(seed);
        let first_tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .build();
        let first_tx_id = first_tx.transaction().get_id();

        let block = tf.make_block_builder().with_transactions(vec![first_tx]).build();
        let block_id = block.get_id();
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::EmptyInputsOutputsInTransactionInBlock(
                        first_tx_id,
                        block_id
                    )
                )
            ))
        );
        assert_eq!(tf.best_block_id(), tf.genesis().get_id());
    });
}

fn make_invalid_pow_block(
    block: &mut Block,
    max_nonce: u128,
    bits: Compact,
) -> Result<bool, ConsensusPoWError> {
    let mut data = PoWData::new(bits, 0);
    for nonce in 0..max_nonce {
        data.update_nonce(nonce);
        block.update_consensus_data(ConsensusData::PoW(data.clone()));

        if !consensus::pow::check_proof_of_work(block.get_id().get(), bits)? {
            return Ok(true);
        }
    }

    Ok(false)
}
