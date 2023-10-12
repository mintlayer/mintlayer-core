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

use super::helpers::new_pub_key_destination;

use chainstate::chainstate_interface::ChainstateInterface;
use chainstate::{
    make_chainstate, BlockError, BlockSource, ChainstateConfig, ChainstateError, CheckBlockError,
    CheckBlockTransactionsError, ConnectTransactionError, DefaultTransactionVerificationStrategy,
    OrphanCheckError,
};
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, get_output_value, TestFramework, TestStore,
    TransactionBuilder,
};
use chainstate_types::{GenBlockIndex, GetAncestorError, PropertyQueryError};
use common::chain::{
    signed_transaction::SignedTransaction, stakelock::StakePoolData, Transaction, UtxoOutPoint,
};
use common::primitives::BlockDistance;
use common::{
    chain::{
        block::{consensus_data::PoWData, timestamp::BlockTimestamp, ConsensusData},
        config::{create_unit_test_config, Builder as ConfigBuilder},
        output_value::OutputValue,
        timelock::OutputTimeLock,
        Block, ConsensusUpgrade, Destination, GenBlock, NetUpgrades, OutPointSourceId,
        OutputSpentState, PoolId, TxInput, TxOutput,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Compact, Id, Idable, H256},
    Uint256,
};
use consensus::{ConsensusPoWError, ConsensusVerificationError};
use crypto::{
    key::{KeyKind, PrivateKey},
    random::Rng,
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use rstest::rstest;
use test_utils::mock_time_getter::mocked_time_getter_seconds;
use test_utils::random::{make_seedable_rng, Seed};
use tx_verifier::timelock_check::OutputMaturityError;
use utils::atomics::SeqCstAtomicU64;
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
        let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

        let coins = OutputValue::Coin(Amount::from_atoms(10));
        let destination =
            Destination::PublicKey(PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1);

        // Case 1: reward is a simple transfer
        let block = tf
            .make_block_builder()
            .with_reward(vec![TxOutput::Transfer(coins.clone(), destination.clone())])
            .add_test_transaction_from_best_block(&mut rng)
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
            .with_reward(vec![TxOutput::LockThenTransfer(
                coins.clone(),
                destination.clone(),
                OutputTimeLock::UntilHeight(BlockHeight::max()),
            )])
            .add_test_transaction_from_best_block(&mut rng)
            .build();

        let block_id = block.get_id();
        let outpoint = UtxoOutPoint::new(block_id.into(), 0);
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::BlockRewardMaturityError(
                    OutputMaturityError::InvalidOutputMaturitySettingType(outpoint)
                )
            ))
        );

        // Case 3: reward is locked until a specific time
        let block = tf
            .make_block_builder()
            .with_reward(vec![TxOutput::LockThenTransfer(
                coins.clone(),
                destination.clone(),
                OutputTimeLock::UntilTime(BlockTimestamp::from_int_seconds(u64::MAX)),
            )])
            .add_test_transaction_from_best_block(&mut rng)
            .build();

        let block_id = block.get_id();
        let outpoint = UtxoOutPoint::new(block_id.into(), 0);
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::BlockRewardMaturityError(
                    OutputMaturityError::InvalidOutputMaturitySettingType(outpoint)
                )
            ))
        );

        // Case 4: reward is locked for an amount of seconds
        let block = tf
            .make_block_builder()
            .with_reward(vec![TxOutput::LockThenTransfer(
                coins.clone(),
                destination.clone(),
                OutputTimeLock::ForSeconds(u64::MAX),
            )])
            .add_test_transaction_from_best_block(&mut rng)
            .build();

        let block_id = block.get_id();
        let outpoint = UtxoOutPoint::new(block_id.into(), 0);
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::BlockRewardMaturityError(
                    OutputMaturityError::InvalidOutputMaturitySettingType(outpoint)
                )
            ))
        );

        // Case 5: reward is locked for an invalid number
        let block = tf
            .make_block_builder()
            .with_reward(vec![TxOutput::LockThenTransfer(
                coins.clone(),
                destination.clone(),
                OutputTimeLock::ForBlockCount(u64::MAX),
            )])
            .add_test_transaction_from_best_block(&mut rng)
            .build();

        let block_id = block.get_id();
        let outpoint = UtxoOutPoint::new(block_id.into(), 0);
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::BlockRewardMaturityError(
                    OutputMaturityError::InvalidOutputMaturityDistanceValue(outpoint, u64::MAX)
                )
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
            .with_reward(vec![TxOutput::LockThenTransfer(
                coins.clone(),
                destination.clone(),
                OutputTimeLock::ForBlockCount(reward_lock_distance as u64 - 1),
            )])
            .add_test_transaction_from_best_block(&mut rng)
            .build();

        let block_id = block.get_id();
        let outpoint = UtxoOutPoint::new(block_id.into(), 0);
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::BlockRewardMaturityError(
                    OutputMaturityError::InvalidOutputMaturityDistance(
                        outpoint,
                        BlockDistance::new(reward_lock_distance - 1),
                        BlockDistance::new(reward_lock_distance)
                    )
                )
            ))
        );

        // Case 7: reward is a stake lock
        let decommission_destination = new_pub_key_destination(&mut rng);
        let (_, vrf_pub_key) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let pool_id = PoolId::new(H256::random_using(&mut rng));
        let block = tf
            .make_block_builder()
            .with_reward(vec![TxOutput::CreateStakePool(
                pool_id,
                Box::new(StakePoolData::new(
                    Amount::from_atoms(10),
                    anyonecanspend_address(),
                    vrf_pub_key,
                    decommission_destination,
                    PerThousand::new(0).unwrap(),
                    Amount::ZERO,
                )),
            )])
            .add_test_transaction_from_best_block(&mut rng)
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
            .with_reward(vec![TxOutput::LockThenTransfer(
                coins,
                destination,
                OutputTimeLock::ForBlockCount(reward_lock_distance as u64),
            )])
            .add_test_transaction_from_best_block(&mut rng)
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
        let mut tf = TestFramework::builder(&mut rng).build();
        assert_eq!(tf.best_block_id(), tf.genesis().get_id());

        // Prepare, but not process the block.
        let missing_block =
            tf.make_block_builder().add_test_transaction_from_best_block(&mut rng).build();

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
            .classify(tf.chainstate.get_chain_config())
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
        let mut tf = TestFramework::builder(&mut rng).build();

        // Check that genesis utxos are present in the utxo set
        let genesis_id = tf.genesis().get_id();
        for (idx, txo) in tf.genesis().utxos().iter().enumerate() {
            let idx = idx as u32;
            let utxo =
                tf.chainstate.utxo(&UtxoOutPoint::new(genesis_id.into(), idx)).unwrap().unwrap();
            assert_eq!(utxo.output(), txo);
            assert_eq!(utxo.source(), &UtxoSource::Blockchain(BlockHeight::new(0)));
        }

        // Create a new block
        let block = tf.make_block_builder().add_test_transaction_from_best_block(&mut rng).build();

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
                let outpoint = tx_in.utxo_outpoint().unwrap();
                if *tf.chainstate.get_chainstate_config().tx_index_enabled {
                    let prev_out_tx_index = tf
                        .chainstate
                        .get_mainchain_tx_index(&outpoint.source_id())
                        .unwrap()
                        .unwrap();
                    assert_eq!(
                        prev_out_tx_index.get_spent_state(outpoint.output_index()).unwrap(),
                        OutputSpentState::SpentBy(tx_id.into())
                    );
                }
                assert_eq!(tf.chainstate.utxo(outpoint), Ok(None))
            }
            // All the outputs of this transaction should be unspent
            let tx_index = tf.chainstate.get_mainchain_tx_index(&tx_id.into()).unwrap();
            if *tf.chainstate.get_chainstate_config().tx_index_enabled {
                let tx_index = tx_index.unwrap();
                for (idx, txo) in tx.transaction().outputs().iter().enumerate() {
                    let idx = idx as u32;
                    assert_eq!(
                        tx_index.get_spent_state(idx).unwrap(),
                        OutputSpentState::Unspent
                    );
                    let utxo =
                        tf.chainstate.utxo(&UtxoOutPoint::new(tx_id.into(), idx)).unwrap().unwrap();
                    assert_eq!(utxo.output(), txo);
                    assert_eq!(utxo.source(), &UtxoSource::Blockchain(BlockHeight::new(1)));
                }
            } else {
                assert!(tx_index.is_none());
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
        let mut tf = TestFramework::builder(&mut rng).build();

        // Transaction that spends the genesis reward
        let tx1 = SignedTransaction::new(
            Transaction::new(
                0,
                vec![TxInput::from_utxo(tf.genesis().get_id().into(), 0)],
                vec![TxOutput::Transfer(
                    get_output_value(&tf.genesis().utxos()[0]).unwrap(),
                    anyonecanspend_address(),
                )],
            )
            .unwrap(),
            vec![empty_witness(&mut rng)],
        )
        .expect("invalid witness count");
        let tx1_id = tx1.transaction().get_id();

        // Transaction that spends tx1
        let tx2 = SignedTransaction::new(
            Transaction::new(
                0,
                vec![TxInput::from_utxo(tx1_id.into(), 0)],
                vec![TxOutput::Transfer(
                    get_output_value(&tx1.transaction().outputs()[0]).unwrap(),
                    anyonecanspend_address(),
                )],
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
                ConnectTransactionError::MissingOutputOrSpent(UtxoOutPoint::new(tx1_id.into(), 0))
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
        let mut tf = TestFramework::builder(&mut rng).build();

        let genesis_index = tf
            .chainstate
            .get_gen_block_index(&tf.genesis().get_id().into())
            .unwrap()
            .unwrap();

        assert_eq!(tf.best_block_id(), tf.genesis().get_id());
        assert_eq!(genesis_index.chain_trust(), Uint256::ZERO);
        assert_eq!(genesis_index.block_height(), BlockHeight::new(0));

        let chain_config_clone = tf.chainstate.get_chain_config();
        let mut block_index =
            GenBlockIndex::Genesis(Arc::clone(chain_config_clone.genesis_block()));
        let mut prev_blk_id: Id<GenBlock> = tf.genesis().get_id().into();

        for _ in 0..rng.gen_range(100..200) {
            assert_eq!(tf.chainstate.get_best_block_id().unwrap(), prev_blk_id);
            let prev_block_id = block_index.block_id();
            let best_block_id = tf.best_block_id();
            assert_eq!(best_block_id, block_index.block_id());
            let new_block = tf
                .make_block_builder()
                .with_parent(prev_block_id)
                .add_test_transaction_with_parent(prev_block_id, &mut rng)
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
            prev_blk_id = new_block.get_id().into();
        }
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_ancestor_invalid_height(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = TestFramework::builder(&mut rng).build();
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
    let mut tf = TestFramework::builder(&mut rng).build();

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
                .unwrap_or_else(|_| panic!("Ancestor of height {i} not reached"))
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
    let mut tf = TestFramework::builder(&mut rng).build();

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
        (ignore_consensus, ConsensusUpgrade::IgnoreConsensus),
        (
            pow,
            ConsensusUpgrade::PoW {
                initial_difficulty: min_difficulty.into(),
            },
        ),
        (ignore_again, ConsensusUpgrade::IgnoreConsensus),
        (
            pow_again,
            ConsensusUpgrade::PoW {
                initial_difficulty: min_difficulty.into(),
            },
        ),
    ];

    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    // Internally this calls Consensus::new, which processes the genesis block
    // This should succeed because config::Builder by default uses create_mainnet_genesis to
    // create the genesis_block, and this function creates a genesis block with
    // ConsensusData::None, which agrees with the net_upgrades we defined above.
    let chain_config = ConfigBuilder::test_chain().consensus_upgrades(net_upgrades).build();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

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
            .add_test_transaction_from_best_block(&mut rng)
            .with_consensus_data(ConsensusData::PoW(Box::new(PoWData::new(Compact(0), 0))))
            .build_and_process()
            .unwrap_err(),
        ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
            CheckBlockError::ConsensusVerificationFailed(
                ConsensusVerificationError::ConsensusTypeMismatch(..)
            )
        ))
    ));

    // Create 4 more blocks with Consensus Now
    tf.create_chain(&tf.genesis().get_id().into(), 4, &mut rng)
        .expect("chain creation");

    // The next block will be at height 5, so it is expected to be a PoW block. Let's crate a block
    // with ConsensusData::None and see that adding it fails
    assert!(matches!(
        tf.make_block_builder()
            .add_test_transaction_from_best_block(&mut rng)
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
        let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let prev_block = tf.block(*tf.index_at(i - 1).block_id());
        let mined_block = tf
            .make_block_builder()
            .with_parent(prev_block.get_id().into())
            .with_reward(vec![TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(10)),
                Destination::PublicKey(pub_key),
                OutputTimeLock::ForBlockCount(reward_lock_distance as u64),
            )])
            .add_test_transaction_from_block(&prev_block, &mut rng)
            .build();
        let mut block_header = mined_block.header().clone();
        let bits = min_difficulty.into();
        assert_eq!(
            consensus::mine(
                block_header.header_mut().unwrap(),
                u128::MAX,
                bits,
                Arc::new(false.into())
            )
            .expect("Unexpected conversion error"),
            consensus::MiningResult::Success
        );
        let mined_block = Block::new_from_header(block_header, mined_block.body().clone()).unwrap();
        tf.process_block(mined_block, BlockSource::Local).unwrap();
    }

    // Block 10 should ignore consensus according to net upgrades. The following Pow block should
    // fail.
    let prev_block = tf.block(*tf.index_at(9).block_id());
    let mined_block = tf
        .make_block_builder()
        .with_parent(prev_block.get_id().into())
        .add_test_transaction_from_block(&prev_block, &mut rng)
        .build();
    let bits = min_difficulty.into();
    let mut block_header = mined_block.header().clone();
    assert_eq!(
        consensus::mine(
            block_header.header_mut().unwrap(),
            u128::MAX,
            bits,
            Arc::new(false.into())
        )
        .expect("Unexpected conversion error"),
        consensus::MiningResult::Success
    );
    let mined_block = Block::new_from_header(block_header, mined_block.body().clone()).unwrap();

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
        let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let prev_block = tf.block(*tf.index_at(i - 1).block_id());
        let mined_block = tf
            .make_block_builder()
            .with_parent(prev_block.get_id().into())
            .with_reward(vec![TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(10)),
                Destination::PublicKey(pub_key),
                OutputTimeLock::ForBlockCount(reward_lock_distance as u64),
            )])
            .add_test_transaction_from_block(&prev_block, &mut rng)
            .build();
        let bits = min_difficulty.into();
        let mut block_header = mined_block.header().clone();
        assert_eq!(
            consensus::mine(
                block_header.header_mut().unwrap(),
                u128::MAX,
                bits,
                Arc::new(false.into())
            )
            .expect("Unexpected conversion error"),
            consensus::MiningResult::Success
        );
        let mined_block = Block::new_from_header(block_header, mined_block.body().clone()).unwrap();
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
        (ignore_consensus, ConsensusUpgrade::IgnoreConsensus),
        (
            pow_consensus,
            ConsensusUpgrade::PoW {
                initial_difficulty: difficulty.into(),
            },
        ),
    ];

    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    // Internally this calls Consensus::new, which processes the genesis block
    // This should succeed because TestChainConfig by default uses create_mainnet_genesis to
    // create the genesis_block, and this function creates a genesis block with
    // ConsensusData::None, which agrees with the net_upgrades we defined above.
    let chain_config = ConfigBuilder::test_chain().consensus_upgrades(net_upgrades).build();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    let reward_lock_distance: i64 = tf
        .chainstate
        .get_chain_config()
        .get_proof_of_work_config()
        .reward_maturity_distance()
        .into();

    // Let's create a block with random (invalid) PoW data and see that it fails the consensus
    // checks
    let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let mut random_invalid_block = tf
        .make_block_builder()
        .with_reward(vec![TxOutput::LockThenTransfer(
            OutputValue::Coin(Amount::from_atoms(10)),
            Destination::PublicKey(pub_key),
            OutputTimeLock::ForBlockCount(reward_lock_distance as u64),
        )])
        .add_test_transaction_from_best_block(&mut rng)
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
    let valid_block = random_invalid_block;
    let bits = difficulty.into();
    let mut block_header = valid_block.header().clone();
    assert_eq!(
        consensus::mine(
            block_header.header_mut().unwrap(),
            u128::MAX,
            bits,
            Arc::new(false.into())
        )
        .expect("Unexpected conversion error"),
        consensus::MiningResult::Success
    );
    let valid_block = Block::new_from_header(block_header, valid_block.body().clone()).unwrap();
    tf.process_block(valid_block, BlockSource::Local).unwrap();
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
        (ignore_consensus, ConsensusUpgrade::IgnoreConsensus),
        (
            pow_consensus,
            ConsensusUpgrade::PoW {
                initial_difficulty: difficulty.into(),
            },
        ),
    ];

    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    // Internally this calls Consensus::new, which processes the genesis block
    // This should succeed because TestChainConfig by default uses create_mainnet_genesis to
    // create the genesis_block, and this function creates a genesis block with
    // ConsensusData::None, which agrees with the net_upgrades we defined above.
    let chain_config = ConfigBuilder::test_chain().consensus_upgrades(net_upgrades).build();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

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
            let pub_key = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1;
            TxOutput::LockThenTransfer(
                OutputValue::Coin(amount),
                Destination::PublicKey(pub_key),
                OutputTimeLock::ForBlockCount(reward_lock_distance as u64),
            )
        })
        .collect::<Vec<_>>();

    // We generate a PoW block, then use its reward to test the storage of block rewards
    let block = {
        let mut random_invalid_block = tf
            .make_block_builder()
            .with_reward(expected_block_reward.clone())
            .add_test_transaction_from_best_block(&mut rng)
            .build();
        make_invalid_pow_block(&mut random_invalid_block, u128::MAX, difficulty.into())
            .expect("generate invalid block");

        let valid_block = random_invalid_block;
        let bits = difficulty.into();
        let mut block_header = valid_block.header().clone();
        assert_eq!(
            consensus::mine(
                block_header.header_mut().unwrap(),
                u128::MAX,
                bits,
                Arc::new(false.into())
            )
            .expect("Unexpected conversion error"),
            consensus::MiningResult::Success
        );
        let valid_block = Block::new_from_header(block_header, valid_block.body().clone()).unwrap();
        valid_block
    };
    tf.process_block(block, BlockSource::Local).unwrap();

    let block_index = tf.chainstate.get_best_block_index().unwrap();
    let block_index = match block_index {
        GenBlockIndex::Block(bi) => bi,
        GenBlockIndex::Genesis(_) => unreachable!(),
    };

    let block_reward = tf.chainstate.get_block_reward(&block_index).unwrap().unwrap();
    assert_eq!(block_reward.outputs(), expected_block_reward);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn blocks_from_the_future(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        // In this test, processing a few correct blocks in a single chain
        let config = create_unit_test_config();

        // current time is genesis time
        let current_time = Arc::new(SeqCstAtomicU64::new(
            config.genesis_block().timestamp().as_int_seconds(),
        ));
        let time_getter = mocked_time_getter_seconds(Arc::clone(&current_time));
        let mut tf = TestFramework::builder(&mut rng)
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
                    current_time.load() + max_future_offset,
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
                        current_time.load() + max_future_offset + 1,
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
            assert!(matches!(
                tf.make_block_builder()
                    .with_timestamp(BlockTimestamp::from_int_seconds(current_time.load() - 1))
                    .build_and_process()
                    .unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                    CheckBlockError::BlockTimeOrderInvalid(_, _)
                ))
            ));
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
        DefaultTransactionVerificationStrategy::new(),
        None,
        Default::default(),
    )
    .unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn empty_inputs_in_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

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

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn empty_outputs_in_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let first_tx = TransactionBuilder::new()
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(1)),
                anyonecanspend_address(),
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
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let first_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
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
    let mut data = Box::new(PoWData::new(bits, 0));
    for nonce in 0..max_nonce {
        data.update_nonce(nonce);
        block
            .header_mut()
            .header_mut()
            .unwrap()
            .update_consensus_data(ConsensusData::PoW(data.clone()));

        if !consensus::check_proof_of_work(block.get_id().to_hash(), bits)? {
            return Ok(true);
        }
    }

    Ok(false)
}
