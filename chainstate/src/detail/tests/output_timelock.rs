use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use chainstate_storage::Store;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, Block},
        config::create_unit_test_config,
        signature::inputsig::InputWitness,
        timelock::OutputTimeLock,
        OutPointSourceId, OutputPurpose, Transaction, TxInput, TxOutput,
    },
    primitives::{time, Amount, BlockDistance, BlockHeight, Idable},
};

use crate::{
    detail::{
        median_time::calculate_median_time_past,
        spend_cache::error::StateUpdateError,
        tests::{anyonecanspend_address, ERR_CREATE_BLOCK_FAIL, ERR_CREATE_TX_FAIL},
    },
    BlockError, BlockSource, Chainstate, ChainstateConfig, TimeGetter,
};

#[test]
fn output_lock_until_height() {
    common::concurrency::model(|| {
        let chain_config = Arc::new(create_unit_test_config());
        let chainstate_config = ChainstateConfig::new();
        let storage = Store::new_empty().unwrap();
        let mut chainstate = Chainstate::new(
            chain_config,
            chainstate_config,
            storage,
            None,
            Default::default(),
        )
        .unwrap();

        let block_height_that_unlocks = 10;

        // create the first block, with a locked output
        let locked_output = add_block_with_locked_output(
            &mut chainstate,
            OutputTimeLock::UntilHeight(BlockHeight::new(block_height_that_unlocks)),
            BlockTimestamp::from_duration_since_epoch(time::get()),
        );

        // attempt to create the next block, and attempt to spend the locked output
        {
            let prev_block_id =
                chainstate.get_best_block_index().unwrap().unwrap().block_id().clone();

            let outputs = vec![TxOutput::new(
                Amount::from_atoms(5000),
                OutputPurpose::Transfer(anyonecanspend_address()),
            )];

            let inputs = vec![locked_output.clone()];

            let block = Block::new(
                vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
                Some(prev_block_id),
                BlockTimestamp::from_duration_since_epoch(time::get()),
                common::chain::block::ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);
            assert_eq!(
                chainstate.process_block(block, BlockSource::Local).unwrap_err(),
                BlockError::StateUpdateFailed(StateUpdateError::TimeLockViolation)
            );

            assert_eq!(
                chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                BlockHeight::new(1)
            );
        }

        // create another block, and spend the first input from the previous block
        {
            let prev_block_id =
                chainstate.get_block_id_from_height(&BlockHeight::new(1)).unwrap().unwrap();
            let prev_block = chainstate.get_block(prev_block_id).unwrap().unwrap();

            let outputs = vec![TxOutput::new(
                Amount::from_atoms(10000),
                OutputPurpose::Transfer(anyonecanspend_address()),
            )];

            let inputs = vec![TxInput::new(
                OutPointSourceId::Transaction(prev_block.transactions().get(0).unwrap().get_id()),
                0,
                InputWitness::NoSignature(None),
            )];

            let block = Block::new(
                vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
                Some(prev_block.get_id()),
                BlockTimestamp::from_duration_since_epoch(time::get()),
                common::chain::block::ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);
            chainstate.process_block(block, BlockSource::Local).unwrap();

            assert_eq!(
                chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                BlockHeight::new(2)
            );
        }

        // let's create more blocks until block_height_that_unlocks - 1, and always fail to spend, and build up the chain
        for height in 3..block_height_that_unlocks {
            assert_eq!(
                BlockHeight::new(height - 1),
                chainstate.get_best_block_index().unwrap().unwrap().block_height()
            );
            logging::log::info!("Submitting block of height: {}", height);
            let prev_block_id =
                chainstate.get_best_block_index().unwrap().unwrap().block_id().clone();

            // create another block, and spend the first input from the previous block
            {
                let outputs = vec![TxOutput::new(
                    Amount::from_atoms(5000),
                    OutputPurpose::Transfer(anyonecanspend_address()),
                )];

                let inputs = vec![locked_output.clone()];

                let block = Block::new(
                    vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
                    Some(prev_block_id.clone()),
                    BlockTimestamp::from_duration_since_epoch(time::get()),
                    common::chain::block::ConsensusData::None,
                )
                .expect(ERR_CREATE_BLOCK_FAIL);
                assert_eq!(
                    chainstate.process_block(block.clone(), BlockSource::Local).unwrap_err(),
                    BlockError::StateUpdateFailed(StateUpdateError::TimeLockViolation)
                );

                assert_eq!(
                    chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                    BlockHeight::new(height - 1)
                );
            }

            // create another block, with no transactions, and get the blockchain to progress
            {
                let block = Block::new(
                    vec![],
                    Some(prev_block_id),
                    BlockTimestamp::from_duration_since_epoch(time::get()),
                    common::chain::block::ConsensusData::None,
                )
                .expect(ERR_CREATE_BLOCK_FAIL);
                chainstate.process_block(block.clone(), BlockSource::Local).unwrap();

                assert_eq!(
                    chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                    BlockHeight::new(height)
                );
            }
        }

        // now we should be able to spend it at block_height_that_unlocks
        {
            let height = block_height_that_unlocks;
            let prev_block_id = chainstate
                .get_block_id_from_height(&BlockHeight::new(height - 1))
                .unwrap()
                .unwrap();

            let tip_id = chainstate.get_best_block_index().unwrap().unwrap().block_id().clone();
            assert_eq!(tip_id, prev_block_id);

            let outputs = vec![TxOutput::new(
                Amount::from_atoms(5000),
                OutputPurpose::Transfer(anyonecanspend_address()),
            )];

            let inputs = vec![locked_output];

            let block = Block::new(
                vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
                Some(prev_block_id),
                BlockTimestamp::from_duration_since_epoch(time::get()),
                common::chain::block::ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);

            chainstate.process_block(block, BlockSource::Local).unwrap();

            assert_eq!(
                chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                BlockHeight::new(height)
            );
        }
    });
}

#[test]
fn output_lock_until_height_but_spend_at_same_block() {
    common::concurrency::model(|| {
        let chain_config = Arc::new(create_unit_test_config());
        let chainstate_config = ChainstateConfig::new();
        let storage = Store::new_empty().unwrap();
        let mut chainstate = Chainstate::new(
            chain_config,
            chainstate_config,
            storage,
            None,
            Default::default(),
        )
        .unwrap();

        let block_height_that_unlocks = 10;

        // create the first block, with a locked output
        {
            let prev_block = chainstate.chain_config.genesis_block();

            let outputs1 = vec![
                TxOutput::new(
                    Amount::from_atoms(100000),
                    OutputPurpose::Transfer(anyonecanspend_address()),
                ),
                TxOutput::new(
                    Amount::from_atoms(100000),
                    OutputPurpose::LockThenTransfer(
                        anyonecanspend_address(),
                        OutputTimeLock::UntilHeight(BlockHeight::new(block_height_that_unlocks)),
                    ),
                ),
            ];
            let inputs1 = vec![TxInput::new(
                OutPointSourceId::Transaction(prev_block.transactions().get(0).unwrap().get_id()),
                0,
                InputWitness::NoSignature(None),
            )];
            let tx1 = Transaction::new(0, inputs1, outputs1, 0).expect(ERR_CREATE_TX_FAIL);

            let outputs2 = vec![TxOutput::new(
                Amount::from_atoms(50000),
                OutputPurpose::Transfer(anyonecanspend_address()),
            )];
            let inputs2 = vec![TxInput::new(
                OutPointSourceId::Transaction(tx1.get_id()),
                1,
                InputWitness::NoSignature(None),
            )];
            let tx2 = Transaction::new(0, inputs2, outputs2, 0).expect(ERR_CREATE_TX_FAIL);

            let block = Block::new(
                vec![tx1, tx2],
                Some(prev_block.get_id()),
                BlockTimestamp::from_duration_since_epoch(time::get()),
                common::chain::block::ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);
            assert_eq!(
                chainstate.process_block(block, BlockSource::Local).unwrap_err(),
                BlockError::StateUpdateFailed(StateUpdateError::TimeLockViolation)
            );

            assert_eq!(
                chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                BlockHeight::new(0)
            );
        }
    });
}

#[test]
fn output_lock_for_block_count() {
    common::concurrency::model(|| {
        let chain_config = Arc::new(create_unit_test_config());
        let chainstate_config = ChainstateConfig::new();
        let storage = Store::new_empty().unwrap();
        let mut chainstate = Chainstate::new(
            chain_config,
            chainstate_config,
            storage,
            None,
            Default::default(),
        )
        .unwrap();

        let block_count_that_unlocks = 20;
        let block_height_with_locked_output = 1;

        // create the first block, with a locked output
        let locked_output = add_block_with_locked_output(
            &mut chainstate,
            OutputTimeLock::ForBlockCount(block_count_that_unlocks),
            BlockTimestamp::from_duration_since_epoch(time::get()),
        );

        // attempt to create the next block, and attempt to spend the locked output
        {
            let prev_block_id =
                chainstate.get_best_block_index().unwrap().unwrap().block_id().clone();

            let outputs = vec![TxOutput::new(
                Amount::from_atoms(5000),
                OutputPurpose::Transfer(anyonecanspend_address()),
            )];

            let inputs = vec![locked_output.clone()];

            let block = Block::new(
                vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
                Some(prev_block_id),
                BlockTimestamp::from_duration_since_epoch(time::get()),
                common::chain::block::ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);
            assert_eq!(
                chainstate.process_block(block, BlockSource::Local).unwrap_err(),
                BlockError::StateUpdateFailed(StateUpdateError::TimeLockViolation)
            );

            assert_eq!(
                chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                BlockHeight::new(1)
            );
        }

        // create another block, and spend the first input from the previous block
        {
            let prev_block_id =
                chainstate.get_best_block_index().unwrap().unwrap().block_id().clone();
            let prev_block = chainstate.get_block(prev_block_id).unwrap().unwrap();

            let outputs = vec![TxOutput::new(
                Amount::from_atoms(10000),
                OutputPurpose::Transfer(anyonecanspend_address()),
            )];

            let inputs = vec![TxInput::new(
                OutPointSourceId::Transaction(prev_block.transactions().get(0).unwrap().get_id()),
                0,
                InputWitness::NoSignature(None),
            )];

            let block = Block::new(
                vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
                Some(prev_block.get_id()),
                BlockTimestamp::from_duration_since_epoch(time::get()),
                common::chain::block::ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);
            chainstate.process_block(block, BlockSource::Local).unwrap();

            assert_eq!(
                chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                BlockHeight::new(2)
            );
        }

        // let's create more blocks until block_count_that_unlocks + block_height_with_locked_output, and always fail to spend, and build up the chain
        for height in 3..block_count_that_unlocks + block_height_with_locked_output {
            assert_eq!(
                BlockHeight::new(height - 1),
                chainstate.get_best_block_index().unwrap().unwrap().block_height()
            );
            logging::log::info!("Submitting block of height: {}", height);
            let prev_block_id =
                chainstate.get_best_block_index().unwrap().unwrap().block_id().clone();
            // create another block, and spend the first input from the previous block
            {
                let outputs = vec![TxOutput::new(
                    Amount::from_atoms(5000),
                    OutputPurpose::Transfer(anyonecanspend_address()),
                )];

                let inputs = vec![locked_output.clone()];

                let block = Block::new(
                    vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
                    Some(prev_block_id.clone()),
                    BlockTimestamp::from_duration_since_epoch(time::get()),
                    common::chain::block::ConsensusData::None,
                )
                .expect(ERR_CREATE_BLOCK_FAIL);
                assert_eq!(
                    chainstate.process_block(block.clone(), BlockSource::Local).unwrap_err(),
                    BlockError::StateUpdateFailed(StateUpdateError::TimeLockViolation)
                );

                assert_eq!(
                    chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                    BlockHeight::new(height - 1)
                );
            }

            // create another block, with no transactions, and get the blockchain to progress
            {
                let block = Block::new(
                    vec![],
                    Some(prev_block_id),
                    BlockTimestamp::from_duration_since_epoch(time::get()),
                    common::chain::block::ConsensusData::None,
                )
                .expect(ERR_CREATE_BLOCK_FAIL);
                chainstate.process_block(block.clone(), BlockSource::Local).unwrap();

                assert_eq!(
                    chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                    BlockHeight::new(height)
                );
            }
        }

        // now we should be able to spend it at block_count_that_unlocks
        {
            let height = block_count_that_unlocks + block_height_with_locked_output;
            let prev_block_id = chainstate
                .get_block_id_from_height(&BlockHeight::new(height - 1))
                .unwrap()
                .unwrap();

            let outputs = vec![TxOutput::new(
                Amount::from_atoms(5000),
                OutputPurpose::Transfer(anyonecanspend_address()),
            )];

            let inputs = vec![locked_output];

            let block = Block::new(
                vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
                Some(prev_block_id),
                BlockTimestamp::from_duration_since_epoch(time::get()),
                common::chain::block::ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);

            chainstate.process_block(block, BlockSource::Local).unwrap();

            assert_eq!(
                chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                BlockHeight::new(height)
            );
        }
    });
}

#[test]
fn output_lock_for_block_count_but_spend_at_same_block() {
    common::concurrency::model(|| {
        let chain_config = Arc::new(create_unit_test_config());
        let chainstate_config = ChainstateConfig::new();
        let storage = Store::new_empty().unwrap();
        let mut chainstate = Chainstate::new(
            chain_config,
            chainstate_config,
            storage,
            None,
            Default::default(),
        )
        .unwrap();

        let block_count_that_unlocks = 10;

        // create the first block, with a locked output
        {
            let prev_block = chainstate.chain_config.genesis_block();

            let outputs1 = vec![
                TxOutput::new(
                    Amount::from_atoms(100000),
                    OutputPurpose::Transfer(anyonecanspend_address()),
                ),
                TxOutput::new(
                    Amount::from_atoms(100000),
                    OutputPurpose::LockThenTransfer(
                        anyonecanspend_address(),
                        OutputTimeLock::ForBlockCount(block_count_that_unlocks),
                    ),
                ),
            ];
            let inputs1 = vec![TxInput::new(
                OutPointSourceId::Transaction(prev_block.transactions().get(0).unwrap().get_id()),
                0,
                InputWitness::NoSignature(None),
            )];
            let tx1 = Transaction::new(0, inputs1, outputs1, 0).expect(ERR_CREATE_TX_FAIL);

            let outputs2 = vec![TxOutput::new(
                Amount::from_atoms(50000),
                OutputPurpose::Transfer(anyonecanspend_address()),
            )];
            let inputs2 = vec![TxInput::new(
                OutPointSourceId::Transaction(tx1.get_id()),
                1,
                InputWitness::NoSignature(None),
            )];
            let tx2 = Transaction::new(0, inputs2, outputs2, 0).expect(ERR_CREATE_TX_FAIL);

            let block = Block::new(
                vec![tx1, tx2],
                Some(prev_block.get_id()),
                BlockTimestamp::from_duration_since_epoch(time::get()),
                common::chain::block::ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);
            assert_eq!(
                chainstate.process_block(block, BlockSource::Local).unwrap_err(),
                BlockError::StateUpdateFailed(StateUpdateError::TimeLockViolation)
            );

            assert_eq!(
                chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                BlockHeight::new(0)
            );
        }
    });
}

#[test]
fn output_lock_for_block_count_attempted_overflow() {
    common::concurrency::model(|| {
        let chain_config = Arc::new(create_unit_test_config());
        let chainstate_config = ChainstateConfig::new();
        let storage = Store::new_empty().unwrap();
        let mut chainstate = Chainstate::new(
            chain_config,
            chainstate_config,
            storage,
            None,
            Default::default(),
        )
        .unwrap();

        let block_count_that_unlocks = u64::MAX;

        // create the first block, with a locked output
        let locked_output = add_block_with_locked_output(
            &mut chainstate,
            OutputTimeLock::ForBlockCount(block_count_that_unlocks),
            BlockTimestamp::from_duration_since_epoch(time::get()),
        );

        // attempt to create the next block, and attempt to spend the locked output
        {
            let prev_block_id =
                chainstate.get_best_block_index().unwrap().unwrap().block_id().clone();

            let outputs = vec![TxOutput::new(
                Amount::from_atoms(5000),
                OutputPurpose::Transfer(anyonecanspend_address()),
            )];

            let inputs = vec![locked_output];

            let block = Block::new(
                vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
                Some(prev_block_id),
                BlockTimestamp::from_duration_since_epoch(time::get()),
                common::chain::block::ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);
            assert_eq!(
                chainstate.process_block(block, BlockSource::Local).unwrap_err(),
                BlockError::StateUpdateFailed(StateUpdateError::BlockHeightArithmeticError)
            );

            assert_eq!(
                chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                BlockHeight::new(1)
            );
        }
    });
}

#[test]
fn output_lock_until_time() {
    common::concurrency::model(|| {
        let chain_config = Arc::new(create_unit_test_config());
        let chainstate_config = ChainstateConfig::new();
        let storage = Store::new_empty().unwrap();
        let current_time = Arc::new(AtomicU64::new(1));
        let current_time_ = Arc::clone(&current_time);
        let time_getter = TimeGetter::new(Arc::new(move || {
            Duration::from_secs(current_time_.load(Ordering::SeqCst))
        }));
        let mut chainstate =
            Chainstate::new(chain_config, chainstate_config, storage, None, time_getter).unwrap();

        let genesis_timestamp = chainstate.chain_config.genesis_block().timestamp();
        let lock_time = genesis_timestamp.as_int_seconds() + 4;
        let block_times: Vec<_> = itertools::iterate(genesis_timestamp.as_int_seconds(), |t| t + 1)
            .take(8)
            .collect();
        // Check that without the last block the output remains locked.
        assert_eq!(
            median_block_time(&block_times[..block_times.len() - 1]),
            lock_time - 1
        );
        // Check that the last block allows to unlock the output.
        assert_eq!(median_block_time(&block_times), lock_time);

        current_time.store(*block_times.last().unwrap(), Ordering::SeqCst);

        let expected_height = 1;
        let locked_output = add_block_with_locked_output(
            &mut chainstate,
            OutputTimeLock::UntilTime(BlockTimestamp::from_int_seconds(lock_time)),
            BlockTimestamp::from_int_seconds(block_times[expected_height]),
        );
        assert_eq!(
            chainstate.get_best_block_index().unwrap().unwrap().block_height(),
            BlockHeight::new(expected_height as u64),
        );

        // Skip the genesis block and the block that contains the locked output.
        for (block_time, height) in block_times.iter().skip(2).zip(expected_height..) {
            let prev_block_id =
                chainstate.get_best_block_index().unwrap().unwrap().block_id().clone();

            assert_eq!(
                calculate_median_time_past(
                    &chainstate.make_db_tx_ro(),
                    chainstate.get_best_block_index().unwrap().unwrap().block_id()
                )
                .as_int_seconds(),
                median_block_time(&block_times[..=height])
            );

            // Check that the output still cannot be spent.
            {
                let outputs = vec![TxOutput::new(
                    Amount::from_atoms(5000),
                    OutputPurpose::Transfer(anyonecanspend_address()),
                )];

                let inputs = vec![locked_output.clone()];

                let block = Block::new(
                    vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
                    Some(prev_block_id.clone()),
                    BlockTimestamp::from_int_seconds(*block_time),
                    common::chain::block::ConsensusData::None,
                )
                .expect(ERR_CREATE_BLOCK_FAIL);
                assert_eq!(
                    chainstate.process_block(block.clone(), BlockSource::Local).unwrap_err(),
                    BlockError::StateUpdateFailed(StateUpdateError::TimeLockViolation)
                );

                assert_eq!(
                    chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                    BlockHeight::new(height as u64),
                );
            }

            // Create another block, with no transactions, and get the blockchain to progress.
            {
                let block = Block::new(
                    vec![],
                    Some(prev_block_id),
                    BlockTimestamp::from_int_seconds(*block_time),
                    common::chain::block::ConsensusData::None,
                )
                .expect(ERR_CREATE_BLOCK_FAIL);
                chainstate.process_block(block.clone(), BlockSource::Local).unwrap();

                assert_eq!(
                    chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                    BlockHeight::new(height as u64 + 1),
                );
            }
        }

        // Check that the output can now be spent.
        {
            let prev_block_id =
                chainstate.get_best_block_index().unwrap().unwrap().block_id().clone();

            let outputs = vec![TxOutput::new(
                Amount::from_atoms(5000),
                OutputPurpose::Transfer(anyonecanspend_address()),
            )];

            let inputs = vec![locked_output];

            let block = Block::new(
                vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
                Some(prev_block_id),
                // The block that is being validated isn't taken into account when calculating the
                // median time, so any time can be used here.
                BlockTimestamp::from_int_seconds(*block_times.last().unwrap()),
                common::chain::block::ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);

            chainstate.process_block(block, BlockSource::Local).unwrap();

            assert_eq!(
                chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                BlockHeight::new(block_times.len() as u64)
            );
        }
    });
}

#[test]
fn output_lock_until_time_but_spend_at_same_block() {
    common::concurrency::model(|| {
        let chain_config = Arc::new(create_unit_test_config());
        let chainstate_config = ChainstateConfig::new();
        let storage = Store::new_empty().unwrap();
        let mut chainstate = Chainstate::new(
            chain_config,
            chainstate_config,
            storage,
            None,
            Default::default(),
        )
        .unwrap();

        let genesis_timestamp = chainstate.chain_config.genesis_block().timestamp();
        let lock_time = genesis_timestamp.as_int_seconds() + 3;

        // create the first block, with a locked output
        {
            let prev_block = chainstate.chain_config.genesis_block();

            let outputs1 = vec![
                TxOutput::new(
                    Amount::from_atoms(100000),
                    OutputPurpose::Transfer(anyonecanspend_address()),
                ),
                TxOutput::new(
                    Amount::from_atoms(100000),
                    OutputPurpose::LockThenTransfer(
                        anyonecanspend_address(),
                        OutputTimeLock::UntilTime(BlockTimestamp::from_int_seconds(lock_time)),
                    ),
                ),
            ];
            let inputs1 = vec![TxInput::new(
                OutPointSourceId::Transaction(prev_block.transactions().get(0).unwrap().get_id()),
                0,
                InputWitness::NoSignature(None),
            )];
            let tx1 = Transaction::new(0, inputs1, outputs1, 0).expect(ERR_CREATE_TX_FAIL);

            let outputs2 = vec![TxOutput::new(
                Amount::from_atoms(50000),
                OutputPurpose::Transfer(anyonecanspend_address()),
            )];
            let inputs2 = vec![TxInput::new(
                OutPointSourceId::Transaction(tx1.get_id()),
                1,
                InputWitness::NoSignature(None),
            )];
            let tx2 = Transaction::new(0, inputs2, outputs2, 0).expect(ERR_CREATE_TX_FAIL);

            let block = Block::new(
                vec![tx1, tx2],
                Some(prev_block.get_id()),
                BlockTimestamp::from_duration_since_epoch(time::get()),
                common::chain::block::ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);
            assert_eq!(
                chainstate.process_block(block, BlockSource::Local).unwrap_err(),
                BlockError::StateUpdateFailed(StateUpdateError::TimeLockViolation)
            );

            assert_eq!(
                chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                BlockHeight::new(0)
            );
        }
    });
}

#[test]
fn output_lock_for_seconds() {
    common::concurrency::model(|| {
        let chain_config = Arc::new(create_unit_test_config());
        let chainstate_config = ChainstateConfig::new();
        let storage = Store::new_empty().unwrap();
        let current_time = Arc::new(AtomicU64::new(1));
        let current_time_ = Arc::clone(&current_time);
        let time_getter = TimeGetter::new(Arc::new(move || {
            Duration::from_secs(current_time_.load(Ordering::SeqCst))
        }));
        let mut chainstate =
            Chainstate::new(chain_config, chainstate_config, storage, None, time_getter).unwrap();

        let genesis_timestamp = chainstate.chain_config.genesis_block().timestamp();
        let block_times: Vec<_> = itertools::iterate(genesis_timestamp.as_int_seconds(), |t| t + 1)
            .take(8)
            .collect();
        let lock_seconds = 3;
        let unlock_time = block_times[1] + lock_seconds;
        // Check that without the last block the output remains locked.
        assert_eq!(
            median_block_time(&block_times[..block_times.len() - 1]),
            unlock_time - 1
        );
        // Check that the last block allows to unlock the output.
        assert_eq!(median_block_time(&block_times), unlock_time);

        current_time.store(*block_times.last().unwrap(), Ordering::SeqCst);

        let expected_height = 1;
        let locked_output = add_block_with_locked_output(
            &mut chainstate,
            OutputTimeLock::ForSeconds(lock_seconds),
            BlockTimestamp::from_int_seconds(block_times[expected_height]),
        );
        assert_eq!(
            chainstate.get_best_block_index().unwrap().unwrap().block_height(),
            BlockHeight::new(expected_height as u64),
        );

        // Skip the genesis block and the block that contains the locked output.
        for (block_time, height) in block_times.iter().skip(2).zip(expected_height..) {
            let prev_block_id =
                chainstate.get_best_block_index().unwrap().unwrap().block_id().clone();

            assert_eq!(
                calculate_median_time_past(
                    &chainstate.make_db_tx_ro(),
                    chainstate.get_best_block_index().unwrap().unwrap().block_id()
                )
                .as_int_seconds(),
                median_block_time(&block_times[..=height])
            );

            // Check that the output still cannot be spent.
            {
                let outputs = vec![TxOutput::new(
                    Amount::from_atoms(5000),
                    OutputPurpose::Transfer(anyonecanspend_address()),
                )];

                let inputs = vec![locked_output.clone()];

                let block = Block::new(
                    vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
                    Some(prev_block_id.clone()),
                    BlockTimestamp::from_int_seconds(*block_time),
                    common::chain::block::ConsensusData::None,
                )
                .expect(ERR_CREATE_BLOCK_FAIL);
                assert_eq!(
                    chainstate.process_block(block.clone(), BlockSource::Local).unwrap_err(),
                    BlockError::StateUpdateFailed(StateUpdateError::TimeLockViolation)
                );

                assert_eq!(
                    chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                    BlockHeight::new(height as u64),
                );
            }

            // Create another block, with no transactions, and get the blockchain to progress.
            {
                let block = Block::new(
                    vec![],
                    Some(prev_block_id),
                    BlockTimestamp::from_int_seconds(*block_time),
                    common::chain::block::ConsensusData::None,
                )
                .expect(ERR_CREATE_BLOCK_FAIL);
                chainstate.process_block(block.clone(), BlockSource::Local).unwrap();

                assert_eq!(
                    chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                    BlockHeight::new(height as u64 + 1),
                );
            }
        }

        // Check that the output can now be spent.
        {
            let prev_block_id =
                chainstate.get_best_block_index().unwrap().unwrap().block_id().clone();

            let outputs = vec![TxOutput::new(
                Amount::from_atoms(5000),
                OutputPurpose::Transfer(anyonecanspend_address()),
            )];

            let inputs = vec![locked_output];

            let block = Block::new(
                vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
                Some(prev_block_id),
                // The block that is being validated isn't taken into account when calculating the
                // median time, so any time can be used here.
                BlockTimestamp::from_int_seconds(*block_times.last().unwrap()),
                common::chain::block::ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);

            chainstate.process_block(block, BlockSource::Local).unwrap();

            assert_eq!(
                chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                BlockHeight::new(block_times.len() as u64)
            );
        }
    });
}

#[test]
fn output_lock_for_seconds_but_spend_at_same_block() {
    common::concurrency::model(|| {
        let chain_config = Arc::new(create_unit_test_config());
        let chainstate_config = ChainstateConfig::new();
        let storage = Store::new_empty().unwrap();
        let mut chainstate = Chainstate::new(
            chain_config,
            chainstate_config,
            storage,
            None,
            Default::default(),
        )
        .unwrap();

        // create the first block, with a locked output
        {
            let prev_block = chainstate.chain_config.genesis_block();

            let outputs1 = vec![
                TxOutput::new(
                    Amount::from_atoms(100000),
                    OutputPurpose::Transfer(anyonecanspend_address()),
                ),
                TxOutput::new(
                    Amount::from_atoms(100000),
                    OutputPurpose::LockThenTransfer(
                        anyonecanspend_address(),
                        OutputTimeLock::ForSeconds(100),
                    ),
                ),
            ];
            let inputs1 = vec![TxInput::new(
                OutPointSourceId::Transaction(prev_block.transactions().get(0).unwrap().get_id()),
                0,
                InputWitness::NoSignature(None),
            )];
            let tx1 = Transaction::new(0, inputs1, outputs1, 0).expect(ERR_CREATE_TX_FAIL);

            let outputs2 = vec![TxOutput::new(
                Amount::from_atoms(50000),
                OutputPurpose::Transfer(anyonecanspend_address()),
            )];
            let inputs2 = vec![TxInput::new(
                OutPointSourceId::Transaction(tx1.get_id()),
                1,
                InputWitness::NoSignature(None),
            )];
            let tx2 = Transaction::new(0, inputs2, outputs2, 0).expect(ERR_CREATE_TX_FAIL);

            let block = Block::new(
                vec![tx1, tx2],
                Some(prev_block.get_id()),
                BlockTimestamp::from_duration_since_epoch(time::get()),
                common::chain::block::ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);
            assert_eq!(
                chainstate.process_block(block, BlockSource::Local).unwrap_err(),
                BlockError::StateUpdateFailed(StateUpdateError::TimeLockViolation)
            );

            assert_eq!(
                chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                BlockHeight::new(0)
            );
        }
    });
}

#[test]
fn output_lock_for_seconds_attempted_overflow() {
    common::concurrency::model(|| {
        let chain_config = Arc::new(create_unit_test_config());
        let chainstate_config = ChainstateConfig::new();
        let storage = Store::new_empty().unwrap();
        let mut chainstate = Chainstate::new(
            chain_config,
            chainstate_config,
            storage,
            None,
            Default::default(),
        )
        .unwrap();

        // create the first block, with a locked output
        let locked_output = add_block_with_locked_output(
            &mut chainstate,
            OutputTimeLock::ForSeconds(u64::MAX),
            BlockTimestamp::from_duration_since_epoch(time::get()),
        );

        // attempt to create the next block, and attempt to spend the locked output
        {
            let prev_block_id =
                chainstate.get_best_block_index().unwrap().unwrap().block_id().clone();
            let prev_block = chainstate.get_block(prev_block_id).unwrap().unwrap();

            let outputs = vec![TxOutput::new(
                Amount::from_atoms(5000),
                OutputPurpose::Transfer(anyonecanspend_address()),
            )];

            let inputs = vec![locked_output];

            let block = Block::new(
                vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
                Some(prev_block.get_id()),
                BlockTimestamp::from_duration_since_epoch(time::get()),
                common::chain::block::ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);
            assert_eq!(
                chainstate.process_block(block, BlockSource::Local).unwrap_err(),
                BlockError::StateUpdateFailed(StateUpdateError::BlockTimestampArithmeticError)
            );

            assert_eq!(
                chainstate.get_best_block_index().unwrap().unwrap().block_height(),
                BlockHeight::new(1)
            );
        }
    });
}

/// Adds a block with the locked output and returns input corresponding to this output.
fn add_block_with_locked_output(
    chainstate: &mut Chainstate,
    output_time_lock: OutputTimeLock,
    timestamp: BlockTimestamp,
) -> TxInput {
    // Find the last block.
    let current_height = chainstate.get_best_block_index().unwrap().unwrap().block_height();
    let prev_block_id = chainstate.get_block_id_from_height(&current_height).unwrap().unwrap();
    let prev_block = chainstate.get_block(prev_block_id).unwrap().unwrap();

    // Create and add a new block.
    let outputs = vec![
        TxOutput::new(
            Amount::from_atoms(100000),
            OutputPurpose::Transfer(anyonecanspend_address()),
        ),
        TxOutput::new(
            Amount::from_atoms(100000),
            OutputPurpose::LockThenTransfer(anyonecanspend_address(), output_time_lock),
        ),
    ];

    let inputs = vec![TxInput::new(
        OutPointSourceId::Transaction(prev_block.transactions().get(0).unwrap().get_id()),
        0,
        InputWitness::NoSignature(None),
    )];

    let block = Block::new(
        vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
        Some(prev_block.get_id()),
        timestamp,
        common::chain::block::ConsensusData::None,
    )
    .expect(ERR_CREATE_BLOCK_FAIL);
    let new_height = (current_height + BlockDistance::new(1)).unwrap();
    chainstate.process_block(block, BlockSource::Local).unwrap();
    assert_eq!(
        chainstate.get_best_block_index().unwrap().unwrap().block_height(),
        new_height,
    );

    let block_id = chainstate.get_block_id_from_height(&new_height).unwrap().unwrap();
    let block = chainstate.get_block(block_id).unwrap().unwrap();
    TxInput::new(
        OutPointSourceId::Transaction(block.transactions().get(0).unwrap().get_id()),
        1,
        InputWitness::NoSignature(None),
    )
}

fn median_block_time(times: &[u64]) -> u64 {
    // Only the last 11 blocks are used for calculating the median time.
    assert!(times.len() < 11);
    *times.iter().nth(times.len() / 2).unwrap()
}
