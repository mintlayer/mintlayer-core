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

use chainstate::ChainstateHandle;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward},
        Block, ChainConfig,
    },
    primitives::{BlockHeight, Id, Idable},
    time_getter::TimeGetter,
};
use logging::log;
use mempool::{
    tx_accumulator::{DefaultTxAccumulator, TransactionAccumulator},
    MempoolHandle,
};
use utils::tap_error_log::LogError;

use crate::BlockProductionError;

pub enum BlockMakerControlCommand {
    NewTip(Id<Block>, BlockHeight),
    Stop,
}

/// Slave to the [PerpetualBlockBuilder]. Every new block tip gets one Block Maker, and keeps running
/// until either it's successful in submitting a block, or there's a new tip in chainstate, deeming
/// the effort pointless
pub struct BlockMaker {
    chain_config: Arc<ChainConfig>,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    time_getter: TimeGetter,
    current_tip_id: Id<Block>,
    current_tip_height: BlockHeight,
    block_maker_rx: crossbeam_channel::Receiver<BlockMakerControlCommand>,
}

#[must_use]
enum BlockSubmitResult {
    Failed,
    Success,
}

impl BlockMaker {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        chainstate_handle: ChainstateHandle,
        mempool_handle: MempoolHandle,
        time_getter: TimeGetter,
        current_tip_id: Id<Block>,
        current_tip_height: BlockHeight,
        block_maker_rx: crossbeam_channel::Receiver<BlockMakerControlCommand>,
    ) -> Self {
        Self {
            chain_config,
            chainstate_handle,
            mempool_handle,
            time_getter,
            current_tip_id,
            current_tip_height,
            block_maker_rx,
        }
    }

    pub async fn collect_transactions(
        &self,
    ) -> Result<Box<dyn TransactionAccumulator>, BlockProductionError> {
        let max_block_size = self.chain_config.max_block_size_from_txs();
        let returned_accumulator = self
            .mempool_handle
            .call_async(move |mempool| {
                mempool.collect_txs(Box::new(DefaultTxAccumulator::new(max_block_size)))
            })
            .await?
            .map_err(|_| BlockProductionError::MempoolChannelClosed)?;
        Ok(returned_accumulator)
    }

    pub fn make_block(
        &self,
        current_tip_id: Id<Block>,
        accumulator: &dyn TransactionAccumulator,
    ) -> Result<Block, BlockProductionError> {
        // TODO: this isn't efficient. We have to create the header first, then see if it obeys consensus rules, then construct the full block
        let current_time = self.time_getter.get_time();
        let block = Block::new(
            accumulator.transactions().clone(),
            current_tip_id.into(),
            BlockTimestamp::from_duration_since_epoch(current_time),
            common::chain::block::ConsensusData::None,
            BlockReward::new(vec![]), // TODO: define consensus and rewards through NetworkUpgrades
        )?;
        Ok(block)
    }

    async fn attempt_submit_new_block(
        &mut self,
        block: Block,
    ) -> Result<BlockSubmitResult, BlockProductionError> {
        let block_check_result = self
            .chainstate_handle
            .call(|chainstate| chainstate.preliminary_block_check(block))
            .await
            .log_err()?;
        if let Ok(block) = block_check_result {
            let block_id = block.get_id();
            let block_submit_result = self
                .chainstate_handle
                .call_mut(|chainstate| {
                    chainstate.process_block(block, chainstate::BlockSource::Local)
                })
                .await
                .log_err()?;
            if let Ok(_new_block_index) = block_submit_result {
                log::info!(
                "Success in submitting block {} at height {}. Exiting Block Maker at tip {} and height {}",
                block_id,
                self.current_tip_height.next_height(),
                self.current_tip_id,
                self.current_tip_height
            );
                return Ok(BlockSubmitResult::Success);
            }
        }

        Ok(BlockSubmitResult::Failed)
    }

    /// Keeps trying to construct a new block, until one of two things happen:
    /// 1. A new block is successfully created and is submitted to chainstate
    /// 2. A new tip is now on chainstate, indicating that there's no point in continuing to mine/stake at that tip
    pub async fn run(&mut self) -> Result<(), BlockProductionError> {
        let accumulator = self.collect_transactions().await?;

        // TODO: do we want to introduce a separate executor for this loop to avoid starving other tasks?
        loop {
            let block = self.make_block(self.current_tip_id, &*accumulator)?;

            match self.attempt_submit_new_block(block).await? {
                BlockSubmitResult::Failed => (),
                BlockSubmitResult::Success => break,
            }

            // attempt to receive new commands from the perpetual Block Builder
            let new_info = match self.block_maker_rx.try_recv() {
                Ok(cmd) => cmd,
                Err(e) => match e {
                    // if there's nothing from the channel, then we can keep trying to build the block
                    crossbeam_channel::TryRecvError::Empty => continue,
                    // if the channel is lost, that means the perpetual Block Builder is destroyed.
                    // No point in continuing since it seems that the node exited.
                    crossbeam_channel::TryRecvError::Disconnected => {
                        log::error!("Block Maker control channel lost. Exiting Block Maker task on tip {} on best height {}", self.current_tip_id, self.current_tip_height);
                        break;
                    }
                },
            };

            match new_info {
                BlockMakerControlCommand::NewTip(block_id, _) => {
                    // if there is a new tip, no point in continuing to mine this block
                    if block_id != self.current_tip_id {
                        break;
                    }
                }
                BlockMakerControlCommand::Stop => break,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::setup_blockprod_test;
    use chainstate_types::{BlockIndex, BlockPreconnectData, ConsensusExtraData};
    use crypto::random::make_pseudo_rng;
    use mempool::{MempoolInterface, MempoolSubsystemInterface};
    use mocks::{MempoolInterfaceMock, MockChainstateInterfaceMock};
    use std::sync::atomic::Ordering::Relaxed;
    use subsystem::CallRequest;

    use chainstate::{
        chainstate_interface::ChainstateInterface,
        BlockError::{self, PrevBlockNotFound},
        ChainstateError,
    };

    use common::{
        chain::{
            block::{timestamp::BlockTimestamp, BlockReward, ConsensusData},
            Block,
        },
        primitives::{BlockHeight, Id, H256},
        time_getter::TimeGetter,
        Uint256,
    };

    use super::*;

    #[tokio::test]
    async fn collect_transactions_subsystem_error() {
        let (mut manager, chain_config, chainstate, _mempool) = setup_blockprod_test();

        let mock_mempool = MempoolInterfaceMock::new();

        let mock_mempool_subsystem = manager.add_subsystem_with_custom_eventloop("mock-mempool", {
            let mock_mempool = mock_mempool.clone();
            move |call: CallRequest<dyn MempoolInterface>, shutdn| async move {
                mock_mempool.run(call, shutdn).await;
            }
        });

        mock_mempool_subsystem.call({
            let shutdown = manager.make_shutdown_trigger();
            move |_| shutdown.initiate()
        });

        // shutdown straight after startup, *then* call collect_transactions()
        manager.main().await;

        // spawn rather than adding a subsystem as manager is moved into main() above
        tokio::spawn(async move {
            let (_tx_builder, rx_builder) = crossbeam_channel::unbounded();

            let block_maker = BlockMaker::new(
                chain_config,
                chainstate.clone(),
                mock_mempool_subsystem,
                Default::default(),
                Id::new(H256::random_using(&mut make_pseudo_rng())),
                BlockHeight::one(),
                rx_builder,
            );

            let accumulator = block_maker.collect_transactions().await;

            assert!(
                !mock_mempool.collect_txs_called.load(Relaxed),
                "Expected collect_tx() to not be called"
            );

            assert!(
                matches!(
                    accumulator,
                    Err(BlockProductionError::SubsystemCallError(_))
                ),
                "Expected a subsystem error"
            );
        })
        .await
        .expect("Subsystem error thread failed");
    }

    #[tokio::test]
    async fn collect_transactions_collect_txs_failed() {
        let (mut manager, chain_config, chainstate, _mempool) = setup_blockprod_test();

        let mock_mempool = MempoolInterfaceMock::new();
        mock_mempool.collect_txs_should_error.store(true, Relaxed);

        let mock_mempool_subsystem = manager.add_subsystem_with_custom_eventloop("mock-mempool", {
            let mock_mempool = mock_mempool.clone();
            move |call, shutdn| async move {
                mock_mempool.run(call, shutdn).await;
            }
        });

        manager.add_subsystem_with_custom_eventloop(
            "test-call",
            move |_: CallRequest<()>, _| async move {
                let (_tx_builder, rx_builder) = crossbeam_channel::unbounded();

                let block_maker = BlockMaker::new(
                    chain_config,
                    chainstate.clone(),
                    mock_mempool_subsystem,
                    Default::default(),
                    Id::new(H256::random_using(&mut make_pseudo_rng())),
                    BlockHeight::one(),
                    rx_builder,
                );

                let accumulator = block_maker.collect_transactions().await;

                assert!(
                    mock_mempool.collect_txs_called.load(Relaxed),
                    "Expected collect_tx() to be called"
                );

                assert!(
                    matches!(accumulator, Err(BlockProductionError::MempoolChannelClosed)),
                    "Expected collect_tx() to fail"
                );
            },
        );

        manager.main().await;
    }

    #[tokio::test]
    async fn collect_transactions_succeeded() {
        let (mut manager, chain_config, chainstate, _mempool) = setup_blockprod_test();

        let mock_mempool = MempoolInterfaceMock::new();

        let mock_mempool_subsystem = manager.add_subsystem_with_custom_eventloop("mock-mempool", {
            let mock_mempool = mock_mempool.clone();
            move |call, shutdn| async move {
                mock_mempool.run(call, shutdn).await;
            }
        });

        manager.add_subsystem_with_custom_eventloop(
            "test-call",
            move |_: CallRequest<()>, _| async move {
                let (_tx_builder, rx_builder) = crossbeam_channel::unbounded();

                let block_maker = BlockMaker::new(
                    chain_config,
                    chainstate.clone(),
                    mock_mempool_subsystem,
                    Default::default(),
                    Id::new(H256::random_using(&mut make_pseudo_rng())),
                    BlockHeight::one(),
                    rx_builder,
                );

                let accumulator = block_maker.collect_transactions().await;

                assert!(
                    mock_mempool.collect_txs_called.load(Relaxed),
                    "Expected collect_tx() to be called"
                );

                assert!(
                    accumulator.is_ok(),
                    "Expected collect_transactions() to succeed"
                );
            },
        );

        manager.main().await;
    }

    //
    // Skipping unit tests as we're about rework make_block()
    //
    // #[test]
    // fn make_block() {}
    //

    #[tokio::test]
    async fn attempt_submit_new_block_subsystem_error() {
        let (manager, chain_config, chainstate, mempool) = setup_blockprod_test();

        chainstate.call({
            let shutdown = manager.make_shutdown_trigger();
            move |_| shutdown.initiate()
        });

        // shutdown straight after startup, *then* call attempt_submit_new_block()
        manager.main().await;

        // spawn rather than adding a subsystem as manager is moved into main() above
        tokio::spawn(async move {
            let (_tx_builder, rx_builder) = crossbeam_channel::unbounded();

            let mut block_maker = BlockMaker::new(
                chain_config.clone(),
                chainstate,
                mempool,
                Default::default(),
                Id::new(H256::random_using(&mut make_pseudo_rng())),
                BlockHeight::one(),
                rx_builder,
            );

            let block = Block::new(
                vec![],
                chain_config.genesis_block_id(),
                BlockTimestamp::from_duration_since_epoch(TimeGetter::default().get_time()),
                ConsensusData::None,
                BlockReward::new(Vec::new()),
            )
            .expect("Error creating test block");

            let submit_result = block_maker.attempt_submit_new_block(block).await;

            assert!(
                matches!(
                    submit_result,
                    Err(BlockProductionError::SubsystemCallError(_))
                ),
                "Expected a subsystem error"
            );
        })
        .await
        .expect("Subsystem error thread failed");
    }

    #[tokio::test]
    async fn attempt_submit_new_block_preliminary_block_check_failed() {
        let (mut manager, chain_config, _chainstate, mempool) = setup_blockprod_test();

        let mock_chainstate: Box<dyn ChainstateInterface> = {
            let mut mock_chainstate = MockChainstateInterfaceMock::new();

            mock_chainstate
                .expect_preliminary_block_check()
                .times(1)
                .returning(|_| Err(ChainstateError::ProcessBlockError(PrevBlockNotFound)));

            Box::new(mock_chainstate)
        };

        let mock_chainstate_subsystem = manager.add_subsystem("mock-chainstate", mock_chainstate);

        manager.add_subsystem_with_custom_eventloop(
            "test-call",
            move |_: CallRequest<()>, _| async move {
                let (_tx_builder, rx_builder) = crossbeam_channel::unbounded();

                let mut block_maker = BlockMaker::new(
                    chain_config.clone(),
                    mock_chainstate_subsystem,
                    mempool,
                    Default::default(),
                    Id::new(H256::random_using(&mut make_pseudo_rng())),
                    BlockHeight::one(),
                    rx_builder,
                );

                let block = Block::new(
                    vec![],
                    chain_config.genesis_block_id(),
                    BlockTimestamp::from_duration_since_epoch(TimeGetter::default().get_time()),
                    ConsensusData::None,
                    BlockReward::new(Vec::new()),
                )
                .expect("Error creating test block");

                let submit_result = block_maker.attempt_submit_new_block(block).await;

                assert!(
                    matches!(submit_result, Ok(BlockSubmitResult::Failed)),
                    "Expected preliminary_block_check() to fail"
                );
            },
        );

        manager.main().await;
    }

    #[tokio::test]
    async fn attempt_submit_new_block_process_block_failed() {
        let (mut manager, chain_config, _chainstate, mempool) = setup_blockprod_test();

        let mock_chainstate: Box<dyn ChainstateInterface> = {
            let mut mock_chainstate = MockChainstateInterfaceMock::new();

            mock_chainstate.expect_preliminary_block_check().times(1).returning(Ok);

            mock_chainstate.expect_process_block().times(1).returning(|_, _| {
                Err(ChainstateError::ProcessBlockError(
                    BlockError::InvariantErrorInvalidTip,
                ))
            });

            Box::new(mock_chainstate)
        };

        let mock_chainstate_subsystem = manager.add_subsystem("mock-chainstate", mock_chainstate);

        manager.add_subsystem_with_custom_eventloop(
            "test-call",
            move |_: CallRequest<()>, _| async move {
                let (_tx_builder, rx_builder) = crossbeam_channel::unbounded();

                let mut block_maker = BlockMaker::new(
                    chain_config.clone(),
                    mock_chainstate_subsystem,
                    mempool,
                    Default::default(),
                    Id::new(H256::random_using(&mut make_pseudo_rng())),
                    BlockHeight::one(),
                    rx_builder,
                );

                let block = Block::new(
                    vec![],
                    chain_config.genesis_block_id(),
                    BlockTimestamp::from_duration_since_epoch(TimeGetter::default().get_time()),
                    ConsensusData::None,
                    BlockReward::new(Vec::new()),
                )
                .expect("Error creating test block");

                let submit_result = block_maker.attempt_submit_new_block(block).await;

                assert!(
                    matches!(submit_result, Ok(BlockSubmitResult::Failed)),
                    "Expected process_block() to fail"
                );
            },
        );

        manager.main().await;
    }

    #[tokio::test]
    async fn attempt_submit_new_block_process_block_no_index() {
        let (mut manager, chain_config, _chainstate, mempool) = setup_blockprod_test();

        let mock_chainstate: Box<dyn ChainstateInterface> = {
            let mut mock_chainstate = MockChainstateInterfaceMock::new();

            mock_chainstate.expect_preliminary_block_check().times(1).returning(Ok);
            mock_chainstate.expect_process_block().times(1).returning(|_, _| Ok(None));

            Box::new(mock_chainstate)
        };

        let mock_chainstate_subsystem = manager.add_subsystem("mock-chainstate", mock_chainstate);

        manager.add_subsystem_with_custom_eventloop(
            "test-call",
            move |_: CallRequest<()>, _| async move {
                let (_tx_builder, rx_builder) = crossbeam_channel::unbounded();

                let mut block_maker = BlockMaker::new(
                    chain_config.clone(),
                    mock_chainstate_subsystem,
                    mempool,
                    Default::default(),
                    Id::new(H256::random_using(&mut make_pseudo_rng())),
                    BlockHeight::one(),
                    rx_builder,
                );

                let block = Block::new(
                    vec![],
                    chain_config.genesis_block_id(),
                    BlockTimestamp::from_duration_since_epoch(TimeGetter::default().get_time()),
                    ConsensusData::None,
                    BlockReward::new(Vec::new()),
                )
                .expect("Error creating test block");

                let submit_result = block_maker.attempt_submit_new_block(block).await;

                assert!(
                    matches!(submit_result, Ok(BlockSubmitResult::Success)),
                    "Expected attempt_submit_new_block() to succeed"
                );
            },
        );

        manager.main().await;
    }

    #[tokio::test]
    async fn attempt_submit_new_block_process_block_with_index() {
        let (mut manager, chain_config, _chainstate, mempool) = setup_blockprod_test();

        let mock_chainstate: Box<dyn ChainstateInterface> = {
            let mut mock_chainstate = MockChainstateInterfaceMock::new();

            mock_chainstate.expect_preliminary_block_check().times(1).returning(Ok);

            mock_chainstate.expect_process_block().times(1).returning({
                let chain_config = chain_config.clone();
                move |block, _| {
                    let block_index = BlockIndex::new(
                        &block,
                        Uint256::ZERO,
                        chain_config.genesis_block_id(),
                        BlockHeight::one(),
                        BlockTimestamp::from_duration_since_epoch(TimeGetter::default().get_time()),
                        BlockPreconnectData::new(ConsensusExtraData::None),
                    );

                    Ok(Some(block_index))
                }
            });

            Box::new(mock_chainstate)
        };

        let mock_chainstate_subsystem = manager.add_subsystem("mock-chainstate", mock_chainstate);

        manager.add_subsystem_with_custom_eventloop(
            "test-call",
            move |_: CallRequest<()>, _| async move {
                let (_tx_builder, rx_builder) = crossbeam_channel::unbounded();

                let mut block_maker = BlockMaker::new(
                    chain_config.clone(),
                    mock_chainstate_subsystem,
                    mempool,
                    Default::default(),
                    Id::new(H256::random_using(&mut make_pseudo_rng())),
                    BlockHeight::one(),
                    rx_builder,
                );

                let block = Block::new(
                    vec![],
                    chain_config.genesis_block_id(),
                    BlockTimestamp::from_duration_since_epoch(TimeGetter::default().get_time()),
                    ConsensusData::None,
                    BlockReward::new(Vec::new()),
                )
                .expect("Error creating test block");

                let submit_result = block_maker.attempt_submit_new_block(block).await;

                assert!(
                    matches!(submit_result, Ok(BlockSubmitResult::Success)),
                    "Expected attempt_submit_new_block() to succeed"
                );
            },
        );

        manager.main().await;
    }

    //
    // Skipping unit tests as we're about rework run()
    //
    // #[tokio::test]
    // async fn run() {}
    //
}
