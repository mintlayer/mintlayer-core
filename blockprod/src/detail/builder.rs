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
    chain::{Block, ChainConfig},
    primitives::{BlockHeight, Id},
    time_getter::TimeGetter,
};
use logging::log;
use mempool::{MempoolEvent, MempoolHandle};
use tokio::sync::mpsc;

use crate::BlockProductionError;

use super::block_maker::{BlockMaker, BlockMakerControlCommand};

/// Master in the master/slave model with BlockMaker. Every time there's a new tip in chainstate or mempool,
/// the perpetual block builder constructs a new instance of BlockMaker that keeps trying to create a block.
pub struct PerpetualBlockBuilder {
    chain_config: Arc<ChainConfig>,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    time_getter: TimeGetter,
    builder_rx: mpsc::UnboundedReceiver<BlockBuilderControlCommand>,
    block_makers_tx: crossbeam_channel::Sender<BlockMakerControlCommand>,
    block_maker_rx: crossbeam_channel::Receiver<BlockMakerControlCommand>,
    enabled: bool,
    _block_makers_destroyer: BlockMakersDestroyer,
}

pub enum BlockBuilderControlCommand {
    Stop,
    Start,
}

impl PerpetualBlockBuilder {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        chainstate_handle: ChainstateHandle,
        mempool_handle: MempoolHandle,
        time_getter: TimeGetter,
        builder_rx: mpsc::UnboundedReceiver<BlockBuilderControlCommand>,
        enabled: bool,
    ) -> Self {
        let (block_makers_tx, block_maker_rx) = crossbeam_channel::unbounded();
        Self {
            chain_config,
            chainstate_handle,
            mempool_handle,
            time_getter,
            builder_rx,
            block_makers_tx: block_makers_tx.clone(),
            block_maker_rx,
            enabled,
            _block_makers_destroyer: BlockMakersDestroyer(block_makers_tx),
        }
    }

    pub fn new_tip(
        &mut self,
        new_tip_id: Id<Block>,
        new_tip_height: BlockHeight,
    ) -> Result<(), BlockProductionError> {
        self.block_makers_tx.send(BlockMakerControlCommand::NewTip(
            new_tip_id,
            new_tip_height,
        )).expect("The channel can never be disconnected since there's a receiver always alive in self");
        Ok(())
    }

    pub fn stop_all_block_makers(&self) -> Result<(), BlockProductionError> {
        self.block_makers_tx.send(BlockMakerControlCommand::Stop).expect(
            "The channel can never be disconnected since there's a receiver always alive in self",
        );
        Ok(())
    }

    pub async fn trigger_new_block_production(
        &self,
        current_tip_id: Id<Block>,
        current_tip_height: BlockHeight,
    ) -> Result<(), BlockProductionError> {
        if !self.enabled {
            return Ok(());
        }

        let chain_config = self.chain_config.clone();
        let chainstate_handle = self.chainstate_handle.clone();
        let mempool_handle = self.mempool_handle.clone();
        let time_getter = self.time_getter.clone();
        let command_receiver = self.block_maker_rx.clone();
        tokio::spawn(async move {
            BlockMaker::new(
                chain_config,
                chainstate_handle,
                mempool_handle,
                time_getter,
                current_tip_id,
                current_tip_height,
                command_receiver,
            )
            .run()
            .await
        });
        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), BlockProductionError> {
        let mut mempool_rx = self.subscribe_to_mempool_events().await?;
        let mut chainstate_rx = self.subscribe_to_chainstate_events().await?;

        loop {
            tokio::select! {
                // when we receive information from chainstate that we have a new tip, we stop building the current block,
                // and expect the mempool to soon send a trigger for a new command
                block_info = chainstate_rx.recv() => {
                    let (block_id, block_height) = block_info.ok_or(BlockProductionError::ChainstateChannelClosed)?;
                    self.new_tip(block_id, block_height)?;
                }
                block_info = mempool_rx.recv() => {
                    let (block_id, block_height) = block_info.ok_or(BlockProductionError::MempoolChannelClosed)?;
                    self.trigger_new_block_production(block_id, block_height).await?;
                }
                event = self.builder_rx.recv() => match event.ok_or(BlockProductionError::BlockBuilderChannelClosed)? {
                    BlockBuilderControlCommand::Stop => {
                        self.enabled = false;
                        self.stop_all_block_makers()?;
                    },
                    BlockBuilderControlCommand::Start => {
                        self.enabled = true;
                    },
                }
            }
        }
    }

    /// Subscribe to events from chainstate
    async fn subscribe_to_chainstate_events(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<(Id<Block>, BlockHeight)>, BlockProductionError> {
        let (tx, rx) = mpsc::unbounded_channel();

        let subscribe_func = Arc::new(move |chainstate_event: chainstate::ChainstateEvent| {
            match chainstate_event {
                chainstate::ChainstateEvent::NewTip(block_id, block_height) => {
                    if let Err(e) = tx.send((block_id, block_height)) {
                        log::error!(
                                    "Block production failed to receive event from chainstate - channel closed: {:?}",
                                    e
                                )
                    }
                }
            }
        });

        self.chainstate_handle
            .call_mut(|this| this.subscribe_to_events(subscribe_func))
            .await
            .expect("Block production subscription to chainstate events failed");

        Ok(rx)
    }

    /// Subscribe to events from the mempool
    async fn subscribe_to_mempool_events(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<(Id<Block>, BlockHeight)>, BlockProductionError> {
        let (tx, rx) = mpsc::unbounded_channel();

        let subscribe_func = Arc::new(move |mempool_event: MempoolEvent| match mempool_event {
            MempoolEvent::NewTip(block_id, block_height) => {
                if let Err(e) = tx.send((block_id, block_height)) {
                    log::error!(
                            "Block production failed to receive event from mempool - channel closed: {:?}",
                            e
                        )
                }
            }
        });

        self.mempool_handle
            .call_async_mut(|this| this.subscribe_to_events(subscribe_func))
            .await
            .map_err(|_| BlockProductionError::MempoolChannelClosed)?
            .expect("Block production subscription to mempool events failed");

        Ok(rx)
    }
}

/// On destruction, this struct sends a message to all Block Makers to stop to aid a graceful exit
struct BlockMakersDestroyer(crossbeam_channel::Sender<BlockMakerControlCommand>);

impl Drop for BlockMakersDestroyer {
    fn drop(&mut self) {
        match self.0.send(BlockMakerControlCommand::Stop) {
            Ok(_) => (),
            Err(err) => log::error!("Failed to stop all Block Makers: {}", err),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::setup_blockprod_test;
    use chainstate::BlockSource;
    use crypto::random::make_pseudo_rng;
    use std::thread;
    use tokio::task::yield_now;
    use tokio::time::{timeout, Duration};

    use common::{
        chain::block::{timestamp::BlockTimestamp, BlockReward, ConsensusData},
        primitives::{Idable, H256},
        time_getter::TimeGetter,
    };

    use super::*;

    #[test]
    fn new_tip() {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test();

        let (_tx_builder, rx_builder) = mpsc::unbounded_channel();

        let mut block_builder = PerpetualBlockBuilder::new(
            chain_config,
            chainstate,
            mempool,
            Default::default(),
            rx_builder,
            true,
        );

        let block_id = Id::new(H256::random_using(&mut make_pseudo_rng()));

        block_builder
            .new_tip(block_id, BlockHeight::one())
            .expect("Error sending new tip to Block Makers");

        match block_builder
            .block_maker_rx
            .try_recv()
            .expect("Error reading from Block Builder")
        {
            BlockMakerControlCommand::NewTip(new_block_id, new_block_height) => {
                assert_eq!(block_id, new_block_id, "Invalid Block ID received");
                assert_eq!(
                    new_block_height,
                    BlockHeight::one(),
                    "Invalid block height received"
                );
            }
            _ => panic!("Error reading new tip from Block Builder"),
        }
    }

    #[test]
    fn stop() {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test();

        let (_tx_builder, rx_builder) = mpsc::unbounded_channel();

        let block_builder = PerpetualBlockBuilder::new(
            chain_config,
            chainstate,
            mempool,
            Default::default(),
            rx_builder,
            true,
        );

        block_builder.stop_all_block_makers().expect("Error stopping all Block Makers");

        match block_builder
            .block_maker_rx
            .try_recv()
            .expect("Error reading from Block Builder")
        {
            BlockMakerControlCommand::Stop => {}
            _ => panic!("Invalid message received from Block Builder"),
        }
    }

    #[tokio::test]
    async fn run() {
        let (manager, chain_config, chainstate, mempool) = setup_blockprod_test();

        let (_tx_builder, rx_builder) = mpsc::unbounded_channel();

        let mut block_builder = PerpetualBlockBuilder::new(
            chain_config.clone(),
            chainstate.clone(),
            mempool.clone(),
            Default::default(),
            rx_builder,
            true,
        );

        let block_maker_rx = block_builder.block_maker_rx.clone();

        let block = Block::new(
            vec![],
            chain_config.genesis_block_id(),
            BlockTimestamp::from_duration_since_epoch(TimeGetter::default().get_time()),
            ConsensusData::None,
            BlockReward::new(Vec::new()),
        )
        .expect("Error creating test block");

        //
        // Flag that the mempool saw the new tip event
        //

        let (tx, _rx) = crossbeam_channel::bounded(1);

        mempool.call_async_mut({
            let block_id = block.get_id();
            move |this| {
                this.subscribe_to_events(Arc::new(move |mempool_event| match mempool_event {
                    MempoolEvent::NewTip(new_block_id, new_block_height) => {
                        if block_id == new_block_id && new_block_height == BlockHeight::one() {
                            tx.send(true).expect("Error sending new tip confirmation");
                        }
                    }
                }))
            }
        });

        //
        // Flag that chainstate saw the new tip event
        //

        thread::spawn({
            let block_id = block.get_id();
            let shutdown = manager.make_shutdown_trigger();

            move || {
                match block_maker_rx.recv().expect("Error reading from Block Builder") {
                    BlockMakerControlCommand::NewTip(new_block_id, new_block_height) => {
                        assert_eq!(block_id, new_block_id, "Invalid Block ID received");
                        assert_eq!(
                            new_block_height,
                            BlockHeight::one(),
                            "Invalid block height received"
                        );
                    }
                    _ => panic!("Error reading new tip from Block Builder"),
                }

                // TODO: the following assertion will fail until we turn on mempool broadcasts
                //
                // assert!(
                //     rx.recv_timeout(Duration::from_millis(1000)).is_ok(),
                //     "Mempool new tip timed out"
                // );

                shutdown.initiate();
            }
        });

        tokio::spawn(async move {
            // This will error due to run()'s recv() on disconnect when done
            block_builder.run().await.err();
        });

        let get_subscriber_count = {
            let chainstate = chainstate.clone();
            move || chainstate.call(|this| this.subscribers().len())
        };

        tokio::spawn(async move {
            loop {
                // One subscriber from this run()'s self.subscribe_to_chainstate_events()
                // The other from mempool.run()'s self.subscribe_to_chainstate_events()
                if get_subscriber_count().await.expect("Error getting subscriber count") == 2 {
                    break;
                }

                yield_now().await;
            }

            chainstate.call_mut(|this| {
                this.process_block(block, BlockSource::Local).expect("Error processing block")
            });
        });

        manager.main().await;
    }

    #[tokio::test]
    async fn subscribe_to_chainstate_events() {
        let (manager, chain_config, chainstate, mempool) = setup_blockprod_test();

        let (_tx_builder, rx_builder) = mpsc::unbounded_channel();

        let block_builder = PerpetualBlockBuilder::new(
            chain_config.clone(),
            chainstate.clone(),
            mempool,
            Default::default(),
            rx_builder,
            true,
        );

        let shutdown = manager.make_shutdown_trigger();

        tokio::spawn(async move {
            let mut chainstate_rx = block_builder
                .subscribe_to_chainstate_events()
                .await
                .expect("Error subscribing to chainstate events");

            let block = Block::new(
                vec![],
                chain_config.genesis_block_id(),
                BlockTimestamp::from_duration_since_epoch(TimeGetter::default().get_time()),
                ConsensusData::None,
                BlockReward::new(Vec::new()),
            )
            .expect("Error creating test block");

            let block_id = block.get_id();

            chainstate.call_mut(move |this| {
                this.process_block(block, BlockSource::Local).expect("Error processing block");
            });

            let recv = timeout(Duration::from_millis(1000), chainstate_rx.recv());

            tokio::select! {
                msg = recv => match msg.expect("Chainstate timed out") {
                    Some((new_block_id, _)) => {
                        assert!(new_block_id == block_id, "Invalid Block Id received");
                    }
                    _ => panic!("Invalid message from chainstate"),
                }
            }

            shutdown.initiate();
        });

        manager.main().await;
    }

    #[tokio::test]
    async fn subscribe_to_mempool_events() {
        let (manager, chain_config, chainstate, mempool) = setup_blockprod_test();

        let (_tx_builder, rx_builder) = mpsc::unbounded_channel();

        let block_builder = PerpetualBlockBuilder::new(
            chain_config.clone(),
            chainstate.clone(),
            mempool,
            Default::default(),
            rx_builder,
            true,
        );

        let shutdown = manager.make_shutdown_trigger();

        tokio::spawn(async move {
            let mut mempool_rx = block_builder
                .subscribe_to_mempool_events()
                .await
                .expect("Error subscribing to chainstate events");

            let block = Block::new(
                vec![],
                chain_config.genesis_block_id(),
                BlockTimestamp::from_duration_since_epoch(TimeGetter::default().get_time()),
                ConsensusData::None,
                BlockReward::new(Vec::new()),
            )
            .expect("Error creating test block");

            let _block_id = block.get_id();

            chainstate.call_mut(move |this| {
                this.process_block(block, BlockSource::Local).expect("Error processing block");
            });

            let _recv = timeout(Duration::from_millis(1000), mempool_rx.recv());

            // TODO: the following assertion will fail until we turn on mempool broadcasts
            //
            // tokio::select! {
            //     msg = recv => match msg.expect("Mempool timed out") {
            //         Some((new_block_id, _)) => {
            //             assert!(new_block_id == block_id, "Invalid Block Id received");
            //         }
            //         _ => panic!("Invalid message from mempool"),
            //     }
            // }

            shutdown.initiate();
        });

        manager.main().await;
    }
}
