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
use futures::FutureExt;
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

    pub fn stop_building(
        &mut self,
        new_tip_id: Id<Block>,
        new_tip_height: BlockHeight,
    ) -> Result<(), BlockProductionError> {
        self.block_makers_tx.send(BlockMakerControlCommand::StopBecauseNewTip(
            new_tip_id,
            new_tip_height,
        )).expect("The channel can never be disconnected since there's a receiver always alive in self");
        Ok(())
    }

    pub fn stop_all_block_makers(&self) -> Result<(), BlockProductionError> {
        self.block_makers_tx.send(BlockMakerControlCommand::JustStop).expect(
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
                block_info = chainstate_rx.recv().fuse() => {
                    let (block_id, block_height) = block_info.ok_or(BlockProductionError::ChainstateChannelClosed)?;
                    self.stop_building(block_id, block_height)?;
                }
                block_info = mempool_rx.recv().fuse() => {
                    let (block_id, block_height) = block_info.ok_or(BlockProductionError::MempoolChannelClosed)?;
                    self.trigger_new_block_production(block_id, block_height).await?;
                }
                event = self.builder_rx.recv().fuse() => match event.ok_or(BlockProductionError::BlockBuilderChannelClosed)? {
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

/// On destruction, this struct sends a message to all block makers to stop to aid a graceful exit
struct BlockMakersDestroyer(crossbeam_channel::Sender<BlockMakerControlCommand>);

impl Drop for BlockMakersDestroyer {
    fn drop(&mut self) {
        match self.0.send(BlockMakerControlCommand::JustStop) {
            Ok(_) => (),
            Err(err) => log::error!("Failed to stop all block makers: {}", err),
        }
    }
}
