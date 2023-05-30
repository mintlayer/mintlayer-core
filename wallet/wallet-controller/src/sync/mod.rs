// Copyright (c) 2023 RBB S.r.l
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

use std::{sync::Arc, time::Duration};

use chainstate::ChainInfo;
use common::{
    chain::{Block, ChainConfig, GenBlock},
    primitives::{BlockHeight, Id},
};
use logging::log;
use node_comm::node_traits::NodeInterface;
use serialization::hex::HexEncode;
use tokio::{sync::mpsc, task::JoinHandle};
use wallet::{DefaultWallet, WalletResult};

use crate::ControllerError;

pub trait SyncingWallet {
    fn best_block(&self) -> WalletResult<(Id<GenBlock>, BlockHeight)>;

    fn scan_blocks(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
    ) -> WalletResult<()>;
}

impl SyncingWallet for DefaultWallet {
    fn best_block(&self) -> WalletResult<(Id<GenBlock>, BlockHeight)> {
        self.get_best_block()
    }

    fn scan_blocks(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
    ) -> WalletResult<()> {
        self.scan_new_blocks(common_block_height, blocks)
    }
}

struct NextBlockInfo {
    common_block_id: Id<GenBlock>,
    common_block_height: BlockHeight,
    block_id: Id<Block>,
}

struct NodeState {
    block_height: BlockHeight,
    block_id: Id<GenBlock>,
}

struct FetchedBlock {
    block: Block,
    common_block_height: BlockHeight,
}

#[derive(thiserror::Error, Debug)]
enum FetchBlockError<T: NodeInterface> {
    #[error("Unexpected RPC error: {0}")]
    UnexpectedRpcError(T::Error),
    #[error("Unexpected genesis block received at height {0}")]
    UnexpectedGenesisBlock(BlockHeight),
    #[error("There is no block at height {0}")]
    NoBlockAtHeight(BlockHeight),
    #[error("Block with id {0} not found")]
    BlockNotFound(Id<Block>),
    #[error("Invalid prev block id: {0}, expected: {1}")]
    InvalidPrevBlockId(Id<GenBlock>, Id<GenBlock>),
}

type BlockFetchResult<T> = Result<FetchedBlock, FetchBlockError<T>>;

pub struct BlockSyncing<T: NodeInterface> {
    config: BlockSyncingConfig,

    chain_config: Arc<ChainConfig>,

    rpc_client: T,

    node_state_rx: mpsc::Receiver<NodeState>,

    /// Last known chain state information of the remote node.
    /// Used to start block synchronization when a new block is found.
    node_chain_state: Option<NodeState>,

    state_sync_task: JoinHandle<()>,

    /// Handle of the background block fetch task, if started.
    /// If successful, the wallet will be updated.
    /// If there was an error, the block sync process will be retried later.
    block_fetch_task: Option<JoinHandle<BlockFetchResult<T>>>,
}

#[derive(Clone)]
pub struct BlockSyncingConfig {
    normal_delay: Duration,
    error_delay: Duration,
}

impl Default for BlockSyncingConfig {
    fn default() -> Self {
        Self {
            normal_delay: Duration::from_secs(1),
            error_delay: Duration::from_secs(10),
        }
    }
}

impl<T: NodeInterface + Clone + Send + Sync + 'static> BlockSyncing<T> {
    pub fn new(config: BlockSyncingConfig, chain_config: Arc<ChainConfig>, rpc_client: T) -> Self {
        let (node_state_tx, node_state_rx) = mpsc::channel(1);
        let state_sync_task = tokio::spawn(run_state_sync(
            config.clone(),
            node_state_tx,
            rpc_client.clone(),
        ));

        Self {
            config,
            chain_config,
            rpc_client,
            node_state_rx,
            node_chain_state: None,
            state_sync_task,
            block_fetch_task: None,
        }
    }

    fn handle_node_state_change(&mut self, node_state: NodeState) {
        if self.node_chain_state.as_ref().map(|state| state.block_id) == Some(node_state.block_id) {
            return;
        }
        log::info!(
            "Node chainstate updated, block height: {}, top block id: {}",
            node_state.block_height,
            node_state.block_id.hex_encode()
        );
        self.node_chain_state = Some(node_state);
    }

    pub async fn force_node_state_update(&mut self) -> Result<ChainInfo, ControllerError<T>> {
        let node_state = self
            .rpc_client
            .chainstate_info()
            .await
            .map_err(ControllerError::NodeCallError)?;
        self.handle_node_state_change(NodeState {
            block_height: node_state.best_block_height,
            block_id: node_state.best_block_id,
        });
        Ok(node_state)
    }

    fn start_block_fetch_if_needed(&mut self, wallet: &mut impl SyncingWallet) {
        if self.block_fetch_task.is_some() {
            return;
        }

        let (node_block_id, node_block_height) = match self.node_chain_state.as_ref() {
            Some(info) => (info.block_id, info.block_height),
            None => return,
        };

        let (wallet_block_id, wallet_block_height) =
            wallet.best_block().expect("`get_best_block` should not fail normally");

        // Wait until the node has enough block height.
        // Block sync may not work correctly otherwise.
        if node_block_id == wallet_block_id || node_block_height < wallet_block_height {
            return;
        }

        let chain_config = Arc::clone(&self.chain_config);
        let mut rpc_client = self.rpc_client.clone();

        // TODO: Download blocks in batches (100-1000 blocks at a time) to reduce overhead and shorten sync time

        let error_delay = self.config.error_delay;
        self.block_fetch_task = Some(tokio::spawn(async move {
            let sync_res = fetch_new_block(
                &chain_config,
                &mut rpc_client,
                node_block_id,
                node_block_height,
                wallet_block_id,
                wallet_block_height,
            )
            .await;

            if let Err(e) = &sync_res {
                log::error!("Block fetch failed: {e}");
                // Wait a bit to not spam constantly if the node is unreachable
                tokio::time::sleep(error_delay).await;
            }

            sync_res
        }));
    }

    fn handle_block_fetch_result(
        &mut self,
        res: BlockFetchResult<T>,
        wallet: &mut impl SyncingWallet,
    ) {
        if let Ok(FetchedBlock {
            block,
            common_block_height,
        }) = res
        {
            let scan_res = wallet.scan_blocks(common_block_height, vec![block]);
            if let Err(e) = scan_res {
                log::error!("Block scan failed: {e}");
            }
        }
    }

    async fn recv_block_fetch_result(
        block_fetch_task: &mut Option<JoinHandle<BlockFetchResult<T>>>,
    ) -> BlockFetchResult<T> {
        // This must be cancel safe!
        match block_fetch_task {
            Some(task) => {
                let res = task.await.expect("Block fetch should not panic");
                *block_fetch_task = None;
                res
            }
            None => std::future::pending().await,
        }
    }

    pub async fn run(&mut self, wallet: &mut impl SyncingWallet, expected: Option<BlockHeight>) {
        // This must be cancel safe!
        loop {
            self.start_block_fetch_if_needed(wallet);

            match (
                self.node_chain_state.as_ref(),
                expected,
                self.block_fetch_task.as_ref(),
            ) {
                (Some(node), Some(expected), None) if node.block_height >= expected => {
                    return;
                }
                _ => {}
            }

            tokio::select! {
                chain_info_opt = self.node_state_rx.recv() => {
                    // Channel is always open because [run_tip_sync] does not return
                    self.handle_node_state_change(chain_info_opt.expect("Channel must be open"));
                }
                sync_result = Self::recv_block_fetch_result(&mut self.block_fetch_task) => {
                    self.handle_block_fetch_result(sync_result, wallet);
                }
            }
        }
    }
}

async fn run_state_sync<T: NodeInterface>(
    config: BlockSyncingConfig,
    state_tx: mpsc::Sender<NodeState>,
    rpc_client: T,
) {
    let mut last_block_id = None;

    while !state_tx.is_closed() {
        let state_res = rpc_client.chainstate_info().await;
        match state_res {
            Ok(state) => {
                if last_block_id.as_ref() != Some(&state.best_block_id) {
                    _ = state_tx
                        .send(NodeState {
                            block_height: state.best_block_height,
                            block_id: state.best_block_id,
                        })
                        .await;
                    last_block_id = Some(state.best_block_id);
                }
                tokio::time::sleep(config.normal_delay).await;
            }
            Err(e) => {
                logging::log::error!("Node state sync error: {}", e);
                tokio::time::sleep(config.error_delay).await;
            }
        }
    }
}

impl<T: NodeInterface> Drop for BlockSyncing<T> {
    fn drop(&mut self) {
        self.state_sync_task.abort();
        self.block_fetch_task.as_ref().map(JoinHandle::abort);
    }
}

// TODO: For security reasons, the wallet should probably keep track of latest blocks
// and not allow very large reorgs (for example, the Monero wallet allows reorgs of up to 100 blocks).
async fn get_next_block_info<T: NodeInterface>(
    chain_config: &ChainConfig,
    rpc_client: &mut T,
    node_block_id: Id<GenBlock>,
    node_block_height: BlockHeight,
    wallet_block_id: Id<GenBlock>,
    wallet_block_height: BlockHeight,
) -> Result<NextBlockInfo, FetchBlockError<T>> {
    assert!(node_block_id != wallet_block_id);
    assert!(node_block_height >= wallet_block_height);

    let common_block_opt = rpc_client
        .get_last_common_ancestor(wallet_block_id, node_block_id)
        .await
        .map_err(FetchBlockError::UnexpectedRpcError)?;

    let (common_block_id, common_block_height) = match common_block_opt {
        // Common branch is found
        Some(common_block) => common_block,
        // Common branch not found, restart from genesis block.
        // This happens when:
        // 1. The node is downloading blocks.
        // 2. Blocks in the blockchain were pruned, so the block the wallet knows about is now unrecognized in the block tree.
        None => (chain_config.genesis_block_id(), BlockHeight::zero()),
    };

    let block_height = common_block_height.next_height();

    let gen_block_id = rpc_client
        .get_block_id_at_height(block_height)
        .await
        .map_err(FetchBlockError::UnexpectedRpcError)?
        .ok_or(FetchBlockError::NoBlockAtHeight(block_height))?;

    // This must not be genesis, but we don't want to trust the remote node and give it power to panic the wallet with expect.
    // TODO: we should mark this node as malicious if this happens to be genesis.
    let block_id = match gen_block_id.classify(chain_config) {
        common::chain::GenBlockId::Genesis(_) => {
            return Err(FetchBlockError::UnexpectedGenesisBlock(wallet_block_height))
        }
        common::chain::GenBlockId::Block(id) => id,
    };

    Ok(NextBlockInfo {
        common_block_id,
        common_block_height,
        block_id,
    })
}

async fn fetch_new_block<T: NodeInterface>(
    chain_config: &ChainConfig,
    rpc_client: &mut T,
    node_block_id: Id<GenBlock>,
    node_block_height: BlockHeight,
    wallet_block_id: Id<GenBlock>,
    wallet_block_height: BlockHeight,
) -> Result<FetchedBlock, FetchBlockError<T>> {
    let NextBlockInfo {
        common_block_id,
        common_block_height,
        block_id,
    } = get_next_block_info(
        chain_config,
        rpc_client,
        node_block_id,
        node_block_height,
        wallet_block_id,
        wallet_block_height,
    )
    .await?;

    let block = rpc_client
        .get_block(block_id)
        .await
        .map_err(FetchBlockError::UnexpectedRpcError)?
        .ok_or(FetchBlockError::BlockNotFound(block_id))?;
    utils::ensure!(
        *block.header().prev_block_id() == common_block_id,
        FetchBlockError::InvalidPrevBlockId(*block.header().prev_block_id(), common_block_id)
    );

    Ok(FetchedBlock {
        block,
        common_block_height,
    })
}

#[cfg(test)]
mod tests;
