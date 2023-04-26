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

use common::{
    chain::{Block, ChainConfig, GenBlock},
    primitives::{BlockHeight, Id},
};
use node_comm::node_traits::NodeInterface;
use tokio::sync::mpsc;
use wallet::DefaultWallet;

pub enum SyncEvent {
    Reset {
        block_id: Id<GenBlock>,
        block_height: BlockHeight,
    },
    NewBlock {
        block: Block,
    },
}

#[derive(thiserror::Error, Debug)]
pub enum SyncError<T: NodeInterface> {
    #[error("Unexpected RPC error: {0}")]
    UnexpectedRpcError(T::Error),
    #[error("Unexpected genesis block received at height {0}")]
    UnexpectedGenesisBlock(BlockHeight),
    #[error("Node did not return block {0}")]
    BlockNotFound(Id<Block>),
}

async fn fetch_new_block<T: NodeInterface>(
    chain_config: &ChainConfig,
    rpc_client: &mut T,
    wallet_block_id: Id<GenBlock>,
    wallet_block_height: BlockHeight,
) -> Result<Option<SyncEvent>, SyncError<T>> {
    // TODO: Make it more efficient: download blocks concurrently and send fewer requests

    let node_best_block =
        rpc_client.get_best_block_id().await.map_err(SyncError::UnexpectedRpcError)?;

    let common_block_opt = rpc_client
        .get_last_common_block(wallet_block_id, node_best_block)
        .await
        .map_err(SyncError::UnexpectedRpcError)?;

    let (common_block_id, common_block_height) = match common_block_opt {
        Some(common_block) => common_block,
        None => {
            return Ok(Some(SyncEvent::Reset {
                block_id: chain_config.genesis_block_id(),
                block_height: BlockHeight::zero(),
            }));
        }
    };

    if common_block_height < wallet_block_height {
        return Ok(Some(SyncEvent::Reset {
            block_id: common_block_id,
            block_height: common_block_height,
        }));
    }

    let next_block_height = wallet_block_height.next_height();
    let next_block_id_opt = rpc_client
        .get_block_id_at_height(next_block_height)
        .await
        .map_err(SyncError::UnexpectedRpcError)?;
    let next_gen_block_id = match next_block_id_opt {
        Some(id) => id,
        None => return Ok(None),
    };
    let next_block_id = match next_gen_block_id.classify(chain_config) {
        common::chain::GenBlockId::Genesis(_) => {
            return Err(SyncError::UnexpectedGenesisBlock(wallet_block_height))
        }
        common::chain::GenBlockId::Block(id) => id,
    };

    let new_block = rpc_client
        .get_block(next_block_id)
        .await
        .map_err(SyncError::UnexpectedRpcError)?;
    match new_block {
        Some(block) => Ok(Some(SyncEvent::NewBlock { block })),
        // This may fail if there was a reorg after this function was started.
        // It should resolve normally next time.
        None => Err(SyncError::BlockNotFound(next_block_id)),
    }
}

pub async fn run<T: NodeInterface>(
    sync_tx: mpsc::Sender<SyncEvent>,
    chain_config: Arc<ChainConfig>,
    mut rpc_client: T,
    mut wallet_block_id: Id<GenBlock>,
    mut wallet_block_height: BlockHeight,
) {
    while !sync_tx.is_closed() {
        let sync_state = fetch_new_block(
            &chain_config,
            &mut rpc_client,
            wallet_block_id,
            wallet_block_height,
        )
        .await;

        match sync_state {
            Ok(Some(v)) => {
                match &v {
                    SyncEvent::Reset {
                        block_id,
                        block_height,
                    } => {
                        wallet_block_id = *block_id;
                        wallet_block_height = *block_height;
                    }
                    SyncEvent::NewBlock { block } => {
                        wallet_block_id = block.header().block_id().into();
                        wallet_block_height = wallet_block_height.next_height();
                    }
                }
                _ = sync_tx.send(v).await;
            }
            Ok(None) => {
                // No new blocks, wait before retrying
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => {
                logging::log::error!("Sync error: {}", e);
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}

/// Sync the wallet state (known blocks) from the node.
/// Returns true if the wallet state has changed.
pub fn apply_sync_event(
    sync_event: SyncEvent,
    wallet: &mut DefaultWallet,
) -> Result<(), wallet::WalletError> {
    match sync_event {
        SyncEvent::Reset {
            block_id: common_block_id,
            block_height: common_block_height,
        } => {
            // Reorg was detected, reset the wallet state to some previous block
            logging::log::debug!("Reorg detected, reset to {common_block_height}");
            wallet.reset_to_height(common_block_id, common_block_height)
        }
        SyncEvent::NewBlock { block } => {
            logging::log::debug!("New block found {}", block.header().block_id());
            wallet.scan_new_blocks(vec![block])
        }
    }
}
