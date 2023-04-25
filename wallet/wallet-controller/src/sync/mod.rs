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
use tokio::sync::Mutex;
use wallet::DefaultWallet;

enum NewSyncState {
    UnknownChain,
    Revert {
        common_block_id: Id<GenBlock>,
        common_block_height: BlockHeight,
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

async fn notify_new_block<T: NodeInterface>(
    chain_config: &ChainConfig,
    rpc_client: &mut T,
    wallet_block_id: Id<GenBlock>,
    wallet_block_height: BlockHeight,
) -> Result<Option<NewSyncState>, SyncError<T>> {
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
            // No common block found for some reason. This can happen if the wallet is on an abandoned chain
            // and the node has never seen this chain before. Reset the wallet to the genesis and start over.
            return Ok(Some(NewSyncState::UnknownChain));
        }
    };

    if common_block_height < wallet_block_height {
        return Ok(Some(NewSyncState::Revert {
            common_block_id,
            common_block_height,
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
        Some(block) => Ok(Some(NewSyncState::NewBlock { block })),
        // This may fail if there was a reorg after this function was started.
        // It should resolve normally next time.
        None => Err(SyncError::BlockNotFound(next_block_id)),
    }
}

/// Sync the wallet state (known blocks) from the node.
/// Returns true if the wallet state has changed.
fn apply_sync_state(
    chain_config: &ChainConfig,
    sync_state: NewSyncState,
    wallet: &mut DefaultWallet,
) -> Result<(), wallet::WalletError> {
    match sync_state {
        NewSyncState::UnknownChain => {
            // No common block found for some reason. This can happen if the wallet is on an abandoned chain
            // and the node has never seen this chain before. Reset the wallet to the genesis and start over.
            wallet.reset_to_height(chain_config.genesis_block_id(), BlockHeight::zero())
        }
        NewSyncState::Revert {
            common_block_id,
            common_block_height,
        } => {
            // Reset the wallet state to some previous block and start over
            logging::log::debug!("Reorg detected, reset to {common_block_height}");
            wallet.reset_to_height(common_block_id, common_block_height)
        }
        NewSyncState::NewBlock { block } => wallet.scan_new_blocks(vec![block]),
    }
}

pub async fn run_sync<T: NodeInterface>(
    chain_config: Arc<ChainConfig>,
    mut rpc_client: T,
    wallet: Arc<Mutex<DefaultWallet>>,
) {
    loop {
        let (wallet_block_id, wallet_block_height) = wallet
            .lock()
            .await
            .get_best_block()
            .expect("`get_best_block` should not fail normally");

        let sync_state_res = notify_new_block(
            &chain_config,
            &mut rpc_client,
            wallet_block_id,
            wallet_block_height,
        )
        .await;

        match sync_state_res {
            Ok(Some(sync_state)) => {
                let mut wallet = wallet.lock().await;
                let apply_res = apply_sync_state(&chain_config, sync_state, &mut wallet);
                if let Err(e) = apply_res {
                    logging::log::error!("Wallet scan failed: {}", e);
                }
            }
            Ok(None) => {
                // No new blocks
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => {
                logging::log::error!("Node scan failed: {}", e);
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}
