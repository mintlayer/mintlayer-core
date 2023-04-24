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

use common::{chain::ChainConfig, primitives::BlockHeight};
use node_comm::node_traits::NodeInterface;
use tokio::sync::Mutex;
use wallet::DefaultWallet;

#[derive(thiserror::Error, Debug)]
pub enum SyncError {
    #[error("Unexpected RPC error: {0}")]
    UnexpectedRpcError(String),
    #[error("Unexpected wallet error: {0}")]
    UnexpectedWalletError(wallet::WalletError),
}

/// Sync the wallet state (blocks) from the node.
/// Returns true if the wallet state has changed and false otherwise.
async fn sync_blocks<T: NodeInterface>(
    chain_config: &ChainConfig,
    rpc_client: &mut T,
    wallet: Arc<Mutex<DefaultWallet>>,
) -> Result<bool, SyncError> {
    // TODO: Make it more efficient: download blocks concurrently and send fewer requests
    let wallet_block_height = match wallet
        .lock()
        .await
        .get_best_block_height()
        .map_err(SyncError::UnexpectedWalletError)?
    {
        Some(height) => height,
        None => {
            wallet.lock().await.scan_genesis().map_err(SyncError::UnexpectedWalletError)?;
            return Ok(true);
        }
    };

    let node_block_height = rpc_client
        .get_best_block_height()
        .await
        .map_err(|e| SyncError::UnexpectedRpcError(e.to_string()))?;

    if node_block_height <= wallet_block_height {
        return Ok(false);
    }

    if wallet_block_height > BlockHeight::zero() {
        let node_block_id = match rpc_client
            .get_block_id_at_height(wallet_block_height)
            .await
            .map_err(|e| SyncError::UnexpectedRpcError(e.to_string()))?
        {
            Some(id) => id,
            None => {
                return Err(SyncError::UnexpectedRpcError(format!(
                    "Node block height is {node_block_height} but block at height {wallet_block_height} is None"
                )));
            }
        };
        let wallet_block_id = match wallet
            .lock()
            .await
            .get_block_hash(wallet_block_height)
            .map_err(SyncError::UnexpectedWalletError)?
        {
            Some(id) => id,
            None => panic!("Wallet block height is {wallet_block_height} but the block is None"),
        };

        if node_block_id != wallet_block_id {
            wallet
                .lock()
                .await
                .reset_to_height(
                    wallet_block_height
                        .prev_height()
                        .expect("Must succeed because `wallet_block_height` is not zero"),
                )
                .map_err(SyncError::UnexpectedWalletError)?;
            return Ok(true);
        }
    }

    let new_block_height = wallet_block_height.next_height();
    let new_block_id = match rpc_client
        .get_block_id_at_height(new_block_height)
        .await
        .map_err(|e| SyncError::UnexpectedRpcError(e.to_string()))?
    {
        Some(id) => id,
        None => return Err(SyncError::UnexpectedRpcError(format!(
            "Node block height is {node_block_height} but block at height {new_block_height} is None"
        ))),
    };
    let new_block_id = match new_block_id.classify(chain_config) {
        common::chain::GenBlockId::Genesis(_) => {
            return Err(SyncError::UnexpectedRpcError(format!(
                "Node returned genesis block at height {new_block_height}"
            )))
        }
        common::chain::GenBlockId::Block(block_id) => block_id,
    };

    let new_block = match rpc_client
        .get_block(new_block_id)
        .await
        .map_err(|e| SyncError::UnexpectedRpcError(e.to_string()))?
    {
        Some(block) => block,
        None => {
            return Err(SyncError::UnexpectedRpcError(format!(
                "Advertised block with id {new_block_id} not found"
            )))
        }
    };

    // This may fail if there was a reorg before the `get_block_id_at_height` and `get_block` calls,
    // but it should resolve normally next time.
    wallet
        .lock()
        .await
        .scan_new_blocks(vec![new_block])
        .map_err(SyncError::UnexpectedWalletError)?;
    Ok(true)
}

pub async fn run_sync<T: NodeInterface>(
    chain_config: Arc<ChainConfig>,
    mut rpc_client: T,
    wallet: Arc<Mutex<DefaultWallet>>,
) {
    loop {
        let res = sync_blocks(&chain_config, &mut rpc_client, Arc::clone(&wallet)).await;
        match res {
            Ok(true) => {}
            Ok(false) => {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => {
                logging::log::error!("Wallet scan failed: {}", e);
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}
