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
use serialization::hex::HexEncode;
use tokio::sync::Mutex;
use wallet::DefaultWallet;

#[derive(thiserror::Error, Debug)]
pub enum SyncError {
    #[error("Unexpected RPC error: {0}")]
    UnexpectedRpcError(String),
    #[error("Unexpected wallet error: {0}")]
    UnexpectedWalletError(wallet::WalletError),
}

/// Sync the wallet state (known blocks) from the node.
/// Returns true if the wallet state has changed.
async fn sync_blocks<T: NodeInterface>(
    chain_config: &ChainConfig,
    rpc_client: &mut T,
    wallet: Arc<Mutex<DefaultWallet>>,
) -> Result<bool, SyncError> {
    // TODO: Make it more efficient: download blocks concurrently and send fewer requests

    let wallet_block_height_opt = wallet
        .lock()
        .await
        .get_best_block_height()
        .map_err(SyncError::UnexpectedWalletError)?;
    let wallet_block_height = match wallet_block_height_opt {
        Some(height) => height,
        None => {
            wallet.lock().await.scan_genesis().map_err(SyncError::UnexpectedWalletError)?;
            return Ok(true);
        }
    };

    if wallet_block_height > BlockHeight::zero() {
        let wallet_best_block = wallet
            .lock()
            .await
            .get_block_hash(wallet_block_height)
            .map_err(SyncError::UnexpectedWalletError)?
            .expect("block id is expected to be known to the wallet");

        let node_best_block = rpc_client
            .get_best_block_id()
            .await
            .map_err(|e| SyncError::UnexpectedRpcError(e.to_string()))?;

        let common_height_opt = rpc_client
            .get_last_common_height(wallet_best_block.into(), node_best_block)
            .await
            .map_err(|e| SyncError::UnexpectedRpcError(e.to_string()))?;
        let common_height = match common_height_opt {
            Some(heigth) => heigth,
            None => {
                // No common block found for some reason. This can happen if the wallet is on an abandoned chain
                // and the node has never seen it before. Reset the wallet to an older block and start over.
                let prev_height = wallet_block_height
                    .prev_height()
                    .expect("Must succeed because `wallet_block_height` is greater than zero");
                logging::log::debug!(
                    "No common block found, reset wallet to {wallet_block_height}"
                );
                wallet
                    .lock()
                    .await
                    .reset_to_height(prev_height)
                    .map_err(SyncError::UnexpectedWalletError)?;
                return Ok(true);
            }
        };

        if common_height < wallet_block_height {
            logging::log::debug!(
                "Reorg detected, reset from {wallet_block_height} to {common_height}"
            );
            wallet
                .lock()
                .await
                .reset_to_height(common_height)
                .map_err(SyncError::UnexpectedWalletError)?;
        }
    }

    let next_block_height = wallet_block_height.next_height();
    let next_block_id_opt = rpc_client
        .get_block_id_at_height(next_block_height)
        .await
        .map_err(|e| SyncError::UnexpectedRpcError(e.to_string()))?;
    let next_gen_block_id = match next_block_id_opt {
        Some(id) => id,
        None => return Ok(false),
    };
    let next_block_id = match next_gen_block_id.classify(chain_config) {
        common::chain::GenBlockId::Genesis(_) => {
            return Err(SyncError::UnexpectedRpcError(format!(
                "Received the genesis block at positive hight {next_block_height}"
            )))
        }
        common::chain::GenBlockId::Block(id) => id,
    };

    let new_block = rpc_client
        .get_block(next_block_id)
        .await
        .map_err(|e| SyncError::UnexpectedRpcError(e.to_string()))?
        .ok_or_else(|| {
            SyncError::UnexpectedRpcError(format!(
                "Advertised block with id {} not found",
                next_block_id.hex_encode()
            ))
        })?;

    // This may fail if there was a reorg after this function was started.
    // It should resolve normally next time.
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
