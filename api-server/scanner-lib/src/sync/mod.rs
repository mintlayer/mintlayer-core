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

use common::{
    chain::{Block, ChainConfig, GenBlock},
    primitives::{BlockHeight, Id},
};
pub mod local_state;
mod remote_node;

use self::{local_state::LocalBlockchainState, remote_node::RemoteNode};

const MAX_FETCH_BLOCK_COUNT: usize = 100;

#[derive(thiserror::Error, Debug)]
pub enum SyncError {
    #[error("Unexpected remote node error: {0}")]
    RemoteNode(String),
    #[error("Unexpected local node error: {0}")]
    LocalNode(String),
    #[error("No new blocks found")]
    NoNewBlocksFound,
    #[error("Invalid prev block id: {0}, expected: {1}")]
    InvalidPrevBlockId(Id<GenBlock>, Id<GenBlock>),
    #[error("Attempted to sync the API server to a height that doesn't exist")]
    NotEnoughBlockHeight,
    #[error("Best block retrieval error {0}")]
    BestBlockRetrievalError(String),
}

struct NextBlockInfo {
    common_block_id: Id<GenBlock>,
    common_block_height: BlockHeight,
}

struct FetchedBlocks {
    blocks: Vec<Block>,
    common_block_height: BlockHeight,
}

/// Sync the local node to the current block height of the remote node.
/// This should be run periodically.
pub async fn sync_once(
    chain_config: &ChainConfig,
    rpc_client: &impl RemoteNode,
    local_state: &mut impl LocalBlockchainState,
) -> Result<(), SyncError> {
    loop {
        let chain_info = rpc_client
            .chainstate()
            .await
            .map_err(|e| SyncError::RemoteNode(e.to_string()))?;

        let (best_block_height, best_block_id) = local_state
            .best_block()
            .await
            .map_err(|e| SyncError::BestBlockRetrievalError(e.to_string()))?;

        if chain_info.best_block_id == best_block_id {
            return Ok(());
        }

        logging::log::info!(
            "Found a new best block in node: ({}, {})",
            best_block_height,
            best_block_id
        );

        fetch_and_sync(
            chain_info.clone(),
            best_block_id,
            best_block_height,
            chain_config,
            rpc_client,
            local_state,
        )
        .await?;
    }
}

async fn fetch_and_sync(
    chain_info: chainstate::ChainInfo,
    best_block_id: Id<GenBlock>,
    best_block_height: BlockHeight,
    chain_config: &ChainConfig,
    rpc_client: &impl RemoteNode,
    local_node: &mut impl LocalBlockchainState,
) -> Result<(), SyncError> {
    // TODO: use chain trust instead of height
    utils::ensure!(
        chain_info.best_block_height >= best_block_height,
        SyncError::NotEnoughBlockHeight
    );

    let FetchedBlocks {
        blocks,
        common_block_height,
    } = fetch_new_blocks(
        chain_config,
        rpc_client,
        chain_info,
        best_block_id,
        best_block_height,
    )
    .await?;

    local_node
        .scan_blocks(common_block_height, blocks)
        .await
        .map_err(|e| SyncError::LocalNode(e.to_string()))
}

async fn fetch_new_blocks(
    chain_config: &ChainConfig,
    rpc_client: &impl RemoteNode,
    chain_info: chainstate::ChainInfo,
    best_block_id: Id<GenBlock>,
    best_block_height: BlockHeight,
) -> Result<FetchedBlocks, SyncError> {
    let NextBlockInfo {
        common_block_id,
        common_block_height,
    } = get_common_block_info(
        chain_config,
        rpc_client,
        chain_info,
        best_block_id,
        best_block_height,
    )
    .await?;

    let blocks = rpc_client
        .mainchain_blocks(common_block_height.next_height(), MAX_FETCH_BLOCK_COUNT)
        .await
        .map_err(|e| SyncError::RemoteNode(e.to_string()))?;
    match blocks.first() {
        Some(block) => utils::ensure!(
            *block.header().prev_block_id() == common_block_id,
            SyncError::InvalidPrevBlockId(*block.header().prev_block_id(), common_block_id)
        ),
        None => return Err(SyncError::NoNewBlocksFound),
    }

    Ok(FetchedBlocks {
        blocks,
        common_block_height,
    })
}

async fn get_common_block_info(
    chain_config: &ChainConfig,
    rpc_client: &impl RemoteNode,
    chain_info: chainstate::ChainInfo,
    best_block_id: Id<GenBlock>,
    best_block_height: BlockHeight,
) -> Result<NextBlockInfo, SyncError> {
    assert!(chain_info.best_block_id != best_block_id);
    assert!(chain_info.best_block_height >= best_block_height);

    let common_block_opt = rpc_client
        .last_common_ancestor(best_block_id, chain_info.best_block_id)
        .await
        .map_err(|e| SyncError::RemoteNode(e.to_string()))?;

    let (common_block_id, common_block_height) = match common_block_opt {
        // Common branch is found
        Some(common_block) => common_block,
        // Common branch not found, restart from genesis block.
        // This happens when:
        // 1. The node is downloading blocks.
        // 2. Blocks in the blockchain were pruned, so the block the API server knows about is now unrecognized in the block tree.
        None => (chain_config.genesis_block_id(), BlockHeight::zero()),
    };

    Ok(NextBlockInfo {
        common_block_id,
        common_block_height,
    })
}

#[cfg(test)]
mod tests;
