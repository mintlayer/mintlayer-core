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

use std::time::Duration;

use chainstate::ChainInfo;
use common::{
    chain::{Block, ChainConfig, GenBlock},
    primitives::{BlockHeight, Id},
};
use node_comm::node_traits::NodeInterface;
use tokio::sync::mpsc;

struct NextBlockInfo {
    pub common_block_id: Id<GenBlock>,
    pub block_id: Id<Block>,
    pub block_height: BlockHeight,
}

pub struct FetchedBlock {
    pub block: Block,
    pub block_height: BlockHeight,
}

#[derive(thiserror::Error, Debug)]
pub enum FetchBlockError<T: NodeInterface> {
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

pub type BlockFetchResult<T> = Result<FetchedBlock, FetchBlockError<T>>;

pub async fn run_state_sync<T: NodeInterface>(state_tx: mpsc::Sender<ChainInfo>, rpc_client: T) {
    let mut last_state = None;

    while !state_tx.is_closed() {
        let state_res = rpc_client.chainstate_info().await;
        match state_res {
            Ok(state) => {
                if last_state.as_ref() != Some(&state) {
                    _ = state_tx.send(state.clone()).await;
                    last_state = Some(state);
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => {
                logging::log::error!("Node state sync error: {}", e);
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
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
        .get_last_common_block(wallet_block_id, node_block_id)
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
        block_id,
        block_height,
    })
}

pub async fn fetch_new_block<T: NodeInterface>(
    chain_config: &ChainConfig,
    rpc_client: &mut T,
    node_block_id: Id<GenBlock>,
    node_block_height: BlockHeight,
    wallet_block_id: Id<GenBlock>,
    wallet_block_height: BlockHeight,
) -> Result<FetchedBlock, FetchBlockError<T>> {
    let NextBlockInfo {
        common_block_id,
        block_id,
        block_height,
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
        block_height,
    })
}
