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
    chain::{block::timestamp::BlockTimestamp, Block, ChainConfig, GenBlock},
    primitives::{BlockHeight, Id},
};
use logging::log;
use node_comm::node_traits::NodeInterface;
use serialization::hex::HexEncode;
use wallet::{DefaultWallet, WalletResult};

use crate::ControllerError;

pub trait SyncingWallet {
    fn best_block(&self) -> WalletResult<(Id<GenBlock>, BlockHeight)>;

    fn scan_blocks(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
    ) -> WalletResult<()>;

    fn update_median_time(&mut self, median_time: BlockTimestamp) -> WalletResult<()>;

    fn best_block_unsynced_acc(&self) -> Option<(Id<GenBlock>, BlockHeight)>;

    fn scan_blocks_unsynced_acc(
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

    fn update_median_time(&mut self, median_time: BlockTimestamp) -> WalletResult<()> {
        self.set_median_time(median_time)
    }

    fn best_block_unsynced_acc(&self) -> Option<(Id<GenBlock>, BlockHeight)> {
        self.get_best_block_for_unsynced_account()
    }

    fn scan_blocks_unsynced_acc(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
    ) -> WalletResult<()> {
        self.scan_new_blocks_for_unsynced_account(common_block_height, blocks)
    }
}

struct NextBlockInfo {
    common_block_id: Id<GenBlock>,
    common_block_height: BlockHeight,
    block_id: Id<Block>,
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

pub async fn sync_once<T: NodeInterface>(
    chain_config: &ChainConfig,
    rpc_client: &T,
    wallet: &mut impl SyncingWallet,
) -> Result<(), ControllerError<T>> {
    loop {
        let chain_info =
            rpc_client.chainstate_info().await.map_err(ControllerError::NodeCallError)?;

        // first sync the unsynced account until it matches the other accounts
        if let Some((wallet_block_id, wallet_block_height)) = wallet.best_block_unsynced_acc() {
            fetch_and_sync(
                chain_info,
                wallet_block_id,
                wallet_block_height,
                chain_config,
                rpc_client,
                &mut |common_block_height: BlockHeight, block: Block| {
                    let block_id = block.header().block_id();
                    wallet
                        .scan_blocks_unsynced_acc(common_block_height, vec![block])
                        .map_err(ControllerError::<T>::WalletError)?;

                    log::info!(
                        "Node chainstate updated for new account, block height: {}, tip block id: {}",
                        common_block_height.next_height(),
                        block_id.hex_encode()
                    );

                    Ok(())
                },
            )
            .await?;
        } else {
            let (wallet_block_id, wallet_block_height) =
                wallet.best_block().map_err(ControllerError::WalletError)?;

            if chain_info.best_block_id == wallet_block_id {
                return Ok(());
            }
            wallet
                .update_median_time(chain_info.median_time)
                .map_err(ControllerError::WalletError)?;
            fetch_and_sync(
                chain_info,
                wallet_block_id,
                wallet_block_height,
                chain_config,
                rpc_client,
                &mut |common_block_height: BlockHeight, block: Block| {
                    let block_id = block.header().block_id();
                    wallet
                        .scan_blocks(common_block_height, vec![block])
                        .map_err(ControllerError::WalletError)?;
                    log::info!(
                        "Node chainstate updated, block height: {}, tip block id: {}",
                        common_block_height.next_height(),
                        block_id.hex_encode()
                    );

                    Ok(())
                },
            )
            .await?;
        }
    }
}

async fn fetch_and_sync<T: NodeInterface>(
    chain_info: chainstate::ChainInfo,
    wallet_block_id: Id<GenBlock>,
    wallet_block_height: BlockHeight,
    chain_config: &ChainConfig,
    rpc_client: &T,
    wallet_sync: &mut impl FnMut(BlockHeight, Block) -> Result<(), ControllerError<T>>,
) -> Result<(), ControllerError<T>> {
    // TODO: use chain trust instead of height
    utils::ensure!(
        chain_info.best_block_height >= wallet_block_height,
        ControllerError::NotEnoughBlockHeight(wallet_block_height, chain_info.best_block_height,)
    );
    let FetchedBlock { block, common_block_height } = fetch_new_block(
        chain_config,
        rpc_client,
        chain_info.best_block_id,
        chain_info.best_block_height,
        wallet_block_id,
        wallet_block_height,
    )
    .await
    .map_err(|e| ControllerError::SyncError(e.to_string()))?;

    wallet_sync(common_block_height, block)
}

// TODO: For security reasons, the wallet should probably keep track of latest blocks
// and not allow very large reorgs (for example, the Monero wallet allows reorgs of up to 100 blocks).
async fn get_next_block_info<T: NodeInterface>(
    chain_config: &ChainConfig,
    rpc_client: &T,
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

    Ok(NextBlockInfo { common_block_id, common_block_height, block_id })
}

// `node_block_height` can't be less than `wallet_block_height` and `node_block_height` can't be equal to `wallet_block_id`
async fn fetch_new_block<T: NodeInterface>(
    chain_config: &ChainConfig,
    rpc_client: &T,
    node_block_id: Id<GenBlock>,
    node_block_height: BlockHeight,
    wallet_block_id: Id<GenBlock>,
    wallet_block_height: BlockHeight,
) -> Result<FetchedBlock, FetchBlockError<T>> {
    let NextBlockInfo { common_block_id, common_block_height, block_id } = get_next_block_info(
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

    Ok(FetchedBlock { block, common_block_height })
}

#[cfg(test)]
mod tests;
