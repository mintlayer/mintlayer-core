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

use std::collections::BTreeMap;

use common::{
    chain::{block::timestamp::BlockTimestamp, Block, ChainConfig, GenBlock},
    primitives::{BlockHeight, Id},
};
use crypto::key::hdkd::u31::U31;
use logging::log;
use node_comm::node_traits::NodeInterface;
use wallet::{wallet_events::WalletEvents, DefaultWallet, WalletResult};

use crate::ControllerError;

const MAX_FETCH_BLOCK_COUNT: usize = 100;

pub trait SyncingWallet {
    fn best_block(&self) -> BTreeMap<U31, (Id<GenBlock>, BlockHeight)>;

    fn scan_blocks(
        &mut self,
        account: U31,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
        wallet_events: &mut impl WalletEvents,
    ) -> WalletResult<()>;

    fn update_median_time(&mut self, median_time: BlockTimestamp) -> WalletResult<()>;
}

impl SyncingWallet for DefaultWallet {
    fn best_block(&self) -> BTreeMap<U31, (Id<GenBlock>, BlockHeight)> {
        self.get_best_block()
    }

    fn scan_blocks(
        &mut self,
        account: U31,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
        wallet_events: &mut impl WalletEvents,
    ) -> WalletResult<()> {
        self.scan_new_blocks(account, common_block_height, blocks, wallet_events)
    }

    fn update_median_time(&mut self, median_time: BlockTimestamp) -> WalletResult<()> {
        self.set_median_time(median_time)
    }
}

struct NextBlockInfo {
    common_block_id: Id<GenBlock>,
    common_block_height: BlockHeight,
}

struct FetchedBlocks {
    blocks: Vec<Block>,
    common_block_height: BlockHeight,
}

#[derive(thiserror::Error, Debug)]
enum FetchBlockError<T: NodeInterface> {
    #[error("Unexpected RPC error: {0}")]
    UnexpectedRpcError(T::Error),
    #[error("No new blocks found")]
    NoNewBlocksFound,
    #[error("Invalid prev block id: {0}, expected: {1}")]
    InvalidPrevBlockId(Id<GenBlock>, Id<GenBlock>),
}

pub async fn sync_once<T: NodeInterface>(
    chain_config: &ChainConfig,
    rpc_client: &T,
    wallet: &mut impl SyncingWallet,
    wallet_events: &mut impl WalletEvents,
) -> Result<(), ControllerError<T>> {
    loop {
        let chain_info =
            rpc_client.chainstate_info().await.map_err(ControllerError::NodeCallError)?;

        let best_blocks = wallet.best_block();

        if best_blocks
            .iter()
            .all(|(_account, wallet_best_block)| chain_info.best_block_id == wallet_best_block.0)
        {
            return Ok(());
        }

        wallet
            .update_median_time(chain_info.median_time)
            .map_err(ControllerError::WalletError)?;

        // Group accounts in the same state
        let mut accounts_grouped: BTreeMap<(Id<GenBlock>, BlockHeight), Vec<U31>> = BTreeMap::new();
        for (account, best_block) in best_blocks.iter() {
            accounts_grouped.entry(*best_block).or_default().push(*account);
        }

        for ((wallet_block_id, wallet_block_height), accounts) in accounts_grouped
            .iter()
            .filter(|(best_block, _accounts)| chain_info.best_block_id != best_block.0)
        {
            fetch_and_sync(
                chain_info.clone(),
                *wallet_block_id,
                *wallet_block_height,
                chain_config,
                rpc_client,
                &mut |common_block_height: BlockHeight, blocks: Vec<Block>| {
                    let block_id =
                        blocks.last().expect("blocks must not be empty").header().block_id();
                    let new_height = common_block_height.into_int() + blocks.len() as u64;

                    for account in accounts.iter() {
                        log::debug!(
                            "Node chainstate updated, account: {}, block height: {}, tip block id: {}",
                            account,
                            new_height,
                            block_id
                        );
                            wallet
                            .scan_blocks(
                                *account,
                                common_block_height,
                                blocks.clone(),
                                wallet_events,
                            )
                            .map_err(ControllerError::WalletError)?;
                    }

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
    wallet_sync: &mut impl FnMut(BlockHeight, Vec<Block>) -> Result<(), ControllerError<T>>,
) -> Result<(), ControllerError<T>> {
    // TODO: use chain trust instead of height
    utils::ensure!(
        chain_info.best_block_height >= wallet_block_height,
        ControllerError::NotEnoughBlockHeight(wallet_block_height, chain_info.best_block_height,)
    );
    let FetchedBlocks {
        blocks,
        common_block_height,
    } = fetch_new_blocks(
        chain_config,
        rpc_client,
        chain_info.best_block_id,
        chain_info.best_block_height,
        wallet_block_id,
        wallet_block_height,
    )
    .await
    .map_err(|e| ControllerError::SyncError(e.to_string()))?;

    wallet_sync(common_block_height, blocks)
}

// TODO: For security reasons, the wallet should probably keep track of latest blocks
// and not allow very large reorgs (for example, the Monero wallet allows reorgs of up to 100 blocks).
async fn get_common_block_info<T: NodeInterface>(
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

    Ok(NextBlockInfo {
        common_block_id,
        common_block_height,
    })
}

// `node_block_height` can't be less than `wallet_block_height` and `node_block_height` can't be equal to `wallet_block_id`
async fn fetch_new_blocks<T: NodeInterface>(
    chain_config: &ChainConfig,
    rpc_client: &T,
    node_block_id: Id<GenBlock>,
    node_block_height: BlockHeight,
    wallet_block_id: Id<GenBlock>,
    wallet_block_height: BlockHeight,
) -> Result<FetchedBlocks, FetchBlockError<T>> {
    let NextBlockInfo {
        common_block_id,
        common_block_height,
    } = get_common_block_info(
        chain_config,
        rpc_client,
        node_block_id,
        node_block_height,
        wallet_block_id,
        wallet_block_height,
    )
    .await?;

    let blocks = rpc_client
        .get_mainchain_blocks(common_block_height.next_height(), MAX_FETCH_BLOCK_COUNT)
        .await
        .map_err(FetchBlockError::UnexpectedRpcError)?;
    match blocks.first() {
        Some(block) => utils::ensure!(
            *block.header().prev_block_id() == common_block_id,
            FetchBlockError::InvalidPrevBlockId(*block.header().prev_block_id(), common_block_id)
        ),
        None => return Err(FetchBlockError::NoNewBlocksFound),
    }

    Ok(FetchedBlocks {
        blocks,
        common_block_height,
    })
}

#[cfg(test)]
mod tests;
