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

use std::{cmp::Reverse, collections::BTreeMap, iter};

use common::{
    chain::{block::timestamp::BlockTimestamp, Block, ChainConfig, GenBlock},
    primitives::{BlockHeight, Id},
};
use crypto::key::hdkd::u31::U31;
use logging::log;
use node_comm::node_traits::NodeInterface;
use wallet::{
    wallet::WalletSyncingState, wallet_events::WalletEvents, DefaultWallet, WalletResult,
};

use crate::ControllerError;

const MAX_FETCH_BLOCK_COUNT: usize = 100;

pub trait SyncingWallet {
    fn syncing_state(&self) -> WalletSyncingState;

    fn scan_blocks(
        &mut self,
        account: U31,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
        wallet_events: &impl WalletEvents,
    ) -> WalletResult<()>;

    fn scan_blocks_for_unused_account(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
        wallet_events: &impl WalletEvents,
    ) -> WalletResult<()>;

    fn update_median_time(&mut self, median_time: BlockTimestamp) -> WalletResult<()>;
}

impl SyncingWallet for DefaultWallet {
    fn syncing_state(&self) -> WalletSyncingState {
        self.get_syncing_state()
    }

    fn scan_blocks(
        &mut self,
        account: U31,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
        wallet_events: &impl WalletEvents,
    ) -> WalletResult<()> {
        self.scan_new_blocks(account, common_block_height, blocks, wallet_events)
    }

    fn scan_blocks_for_unused_account(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
        wallet_events: &impl WalletEvents,
    ) -> WalletResult<()> {
        self.scan_new_blocks_unused_account(common_block_height, blocks, wallet_events)
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

enum AccountType {
    Account(U31),
    UnusedAccount,
}

pub async fn sync_once<T: NodeInterface>(
    chain_config: &ChainConfig,
    rpc_client: &T,
    wallet: &mut impl SyncingWallet,
    wallet_events: &impl WalletEvents,
) -> Result<(), ControllerError<T>> {
    loop {
        let chain_info =
            rpc_client.chainstate_info().await.map_err(ControllerError::NodeCallError)?;

        let WalletSyncingState {
            account_best_blocks,
            unused_account_best_block,
        } = wallet.syncing_state();
        if account_best_blocks
            .values()
            .chain(iter::once(&unused_account_best_block))
            .all(|wallet_best_block| chain_info.best_block_id == wallet_best_block.0)
        {
            // if all accounts are on the latest tip nothing to sync
            return Ok(());
        }

        wallet
            .update_median_time(chain_info.median_time)
            .map_err(ControllerError::WalletError)?;

        // Group accounts in the same state
        let mut accounts_grouped = group_accounts_by_common_block(
            chain_config,
            rpc_client,
            chain_info.best_block_id,
            chain_info.best_block_height,
            account_best_blocks,
            unused_account_best_block,
        )
        .await?;

        let mut current = accounts_grouped.pop().expect("empty accounts");
        while let Some(mut next) = accounts_grouped.pop() {
            // fetch blocks up to the next account group
            let block_to_fetch = (next.0.common_block_height - current.0.common_block_height)
                .expect("already sorted")
                .to_int() as usize;

            fetch_and_sync(&current, block_to_fetch, rpc_client, wallet, wallet_events).await?;

            current.1.append(&mut next.1);
        }

        fetch_and_sync(
            &current,
            MAX_FETCH_BLOCK_COUNT,
            rpc_client,
            wallet,
            wallet_events,
        )
        .await?;
    }
}

async fn fetch_and_sync<T: NodeInterface>(
    accounts: &(NextBlockInfo, Vec<AccountType>),
    block_to_fetch: usize,
    rpc_client: &T,
    wallet: &mut impl SyncingWallet,
    wallet_events: &impl WalletEvents,
) -> Result<(), ControllerError<T>> {
    let FetchedBlocks {
        blocks,
        common_block_height,
    } = fetch_next_blocks(&accounts.0, block_to_fetch, rpc_client)
        .await
        .map_err(|e| ControllerError::SyncError(e.to_string()))?;
    let block_id = blocks.last().expect("blocks must not be empty").header().block_id();
    let new_height = common_block_height.into_int() + blocks.len() as u64;
    for account in accounts.1.iter() {
        scan_new_blocks(
            account,
            new_height,
            block_id,
            wallet,
            common_block_height,
            blocks.clone(),
            wallet_events,
        )?;
    }

    Ok(())
}

fn scan_new_blocks<T: NodeInterface>(
    acc: &AccountType,
    new_height: u64,
    block_id: Id<Block>,
    wallet: &mut impl SyncingWallet,
    common_block_height: BlockHeight,
    blocks: Vec<Block>,
    wallet_events: &impl WalletEvents,
) -> Result<(), ControllerError<T>> {
    match acc {
        AccountType::Account(account) => {
            log::debug!(
                "Node chainstate updated, account: {}, block height: {}, tip block id: {}",
                account,
                new_height,
                block_id
            );
            wallet
                .scan_blocks(*account, common_block_height, blocks, wallet_events)
                .map_err(ControllerError::WalletError)?;
        }
        AccountType::UnusedAccount => {
            log::debug!(
                "Node chainstate updated, unused account, block height: {}, tip block id: {}",
                new_height,
                block_id
            );

            wallet
                .scan_blocks_for_unused_account(common_block_height, blocks, wallet_events)
                .map_err(ControllerError::WalletError)?;
        }
    }

    Ok(())
}

async fn fetch_next_blocks<T: NodeInterface>(
    current: &NextBlockInfo,
    block_to_fetch: usize,
    rpc_client: &T,
) -> Result<FetchedBlocks, FetchBlockError<T>> {
    let blocks = rpc_client
        .get_mainchain_blocks(current.common_block_height.next_height(), block_to_fetch)
        .await
        .map_err(FetchBlockError::UnexpectedRpcError)?;
    match blocks.first() {
        Some(block) => utils::ensure!(
            *block.header().prev_block_id() == current.common_block_id,
            FetchBlockError::InvalidPrevBlockId(
                *block.header().prev_block_id(),
                current.common_block_id
            )
        ),
        None => return Err(FetchBlockError::NoNewBlocksFound),
    }

    Ok(FetchedBlocks {
        blocks,
        common_block_height: current.common_block_height,
    })
}

/// Group the accounts by the highest common block on the mainchain
/// and sort them in descending order from highest to lowest
async fn group_accounts_by_common_block<T: NodeInterface>(
    chain_config: &ChainConfig,
    rpc_client: &T,
    node_block_id: Id<GenBlock>,
    node_block_height: BlockHeight,
    account_best_blocks: BTreeMap<U31, (Id<GenBlock>, BlockHeight)>,
    unused_account_best_block: (Id<GenBlock>, BlockHeight),
) -> Result<Vec<(NextBlockInfo, Vec<AccountType>)>, ControllerError<T>> {
    let mut accounts_grouped: BTreeMap<(Id<GenBlock>, BlockHeight), Vec<AccountType>> =
        BTreeMap::new();
    for (account, best_block) in account_best_blocks.iter() {
        accounts_grouped
            .entry(*best_block)
            .or_default()
            .push(AccountType::Account(*account));
    }
    accounts_grouped
        .entry(unused_account_best_block)
        .or_default()
        .push(AccountType::UnusedAccount);

    let mut accounts_by_common_block = Vec::new();
    for ((acc_block_id, acc_block_height), acc) in accounts_grouped {
        let common_block = get_common_block_info(
            chain_config,
            rpc_client,
            node_block_id,
            node_block_height,
            acc_block_id,
            acc_block_height,
        )
        .await
        .map_err(|e| ControllerError::SyncError(e.to_string()))?;

        accounts_by_common_block.push((common_block, acc));
    }

    // sort by height
    accounts_by_common_block.sort_by_key(|(info, _acc)| Reverse(info.common_block_height));

    Ok(accounts_by_common_block)
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

#[cfg(test)]
mod tests;
