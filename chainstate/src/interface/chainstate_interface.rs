// Copyright (c) 2022 RBB S.r.l
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

use std::{collections::BTreeMap, num::NonZeroUsize, sync::Arc};

use crate::{
    detail::BlockSource, ChainInfo, ChainstateConfig, ChainstateError, ChainstateEvent,
    NonZeroPoolBalances,
};
use chainstate_types::{BlockIndex, EpochData, GenBlockIndex, Locator};
use common::{
    chain::{
        block::{
            signed_block_header::SignedBlockHeader, timestamp::BlockTimestamp, Block, BlockReward,
            GenBlock,
        },
        tokens::{RPCTokenInfo, TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, ChainConfig, DelegationId, OrderId, PoolId, RpcOrderInfo,
        Transaction, TxInput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id},
};
use orders_accounting::OrderData;
use pos_accounting::{DelegationData, PoolData};
use utils::eventhandler::EventHandler;
use utils_networking::broadcaster;
use utxo::Utxo;

pub trait ChainstateInterface: Send + Sync {
    fn subscribe_to_subsystem_events(
        &mut self,
        handler: Arc<dyn Fn(ChainstateEvent) + Send + Sync>,
    );
    fn subscribe_to_rpc_events(&mut self) -> broadcaster::Receiver<ChainstateEvent>;
    /// Process the given block. If a reorg occurs, return the block index of the new tip.
    /// Otherwise return None.
    fn process_block(
        &mut self,
        block: Block,
        source: BlockSource,
    ) -> Result<Option<BlockIndex>, ChainstateError>;
    fn invalidate_block(&mut self, block_id: &Id<Block>) -> Result<(), ChainstateError>;
    fn reset_block_failure_flags(&mut self, block_id: &Id<Block>) -> Result<(), ChainstateError>;
    fn preliminary_block_check(&self, block: Block) -> Result<Block, ChainstateError>;

    /// Check the headers. The first header's parent block must be known.
    /// Each following header must be connected to the previous one.
    /// The first header is fully checked; for others, only the most basic checks are performed
    /// (e.g. checkpoint enforcement).
    fn preliminary_headers_check(
        &self,
        headers: &[SignedBlockHeader],
    ) -> Result<(), ChainstateError>;

    fn get_best_block_id(&self) -> Result<Id<GenBlock>, ChainstateError>;
    fn is_block_in_main_chain(&self, block_id: &Id<GenBlock>) -> Result<bool, ChainstateError>;
    fn get_min_height_with_allowed_reorg(&self) -> Result<BlockHeight, ChainstateError>;
    fn get_block_height_in_main_chain(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<BlockHeight>, ChainstateError>;
    fn get_best_block_height(&self) -> Result<BlockHeight, ChainstateError>;
    fn get_best_block_header(&self) -> Result<SignedBlockHeader, ChainstateError>;
    fn get_block_id_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, ChainstateError>;
    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ChainstateError>;
    fn get_mainchain_blocks(
        &self,
        from: BlockHeight,
        max_count: usize,
    ) -> Result<Vec<Block>, ChainstateError>;
    fn get_block_header(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<SignedBlockHeader>, ChainstateError>;

    /// Returns a list of block headers whose heights distances increase exponentially starting
    /// from the current tip.
    ///
    /// This returns a relatively short sequence even for a long chain. Such sequence can be used
    /// to quickly find a common ancestor between different chains.
    fn get_locator(&self) -> Result<Locator, ChainstateError>;

    /// Returns a locator starting from the specified height.
    fn get_locator_from_height(&self, height: BlockHeight) -> Result<Locator, ChainstateError>;

    /// Returns mainchain block ids with heights in the range start_height..end_height using
    /// the given step;
    fn get_block_ids_as_checkpoints(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
        step: NonZeroUsize,
    ) -> Result<Vec<(BlockHeight, Id<GenBlock>)>, ChainstateError>;

    /// Returns a list of mainchain block headers starting from the locator's highest block that
    /// is in the main chain (or genesis, if there is no such block).
    ///
    /// The number of returned headers is limited by `header_count_limit`.
    fn get_mainchain_headers_by_locator(
        &self,
        locator: &Locator,
        header_count_limit: usize,
    ) -> Result<Vec<SignedBlockHeader>, ChainstateError>;

    /// For each block id in the list, find its latest ancestor that is still on the main chain
    /// (the fork point); among the obtained fork points choose the one with the biggest height;
    /// return headers of all mainchain blocks above that height.
    fn get_mainchain_headers_since_latest_fork_point(
        &self,
        block_ids: &[Id<GenBlock>],
        header_count_limit: usize,
    ) -> Result<Vec<SignedBlockHeader>, ChainstateError>;

    /// Find the first header in the passed vector for which the block is not in the chainstate;
    /// split the vector into two parts - first, all headers up to the found one, second, the rest.
    fn split_off_leading_known_headers(
        &self,
        headers: Vec<SignedBlockHeader>,
    ) -> Result<(Vec<SignedBlockHeader>, Vec<SignedBlockHeader>), ChainstateError>;

    /// Return the block index given a block id.
    /// This function will only return block indices for persisted blocks; if the corresponding
    /// block hasn't been persisted, None will be returned.
    fn get_block_index_for_persisted_block(
        &self,
        id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, ChainstateError>;

    /// Return the block index given a block id. The corresponding block may or may not be persisted.
    /// Note that a block index object for a non-persisted block may be deleted from the db at any moment.
    fn get_block_index_for_any_block(
        &self,
        id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, ChainstateError>;

    /// Return the block index given a block id.
    /// This function will only return block indices for persisted blocks; if the corresponding
    /// block hasn't been persisted, None will be returned.
    fn get_gen_block_index_for_persisted_block(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, ChainstateError>;

    /// Return the block index given a block id. The corresponding block may or may not be persisted.
    /// Note that a block index object for a non-persisted block may be deleted from the db at any moment.
    fn get_gen_block_index_for_any_block(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, ChainstateError>;

    fn get_best_block_index(&self) -> Result<GenBlockIndex, ChainstateError>;

    fn get_chain_config(&self) -> &Arc<ChainConfig>;
    fn get_chainstate_config(&self) -> ChainstateConfig;
    fn wait_for_all_events(&self);
    fn subscribers(&self) -> &[EventHandler<ChainstateEvent>];
    fn calculate_median_time_past(
        &self,
        starting_block: &Id<GenBlock>,
    ) -> Result<BlockTimestamp, ChainstateError>;
    fn is_already_an_orphan(&self, block_id: &Id<Block>) -> bool;
    fn orphans_count(&self) -> usize;
    fn get_ancestor(
        &self,
        block_index: &GenBlockIndex,
        ancestor_height: BlockHeight,
    ) -> Result<GenBlockIndex, ChainstateError>;
    fn last_common_ancestor(
        &self,
        first_block_index: &GenBlockIndex,
        second_block_index: &GenBlockIndex,
    ) -> Result<GenBlockIndex, ChainstateError>;
    /// Returns last common block id and height of two chains.
    /// Returns `None` if no block indexes are found and therefore the last common ancestor is unknown.
    fn last_common_ancestor_by_id(
        &self,
        first_block: &Id<GenBlock>,
        second_block: &Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, ChainstateError>;
    fn get_block_reward(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<BlockReward>, ChainstateError>;

    /// Returns epoch data for the given epoch index.
    /// Returns `None` if no epoch data was found.
    fn get_epoch_data(&self, epoch_index: u64) -> Result<Option<EpochData>, ChainstateError>;

    /// Returns token info by `token_id`.
    fn get_token_info_for_rpc(
        &self,
        token_id: TokenId,
    ) -> Result<Option<RPCTokenInfo>, ChainstateError>;
    fn get_token_aux_data(
        &self,
        token_id: TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, ChainstateError>;
    fn get_token_id_from_issuance_tx(
        &self,
        tx_id: &Id<Transaction>,
    ) -> Result<Option<TokenId>, ChainstateError>;
    fn get_token_data(
        &self,
        id: &TokenId,
    ) -> Result<Option<tokens_accounting::TokenData>, ChainstateError>;
    fn get_token_circulating_supply(&self, id: &TokenId)
        -> Result<Option<Amount>, ChainstateError>;

    fn get_order_data(&self, id: &OrderId) -> Result<Option<OrderData>, ChainstateError>;
    fn get_order_ask_balance(&self, id: &OrderId) -> Result<Option<Amount>, ChainstateError>;
    fn get_order_give_balance(&self, id: &OrderId) -> Result<Option<Amount>, ChainstateError>;
    fn get_order_info_for_rpc(
        &self,
        order_id: OrderId,
    ) -> Result<Option<RpcOrderInfo>, ChainstateError>;

    /// Returns the coin amounts of the outpoints spent by a transaction.
    /// If a utxo for an input was not found or contains tokens the result is `None`.
    fn get_inputs_outpoints_coin_amount(
        &self,
        inputs: &[TxInput],
    ) -> Result<Vec<Option<Amount>>, ChainstateError>;

    /// Returns a list of all block ids in mainchain in order (starting from block of height 1, hence the result length is best_height - 1).
    fn get_mainchain_blocks_list(&self) -> Result<Vec<Id<Block>>, ChainstateError>;

    /// Returns a list of all blocks in the block tree, including orphans. The length cannot be predicted before the call.
    fn get_block_id_tree_as_list(&self) -> Result<Vec<Id<Block>>, ChainstateError>;

    /// Imports a bootstrap file exported with `export_bootstrap_stream`.
    fn import_bootstrap_stream<'a>(
        &mut self,
        reader: std::io::BufReader<Box<dyn std::io::Read + Send + 'a>>,
    ) -> Result<(), ChainstateError>;

    /// Writes the blocks of the blockchain into a stream that's meant to go to a file.
    /// The blocks in the stream can be used to resync the blockchain in another node.
    /// NOTE: `include_orphans` here means "include all blocks that are not on mainchain", rather than just
    /// "blocks without a parent".
    fn export_bootstrap_stream<'a>(
        &self,
        writer: std::io::BufWriter<Box<dyn std::io::Write + Send + 'a>>,
        include_orphans: bool,
    ) -> Result<(), ChainstateError>;

    /// Returns the UTXO for a specified OutPoint.
    fn utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, ChainstateError>;

    /// Returns true if the initial block download isn't finished yet.
    fn is_initial_block_download(&self) -> bool;

    /// Check whether stake pool with given ID exists.
    fn stake_pool_exists(&self, pool_id: PoolId) -> Result<bool, ChainstateError>;

    /// Get stake pool balance. See [pos_accounting::PoSAccountingView::get_pool_balance].
    fn get_stake_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, ChainstateError>;

    /// Get balances of the specified stake pools at the specified heights (i.e. at the points
    /// when the mainchain tip had that particular height).
    ///
    /// `min_height` must be less or equal to `max_height`;
    /// `max_height` must be less or equal to the best block height.
    fn get_stake_pool_balances_at_heights(
        &self,
        pool_ids: &[PoolId],
        min_height: BlockHeight,
        max_height: BlockHeight,
    ) -> Result<BTreeMap<BlockHeight, BTreeMap<PoolId, NonZeroPoolBalances>>, ChainstateError>;

    /// Get stake pool data. See [pos_accounting::PoSAccountingView::get_pool_data].
    fn get_stake_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, ChainstateError>;

    /// Get all delegation shares for given stake pool.
    /// See [pos_accounting::PoSAccountingView::get_pool_delegations_shares].
    fn get_stake_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, ChainstateError>;

    /// Get delegation balance for given stake pool delegation ID.
    /// See [pos_accounting::PoSAccountingView::get_delegation_balance].
    fn get_stake_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, ChainstateError>;

    /// Get data for given stake pool delegation ID.
    /// See [pos_accounting::PoSAccountingView::get_delegation_data].
    fn get_stake_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, ChainstateError>;

    /// Get delegation share for given stake pool and delegation.
    /// See [pos_accounting::PoSAccountingView::get_pool_delegation_share].
    fn get_stake_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, ChainstateError>;

    /// Returns information about the chain.
    fn info(&self) -> Result<ChainInfo, ChainstateError>;

    /// Returns account nonce for the account
    fn get_account_nonce_count(
        &self,
        account: AccountType,
    ) -> Result<Option<AccountNonce>, ChainstateError>;
}
