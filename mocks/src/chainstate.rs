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

use chainstate::{
    BlockSource, ChainInfo, ChainstateConfig, ChainstateError, ChainstateEvent, Locator,
};
use chainstate_types::{BlockIndex, EpochData, GenBlockIndex};
use common::{
    chain::{
        block::{
            signed_block_header::SignedBlockHeader, timestamp::BlockTimestamp, Block, BlockReward,
            GenBlock,
        },
        tokens::{RPCTokenInfo, TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, ChainConfig, DelegationId, OrderId, PoolId, RpcOrderInfo,
        TxInput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id},
};
use orders_accounting::OrderData;
use pos_accounting::PoolData;
use utils::eventhandler::EventHandler;
use utxo::Utxo;

use chainstate::chainstate_interface::ChainstateInterface;

mockall::mock! {
    pub ChainstateInterface {}

    impl ChainstateInterface for ChainstateInterface {
        fn subscribe_to_subsystem_events(&mut self, handler: Arc<dyn Fn(ChainstateEvent) + Send + Sync>);
        fn subscribe_to_rpc_events(&mut self) -> utils_networking::broadcaster::Receiver<ChainstateEvent>;
        fn process_block(&mut self, block: Block, source: BlockSource) -> Result<Option<BlockIndex>, ChainstateError>;
        fn invalidate_block(&mut self, block_id: &Id<Block>) -> Result<(), ChainstateError>;
        fn reset_block_failure_flags(&mut self, block_id: &Id<Block>) -> Result<(), ChainstateError>;
        fn preliminary_block_check(&self, block: Block) -> Result<Block, ChainstateError>;
        fn preliminary_headers_check(
            &self,
            headers: &[SignedBlockHeader],
        )-> Result<(), ChainstateError>;
        fn get_best_block_id(&self) -> Result<Id<GenBlock>, ChainstateError>;
        fn get_best_block_height(&self) -> Result<BlockHeight, ChainstateError>;
        fn get_best_block_header(&self) -> Result<SignedBlockHeader, ChainstateError>;
        fn is_block_in_main_chain(&self, block_id: &Id<GenBlock>) -> Result<bool, ChainstateError>;
        fn get_min_height_with_allowed_reorg(&self) -> Result<BlockHeight, ChainstateError>;
        fn get_block_height_in_main_chain(
            &self,
            block_id: &Id<GenBlock>,
        ) -> Result<Option<BlockHeight>, ChainstateError>;
        fn get_block_id_from_height(
            &self,
            height: &BlockHeight,
        ) -> Result<Option<Id<GenBlock>>, ChainstateError>;
        fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ChainstateError>;
        fn get_mainchain_blocks(
            &self,
            start_block_height: BlockHeight,
            max_count: usize,
        ) -> Result<Vec<Block>, ChainstateError>;
        fn get_block_header(&self, block_id: Id<Block>) -> Result<Option<SignedBlockHeader>, ChainstateError>;
        fn get_locator(&self) -> Result<Locator, ChainstateError>;
        fn get_locator_from_height(&self, height: BlockHeight) -> Result<Locator, ChainstateError>;
        fn get_block_ids_as_checkpoints(
            &self,
            start_height: BlockHeight,
            end_height: BlockHeight,
            step: NonZeroUsize,
        ) -> Result<Vec<(BlockHeight, Id<GenBlock>)>, ChainstateError>;
        fn get_mainchain_headers_by_locator(
            &self,
            locator: &Locator,
            header_count_limit: usize,
        ) -> Result<Vec<SignedBlockHeader>, ChainstateError>;
        fn get_mainchain_headers_since_latest_fork_point(
            &self,
            block_ids: &[Id<GenBlock>],
            header_count_limit: usize,
        ) -> Result<Vec<SignedBlockHeader>, ChainstateError>;
        fn split_off_leading_known_headers(
            &self,
            headers: Vec<SignedBlockHeader>,
        ) -> Result<(Vec<SignedBlockHeader>, Vec<SignedBlockHeader>), ChainstateError>;
        fn get_block_index_for_persisted_block(
            &self,
            id: &Id<Block>
        ) -> Result<Option<BlockIndex>, ChainstateError>;
        fn get_block_index_for_any_block(
            &self,
            id: &Id<Block>
        ) -> Result<Option<BlockIndex>, ChainstateError>;
        fn get_gen_block_index_for_persisted_block(
            &self,
            id: &Id<GenBlock>,
        ) -> Result<Option<GenBlockIndex>, ChainstateError>;
        fn get_gen_block_index_for_any_block(
            &self,
            id: &Id<GenBlock>,
        ) -> Result<Option<GenBlockIndex>, ChainstateError>;
        fn get_chain_config(&self) -> &Arc<ChainConfig>;
        fn get_best_block_index(&self) -> Result<chainstate_types::GenBlockIndex, ChainstateError>;
        fn get_chainstate_config(&self) -> ChainstateConfig;
        fn wait_for_all_events(&self);
        fn subscribers(&self) -> &[EventHandler<ChainstateEvent>];
        fn calculate_median_time_past(&self, starting_block: &Id<GenBlock>) -> Result<BlockTimestamp, ChainstateError>;
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
        fn last_common_ancestor_by_id(
            &self,
            first_block: &Id<GenBlock>,
            second_block: &Id<GenBlock>,
        ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, ChainstateError>;
        fn get_block_reward(
            &self,
            block_index: &BlockIndex,
        ) -> Result<Option<BlockReward>, ChainstateError>;
        fn get_epoch_data(&self, epoch_index: u64) -> Result<Option<EpochData>, ChainstateError>;
        fn get_token_info_for_rpc(&self, token_id: TokenId) -> Result<Option<RPCTokenInfo>, ChainstateError>;
        fn get_token_aux_data(
            &self,
            token_id: TokenId,
        ) -> Result<Option<TokenAuxiliaryData>, ChainstateError>;
        fn get_token_id_from_issuance_tx(
            &self,
            tx_id: &Id<common::chain::Transaction>,
        ) -> Result<Option<TokenId>, ChainstateError>;
        fn get_token_data(
            &self,
            id: &TokenId,
        ) -> Result<Option<tokens_accounting::TokenData>, ChainstateError>;
        fn get_token_circulating_supply(&self, id: &TokenId) -> Result<Option<Amount>, ChainstateError>;
        fn get_inputs_outpoints_coin_amount(
            &self,
            inputs: &[TxInput],
        ) -> Result<Vec<Option<Amount>>, ChainstateError>;
        fn get_mainchain_blocks_list(&self) -> Result<Vec<Id<Block>>, ChainstateError>;
        fn get_block_id_tree_as_list(&self) -> Result<Vec<Id<Block>>, ChainstateError>;
        fn import_bootstrap_stream<'a>(
            &'a mut self,
            reader: std::io::BufReader<Box<dyn std::io::Read + Send + 'a>>,
        ) -> Result<(), ChainstateError>;
        fn export_bootstrap_stream<'a>(
            &'a self,
            writer: std::io::BufWriter<Box<dyn std::io::Write + Send + 'a>>,
            include_stale_blocks: bool,
        ) -> Result<(), ChainstateError>;
        fn utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, ChainstateError>;
        fn is_initial_block_download(&self) -> bool;
        fn stake_pool_exists(&self, pool_id: PoolId) -> Result<bool, ChainstateError>;
        fn get_stake_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, ChainstateError>;
        fn get_stake_pool_balances_at_heights(
            &self,
            pool_ids: &[PoolId],
            min_height: BlockHeight,
            max_height: BlockHeight,
        ) -> Result<BTreeMap<BlockHeight, BTreeMap<PoolId, chainstate::NonZeroPoolBalances>>, ChainstateError>;
        fn get_stake_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, ChainstateError>;
        fn get_stake_pool_delegations_shares(
            &self,
            pool_id: PoolId,
        ) -> Result<Option<std::collections::BTreeMap<DelegationId, Amount>>, ChainstateError>;
        fn get_stake_delegation_balance(
            &self,
            delegation_id: DelegationId,
        ) -> Result<Option<Amount>, ChainstateError>;
        fn get_stake_delegation_data(
            &self,
            delegation_id: DelegationId,
        ) -> Result<Option<pos_accounting::DelegationData>, ChainstateError>;
        fn get_stake_pool_delegation_share(
            &self,
            pool_id: PoolId,
            delegation_id: DelegationId,
        ) -> Result<Option<Amount>, ChainstateError>;
        fn info(&self) -> Result<ChainInfo, ChainstateError>;
        fn get_account_nonce_count(
            &self,
            account: AccountType,
        ) -> Result<Option<AccountNonce>, ChainstateError>;

        fn get_order_data(&self, id: &OrderId) -> Result<Option<OrderData>, ChainstateError>;
        fn get_order_ask_balance(&self, id: &OrderId) -> Result<Option<Amount>, ChainstateError>;
        fn get_order_give_balance(&self, id: &OrderId) -> Result<Option<Amount>, ChainstateError>;
        fn get_order_info_for_rpc(&self, id: OrderId) -> Result<Option<RpcOrderInfo>, ChainstateError>;
    }
}

impl subsystem::Subsystem for MockChainstateInterface {
    type Interface = dyn ChainstateInterface;

    fn interface_ref(&self) -> &Self::Interface {
        self
    }

    fn interface_mut(&mut self) -> &mut Self::Interface {
        self
    }
}
