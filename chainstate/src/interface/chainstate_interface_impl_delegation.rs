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

use std::{
    collections::BTreeMap,
    num::NonZeroUsize,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use chainstate_types::{BlockIndex, EpochData, GenBlockIndex, Locator};
use common::{
    chain::{
        block::{signed_block_header::SignedBlockHeader, timestamp::BlockTimestamp, BlockReward},
        config::ChainConfig,
        tokens::{RPCTokenInfo, TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, Block, DelegationId, GenBlock, OrderId, PoolId, RpcOrderInfo,
        Transaction, TxInput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id},
};
use orders_accounting::OrderData;
use pos_accounting::{DelegationData, PoolData};
use utils::eventhandler::EventHandler;
use utils_networking::broadcaster;
use utxo::Utxo;

use crate::{
    chainstate_interface::ChainstateInterface, BlockSource, ChainInfo, ChainstateConfig,
    ChainstateError, ChainstateEvent, NonZeroPoolBalances,
};

impl<T: Deref + DerefMut + Send + Sync> ChainstateInterface for T
where
    T::Target: ChainstateInterface,
{
    fn subscribe_to_subsystem_events(
        &mut self,
        handler: Arc<dyn Fn(ChainstateEvent) + Send + Sync>,
    ) {
        self.deref_mut().subscribe_to_subsystem_events(handler)
    }

    fn subscribe_to_rpc_events(&mut self) -> broadcaster::Receiver<ChainstateEvent> {
        self.deref_mut().subscribe_to_rpc_events()
    }

    fn process_block(
        &mut self,
        block: Block,
        source: BlockSource,
    ) -> Result<Option<BlockIndex>, ChainstateError> {
        self.deref_mut().process_block(block, source)
    }

    fn invalidate_block(&mut self, block_id: &Id<Block>) -> Result<(), ChainstateError> {
        self.deref_mut().invalidate_block(block_id)
    }

    fn reset_block_failure_flags(&mut self, block_id: &Id<Block>) -> Result<(), ChainstateError> {
        self.deref_mut().reset_block_failure_flags(block_id)
    }

    fn preliminary_block_check(&self, block: Block) -> Result<Block, ChainstateError> {
        self.deref().preliminary_block_check(block)
    }

    fn preliminary_headers_check(
        &self,
        headers: &[SignedBlockHeader],
    ) -> Result<(), ChainstateError> {
        self.deref().preliminary_headers_check(headers)
    }

    fn get_best_block_id(&self) -> Result<Id<GenBlock>, ChainstateError> {
        self.deref().get_best_block_id()
    }

    fn is_block_in_main_chain(&self, block_id: &Id<GenBlock>) -> Result<bool, ChainstateError> {
        self.deref().is_block_in_main_chain(block_id)
    }

    fn get_min_height_with_allowed_reorg(&self) -> Result<BlockHeight, ChainstateError> {
        self.deref().get_min_height_with_allowed_reorg()
    }

    fn get_block_height_in_main_chain(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<BlockHeight>, ChainstateError> {
        self.deref().get_block_height_in_main_chain(block_id)
    }

    fn get_best_block_height(&self) -> Result<BlockHeight, ChainstateError> {
        self.deref().get_best_block_height()
    }

    fn get_best_block_header(&self) -> Result<SignedBlockHeader, ChainstateError> {
        self.deref().get_best_block_header()
    }

    fn get_block_id_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, ChainstateError> {
        self.deref().get_block_id_from_height(height)
    }

    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ChainstateError> {
        self.deref().get_block(block_id)
    }

    fn get_mainchain_blocks(
        &self,
        from: BlockHeight,
        max_count: usize,
    ) -> Result<Vec<Block>, ChainstateError> {
        self.deref().get_mainchain_blocks(from, max_count)
    }

    fn get_locator(&self) -> Result<Locator, ChainstateError> {
        self.deref().get_locator()
    }

    fn get_locator_from_height(&self, height: BlockHeight) -> Result<Locator, ChainstateError> {
        self.deref().get_locator_from_height(height)
    }

    fn get_block_ids_as_checkpoints(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
        step: NonZeroUsize,
    ) -> Result<Vec<(BlockHeight, Id<GenBlock>)>, ChainstateError> {
        self.deref().get_block_ids_as_checkpoints(start_height, end_height, step)
    }

    fn get_mainchain_headers_by_locator(
        &self,
        locator: &Locator,
        header_count_limit: usize,
    ) -> Result<Vec<SignedBlockHeader>, ChainstateError> {
        self.deref().get_mainchain_headers_by_locator(locator, header_count_limit)
    }

    fn get_mainchain_headers_since_latest_fork_point(
        &self,
        block_ids: &[Id<GenBlock>],
        header_count_limit: usize,
    ) -> Result<Vec<SignedBlockHeader>, ChainstateError> {
        self.deref()
            .get_mainchain_headers_since_latest_fork_point(block_ids, header_count_limit)
    }

    fn split_off_leading_known_headers(
        &self,
        headers: Vec<SignedBlockHeader>,
    ) -> Result<(Vec<SignedBlockHeader>, Vec<SignedBlockHeader>), ChainstateError> {
        self.deref().split_off_leading_known_headers(headers)
    }

    fn get_block_index_for_persisted_block(
        &self,
        id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, ChainstateError> {
        self.deref().get_block_index_for_persisted_block(id)
    }

    fn get_block_index_for_any_block(
        &self,
        id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, ChainstateError> {
        self.deref().get_block_index_for_any_block(id)
    }

    fn get_gen_block_index_for_persisted_block(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, ChainstateError> {
        self.deref().get_gen_block_index_for_persisted_block(id)
    }

    fn get_gen_block_index_for_any_block(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, ChainstateError> {
        self.deref().get_gen_block_index_for_any_block(id)
    }

    fn get_best_block_index(&self) -> Result<GenBlockIndex, ChainstateError> {
        self.deref().get_best_block_index()
    }

    fn get_chain_config(&self) -> &Arc<ChainConfig> {
        self.deref().get_chain_config()
    }

    fn get_chainstate_config(&self) -> ChainstateConfig {
        self.deref().get_chainstate_config()
    }

    fn wait_for_all_events(&self) {
        self.deref().wait_for_all_events()
    }

    fn subscribers(&self) -> &[EventHandler<ChainstateEvent>] {
        self.deref().subscribers()
    }

    fn calculate_median_time_past(
        &self,
        starting_block: &Id<GenBlock>,
    ) -> Result<BlockTimestamp, ChainstateError> {
        self.deref().calculate_median_time_past(starting_block)
    }

    fn is_already_an_orphan(&self, block_id: &Id<Block>) -> bool {
        self.deref().is_already_an_orphan(block_id)
    }

    fn orphans_count(&self) -> usize {
        self.deref().orphans_count()
    }

    fn get_ancestor(
        &self,
        block_index: &GenBlockIndex,
        ancestor_height: BlockHeight,
    ) -> Result<GenBlockIndex, ChainstateError> {
        self.deref().get_ancestor(block_index, ancestor_height)
    }

    fn last_common_ancestor(
        &self,
        first_block_index: &GenBlockIndex,
        second_block_index: &GenBlockIndex,
    ) -> Result<GenBlockIndex, ChainstateError> {
        self.deref().last_common_ancestor(first_block_index, second_block_index)
    }

    fn last_common_ancestor_by_id(
        &self,
        first_block: &Id<GenBlock>,
        second_block: &Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, ChainstateError> {
        self.deref().last_common_ancestor_by_id(first_block, second_block)
    }

    fn get_block_reward(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<BlockReward>, ChainstateError> {
        self.deref().get_block_reward(block_index)
    }

    fn get_epoch_data(&self, epoch_index: u64) -> Result<Option<EpochData>, ChainstateError> {
        self.deref().get_epoch_data(epoch_index)
    }

    fn get_token_info_for_rpc(
        &self,
        token_id: TokenId,
    ) -> Result<Option<RPCTokenInfo>, ChainstateError> {
        self.deref().get_token_info_for_rpc(token_id)
    }

    fn get_token_aux_data(
        &self,
        token_id: TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, ChainstateError> {
        self.deref().get_token_aux_data(token_id)
    }

    fn get_token_id_from_issuance_tx(
        &self,
        tx_id: &Id<Transaction>,
    ) -> Result<Option<TokenId>, ChainstateError> {
        self.deref().get_token_id_from_issuance_tx(tx_id)
    }

    fn get_inputs_outpoints_coin_amount(
        &self,
        inputs: &[TxInput],
    ) -> Result<Vec<Option<Amount>>, ChainstateError> {
        self.deref().get_inputs_outpoints_coin_amount(inputs)
    }

    fn get_mainchain_blocks_list(&self) -> Result<Vec<Id<Block>>, ChainstateError> {
        self.deref().get_mainchain_blocks_list()
    }

    fn get_block_id_tree_as_list(&self) -> Result<Vec<Id<Block>>, ChainstateError> {
        self.deref().get_block_id_tree_as_list()
    }

    fn import_bootstrap_stream<'a>(
        &mut self,
        reader: std::io::BufReader<Box<dyn std::io::Read + Send + 'a>>,
    ) -> Result<(), ChainstateError> {
        self.deref_mut().import_bootstrap_stream(reader)
    }

    fn export_bootstrap_stream<'a>(
        &self,
        writer: std::io::BufWriter<Box<dyn std::io::Write + Send + 'a>>,
        include_stale_blocks: bool,
    ) -> Result<(), ChainstateError> {
        self.deref().export_bootstrap_stream(writer, include_stale_blocks)
    }

    fn utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, ChainstateError> {
        self.deref().utxo(outpoint)
    }

    fn is_initial_block_download(&self) -> bool {
        self.deref().is_initial_block_download()
    }

    fn stake_pool_exists(&self, pool_id: PoolId) -> Result<bool, ChainstateError> {
        self.deref().stake_pool_exists(pool_id)
    }

    fn get_stake_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, ChainstateError> {
        self.deref().get_stake_pool_balance(pool_id)
    }

    fn get_stake_pool_balances_at_heights(
        &self,
        pool_ids: &[PoolId],
        min_height: BlockHeight,
        max_height: BlockHeight,
    ) -> Result<BTreeMap<BlockHeight, BTreeMap<PoolId, NonZeroPoolBalances>>, ChainstateError> {
        self.deref()
            .get_stake_pool_balances_at_heights(pool_ids, min_height, max_height)
    }

    fn get_stake_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, ChainstateError> {
        self.deref().get_stake_pool_data(pool_id)
    }

    fn get_stake_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, ChainstateError> {
        self.deref().get_stake_pool_delegations_shares(pool_id)
    }

    fn get_stake_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, ChainstateError> {
        self.deref().get_stake_delegation_balance(delegation_id)
    }

    fn get_stake_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, ChainstateError> {
        self.deref().get_stake_delegation_data(delegation_id)
    }

    fn get_stake_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, ChainstateError> {
        self.deref().get_stake_pool_delegation_share(pool_id, delegation_id)
    }

    fn info(&self) -> Result<ChainInfo, ChainstateError> {
        self.deref().info()
    }

    fn get_block_header(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<SignedBlockHeader>, ChainstateError> {
        self.deref().get_block_header(block_id)
    }

    fn get_account_nonce_count(
        &self,
        account: AccountType,
    ) -> Result<Option<AccountNonce>, ChainstateError> {
        self.deref().get_account_nonce_count(account)
    }

    fn get_token_data(
        &self,
        id: &TokenId,
    ) -> Result<Option<tokens_accounting::TokenData>, ChainstateError> {
        self.deref().get_token_data(id)
    }

    fn get_token_circulating_supply(
        &self,
        id: &TokenId,
    ) -> Result<Option<Amount>, ChainstateError> {
        self.deref().get_token_circulating_supply(id)
    }

    fn get_order_data(&self, id: &OrderId) -> Result<Option<OrderData>, ChainstateError> {
        self.deref().get_order_data(id)
    }

    fn get_order_ask_balance(&self, id: &OrderId) -> Result<Option<Amount>, ChainstateError> {
        self.deref().get_order_ask_balance(id)
    }

    fn get_order_give_balance(&self, id: &OrderId) -> Result<Option<Amount>, ChainstateError> {
        self.deref().get_order_give_balance(id)
    }

    fn get_order_info_for_rpc(
        &self,
        order_id: OrderId,
    ) -> Result<Option<RpcOrderInfo>, ChainstateError> {
        self.deref().get_order_info_for_rpc(order_id)
    }
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use chainstate_storage::inmemory::Store;
    use common::{
        chain::{config::create_unit_test_config, ChainConfig},
        primitives::BlockHeight,
    };

    use crate::{
        chainstate_interface::ChainstateInterface, make_chainstate, ChainstateConfig,
        DefaultTransactionVerificationStrategy,
    };
    use common::time_getter::TimeGetter;

    fn test_interface_ref<C: ChainstateInterface>(chainstate: &C, chain_config: &ChainConfig) {
        assert_eq!(
            chainstate.get_best_block_id().unwrap(),
            chain_config.genesis_block_id()
        );
        assert_eq!(
            chainstate.get_best_block_height().unwrap(),
            BlockHeight::new(0)
        );
    }

    fn test_interface<C: ChainstateInterface>(chainstate: C, chain_config: &ChainConfig) {
        assert_eq!(
            chainstate.get_best_block_id().unwrap(),
            chain_config.genesis_block_id()
        );
        assert_eq!(
            chainstate.get_best_block_height().unwrap(),
            BlockHeight::new(0)
        );
    }

    #[test]
    fn boxed_interface_call() {
        utils::concurrency::model(|| {
            let chain_config = Arc::new(create_unit_test_config());
            let chainstate_config = ChainstateConfig {
                max_db_commit_attempts: 10.into(),
                max_orphan_blocks: 0.into(),
                min_max_bootstrap_import_buffer_sizes: Default::default(),
                max_tip_age: Default::default(),
                enable_heavy_checks: Some(true),
                allow_checkpoints_mismatch: Default::default(),
            };
            let chainstate_storage = Store::new_empty().unwrap();

            let boxed_chainstate: Box<dyn ChainstateInterface> = make_chainstate(
                chain_config.clone(),
                chainstate_config,
                chainstate_storage,
                DefaultTransactionVerificationStrategy::new(),
                None,
                TimeGetter::default(),
            )
            .unwrap();

            test_interface_ref(&boxed_chainstate, &chain_config);
            test_interface(boxed_chainstate, &chain_config);
        });
    }
}
