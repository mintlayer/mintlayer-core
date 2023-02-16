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
    ops::{Deref, DerefMut},
    sync::Arc,
};

use chainstate_types::Locator;
use chainstate_types::{BlockIndex, GenBlockIndex};
use common::chain::TxInput;
use common::chain::{
    block::{timestamp::BlockTimestamp, BlockReward},
    config::ChainConfig,
    tokens::TokenAuxiliaryData,
    OutPointSourceId, TxMainChainIndex,
};
use common::chain::{OutPoint, Transaction};
use common::{
    chain::{
        block::BlockHeader,
        tokens::{RPCTokenInfo, TokenId},
        Block, GenBlock,
    },
    primitives::{BlockHeight, Id},
};
use utils::eventhandler::EventHandler;
use utxo::Utxo;

use crate::ChainstateConfig;
use crate::{
    chainstate_interface::ChainstateInterface, BlockSource, ChainstateError, ChainstateEvent,
};

impl<
        T: Deref<Target = dyn ChainstateInterface> + DerefMut<Target = dyn ChainstateInterface> + Send,
    > ChainstateInterface for T
{
    fn subscribe_to_events(&mut self, handler: Arc<dyn Fn(ChainstateEvent) + Send + Sync>) {
        self.deref_mut().subscribe_to_events(handler)
    }

    fn process_block(
        &mut self,
        block: Block,
        source: BlockSource,
    ) -> Result<Option<BlockIndex>, ChainstateError> {
        self.deref_mut().process_block(block, source)
    }

    fn preliminary_block_check(&self, block: Block) -> Result<Block, ChainstateError> {
        self.deref().preliminary_block_check(block)
    }

    fn preliminary_header_check(&self, header: BlockHeader) -> Result<(), ChainstateError> {
        self.deref().preliminary_header_check(header)
    }

    fn get_best_block_id(&self) -> Result<Id<GenBlock>, ChainstateError> {
        self.deref().get_best_block_id()
    }

    fn is_block_in_main_chain(&self, block_id: &Id<Block>) -> Result<bool, ChainstateError> {
        self.deref().is_block_in_main_chain(block_id)
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

    fn get_best_block_header(&self) -> Result<BlockHeader, ChainstateError> {
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

    fn get_locator(&self) -> Result<Locator, ChainstateError> {
        self.deref().get_locator()
    }

    fn get_headers(
        &self,
        locator: Locator,
        header_count_limit: usize,
    ) -> Result<Vec<BlockHeader>, ChainstateError> {
        self.deref().get_headers(locator, header_count_limit)
    }

    fn filter_already_existing_blocks(
        &self,
        headers: Vec<BlockHeader>,
    ) -> Result<Vec<BlockHeader>, ChainstateError> {
        self.deref().filter_already_existing_blocks(headers)
    }

    fn get_block_index(&self, id: &Id<Block>) -> Result<Option<BlockIndex>, ChainstateError> {
        self.deref().get_block_index(id)
    }

    fn get_gen_block_index(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, ChainstateError> {
        self.deref().get_gen_block_index(id)
    }

    fn get_best_block_index(&self) -> Result<GenBlockIndex, ChainstateError> {
        self.deref().get_best_block_index()
    }

    fn get_chain_config(&self) -> Arc<ChainConfig> {
        self.deref().get_chain_config()
    }

    fn get_chainstate_config(&self) -> ChainstateConfig {
        self.deref().get_chainstate_config()
    }

    fn wait_for_all_events(&self) {
        self.deref().wait_for_all_events()
    }

    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<TxMainChainIndex>, ChainstateError> {
        self.deref().get_mainchain_tx_index(tx_id)
    }

    fn subscribers(&self) -> &Vec<EventHandler<ChainstateEvent>> {
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

    fn get_block_reward(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<BlockReward>, ChainstateError> {
        self.deref().get_block_reward(block_index)
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
        tx_id: &Id<common::chain::Transaction>,
    ) -> Result<Option<TokenId>, ChainstateError> {
        self.deref().get_token_id_from_issuance_tx(tx_id)
    }

    fn available_inputs(&self, tx: &Transaction) -> Result<Vec<Option<TxInput>>, ChainstateError> {
        self.deref().available_inputs(tx)
    }
    fn get_inputs_outpoints_values(
        &self,
        tx: &Transaction,
    ) -> Result<Vec<Option<common::primitives::Amount>>, ChainstateError> {
        self.deref().get_inputs_outpoints_values(tx)
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
        include_orphans: bool,
    ) -> Result<(), ChainstateError> {
        self.deref().export_bootstrap_stream(writer, include_orphans)
    }

    fn utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, ChainstateError> {
        self.deref().utxo(outpoint)
    }

    fn is_initial_block_download(&self) -> Result<bool, ChainstateError> {
        self.deref().is_initial_block_download()
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
                tx_index_enabled: Default::default(),
                max_tip_age: Default::default(),
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
