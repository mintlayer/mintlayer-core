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

use std::sync::Arc;

use crate::ChainstateConfig;
use chainstate_types::{BlockIndex, GenBlockIndex};
use common::chain::tokens::TokenAuxiliaryData;
use common::chain::Transaction;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, Block, BlockHeader, BlockReward, GenBlock},
        tokens::{RPCTokenInfo, TokenId},
        ChainConfig, OutPointSourceId, TxMainChainIndex,
    },
    primitives::{BlockHeight, Id},
};
use utils::eventhandler::EventHandler;

use crate::{detail::BlockSource, ChainstateError, ChainstateEvent, Locator};

pub trait ChainstateInterface: Send {
    fn subscribe_to_events(&mut self, handler: Arc<dyn Fn(ChainstateEvent) + Send + Sync>);
    fn process_block(
        &mut self,
        block: Block,
        source: BlockSource,
    ) -> Result<Option<BlockIndex>, ChainstateError>;
    fn preliminary_block_check(&self, block: Block) -> Result<Block, ChainstateError>;
    fn preliminary_header_check(&self, header: BlockHeader) -> Result<(), ChainstateError>;
    fn get_best_block_id(&self) -> Result<Id<GenBlock>, ChainstateError>;
    fn is_block_in_main_chain(&self, block_id: &Id<Block>) -> Result<bool, ChainstateError>;
    fn get_block_height_in_main_chain(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<BlockHeight>, ChainstateError>;
    fn get_best_block_height(&self) -> Result<BlockHeight, ChainstateError>;
    fn get_block_id_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, ChainstateError>;
    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ChainstateError>;

    /// Returns a list of block headers whose heights distances increase exponentially starting
    /// from the current tip.
    ///
    /// This returns a relatively short sequence even for a long chain. Such sequence can be used
    /// to quickly find a common ancestor between different chains.
    fn get_locator(&self) -> Result<Locator, ChainstateError>;

    /// Returns a list of block headers starting from the last locator's block that is in the main
    /// chain.
    ///
    /// The number of returned headers is limited by the `HEADER_LIMIT` constant. The genesis block
    /// header is returned in case there is no common ancestor with a better block height.
    fn get_headers(&self, locator: Locator) -> Result<Vec<BlockHeader>, ChainstateError>;

    /// Removes all headers that are already known to the chain from the given vector.
    fn filter_already_existing_blocks(
        &self,
        headers: Vec<BlockHeader>,
    ) -> Result<Vec<BlockHeader>, ChainstateError>;

    fn get_block_index(&self, id: &Id<Block>) -> Result<Option<BlockIndex>, ChainstateError>;
    fn get_gen_block_index(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, ChainstateError>;
    fn get_best_block_index(&self) -> Result<GenBlockIndex, ChainstateError>;

    fn get_chain_config(&self) -> Arc<ChainConfig>;
    fn get_chainstate_config(&self) -> ChainstateConfig;
    fn wait_for_all_events(&self);
    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<TxMainChainIndex>, ChainstateError>;
    fn subscribers(&self) -> &Vec<EventHandler<ChainstateEvent>>;
    fn calculate_median_time_past(&self, starting_block: &Id<GenBlock>) -> BlockTimestamp;
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
    fn get_block_reward(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<BlockReward>, ChainstateError>;
    /// Returns token info by token_id
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
}
