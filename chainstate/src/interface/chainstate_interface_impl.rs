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

use crate::detail::bootstrap::export_bootstrap_stream;
use crate::detail::bootstrap::import_bootstrap_stream;
use crate::detail::calculate_median_time_past;
use crate::detail::tx_verification_strategy::TransactionVerificationStrategy;
use chainstate_storage::BlockchainStorage;
use chainstate_types::{BlockIndex, GenBlockIndex};
use common::chain::block::BlockReward;
use common::chain::config::ChainConfig;
use common::chain::tokens::OutputValue;
use common::chain::tokens::TokenAuxiliaryData;
use common::chain::{OutPoint, TxInput};
use common::chain::{OutPointSourceId, Transaction, TxMainChainIndex};
use common::primitives::Amount;

use chainstate_types::PropertyQueryError;
use common::{
    chain::{
        block::{Block, BlockHeader, GenBlock},
        tokens::{RPCTokenInfo, TokenId},
    },
    primitives::{id::WithId, BlockHeight, Id},
};
use utils::eventhandler::EventHandler;
use utxo::{Utxo, UtxosView};

use crate::ChainstateConfig;
use crate::{
    detail::{self, BlockSource},
    ChainstateError, ChainstateEvent, ChainstateInterface, Locator,
};

pub struct ChainstateInterfaceImpl<S, V> {
    chainstate: detail::Chainstate<S, V>,
}

impl<S, V> ChainstateInterfaceImpl<S, V> {
    pub fn new(chainstate: detail::Chainstate<S, V>) -> Self {
        Self { chainstate }
    }
}

impl<S: BlockchainStorage, V: TransactionVerificationStrategy> ChainstateInterface
    for ChainstateInterfaceImpl<S, V>
{
    fn subscribe_to_events(&mut self, handler: EventHandler<ChainstateEvent>) {
        self.chainstate.subscribe_to_events(handler)
    }

    fn process_block(
        &mut self,
        block: Block,
        source: BlockSource,
    ) -> Result<Option<BlockIndex>, ChainstateError> {
        self.chainstate
            .process_block(block.into(), source)
            .map_err(ChainstateError::ProcessBlockError)
    }

    fn preliminary_header_check(&self, header: BlockHeader) -> Result<(), ChainstateError> {
        self.chainstate
            .preliminary_header_check(header)
            .map_err(ChainstateError::ProcessBlockError)
    }

    fn preliminary_block_check(&self, block: Block) -> Result<Block, ChainstateError> {
        let block = self
            .chainstate
            .preliminary_block_check(block.into())
            .map_err(ChainstateError::ProcessBlockError)?;
        Ok(WithId::take(block))
    }

    fn get_best_block_id(&self) -> Result<Id<GenBlock>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_best_block_id()
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn is_block_in_main_chain(&self, block_id: &Id<Block>) -> Result<bool, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_block_height_in_main_chain(&(*block_id).into())
            .map_err(ChainstateError::FailedToReadProperty)
            .map(|ht| ht.is_some())
    }

    fn get_block_height_in_main_chain(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<BlockHeight>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_block_height_in_main_chain(block_id)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn get_block_id_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_block_id_from_height(height)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_block(block_id)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn get_locator(&self) -> Result<Locator, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_locator()
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn get_headers(&self, locator: Locator) -> Result<Vec<BlockHeader>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_headers(locator)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn filter_already_existing_blocks(
        &self,
        headers: Vec<BlockHeader>,
    ) -> Result<Vec<BlockHeader>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .filter_already_existing_blocks(headers)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn get_best_block_height(&self) -> Result<BlockHeight, ChainstateError> {
        let best_block_index = self
            .chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_best_block_index()
            .map_err(ChainstateError::FailedToReadProperty)?
            .expect("Best block index could not be found");
        Ok(best_block_index.block_height())
    }

    fn get_best_block_header(&self) -> Result<BlockHeader, ChainstateError> {
        Ok(self
            .chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_best_block_header()
            .map_err(ChainstateError::FailedToReadProperty)?
            .expect("Best block header could not be found"))
    }

    fn get_best_block_index(&self) -> Result<GenBlockIndex, ChainstateError> {
        Ok(self
            .chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_best_block_index()
            .map_err(ChainstateError::FailedToReadProperty)?
            .expect("Best block index could not be found"))
    }

    fn get_block_index(&self, block_id: &Id<Block>) -> Result<Option<BlockIndex>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_block_index(block_id)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn get_gen_block_index(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_gen_block_index(id)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn get_chain_config(&self) -> Arc<ChainConfig> {
        Arc::clone(self.chainstate.chain_config())
    }

    fn get_chainstate_config(&self) -> ChainstateConfig {
        self.chainstate.chainstate_config().clone()
    }

    fn wait_for_all_events(&self) {
        self.chainstate.wait_for_all_events()
    }

    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<TxMainChainIndex>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_mainchain_tx_index(tx_id)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn subscribers(&self) -> &Vec<EventHandler<ChainstateEvent>> {
        self.chainstate.events_controller().subscribers()
    }

    fn calculate_median_time_past(
        &self,
        starting_block: &Id<GenBlock>,
    ) -> Result<common::chain::block::timestamp::BlockTimestamp, ChainstateError> {
        let err_f = |e| ChainstateError::FailedToReadProperty(PropertyQueryError::from(e));
        let dbtx = self.chainstate.make_db_tx_ro().map_err(err_f)?;
        Ok(calculate_median_time_past(&dbtx, starting_block))
    }

    fn is_already_an_orphan(&self, block_id: &Id<Block>) -> bool {
        self.chainstate.orphan_blocks_pool().is_already_an_orphan(block_id)
    }

    fn orphans_count(&self) -> usize {
        self.chainstate.orphan_blocks_pool().len()
    }

    fn get_ancestor(
        &self,
        block_index: &GenBlockIndex,
        ancestor_height: BlockHeight,
    ) -> Result<GenBlockIndex, ChainstateError> {
        self.chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))?
            .get_ancestor(block_index, ancestor_height)
            .map_err(|e| {
                ChainstateError::FailedToReadProperty(PropertyQueryError::GetAncestorError(e))
            })
    }

    fn last_common_ancestor(
        &self,
        first_block_index: &GenBlockIndex,
        second_block_index: &GenBlockIndex,
    ) -> Result<GenBlockIndex, ChainstateError> {
        self.chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))?
            .last_common_ancestor(first_block_index, second_block_index)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn get_block_reward(
        &self,
        block_index: &chainstate_types::BlockIndex,
    ) -> Result<Option<BlockReward>, ChainstateError> {
        self.chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))?
            .get_block_reward(block_index)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn get_token_info_for_rpc(
        &self,
        token_id: TokenId,
    ) -> Result<Option<RPCTokenInfo>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_token_info_for_rpc(token_id)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn get_token_aux_data(
        &self,
        token_id: TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_token_aux_data(&token_id)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn get_token_id_from_issuance_tx(
        &self,
        tx_id: &Id<Transaction>,
    ) -> Result<Option<TokenId>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_token_id_from_issuance_tx(tx_id)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn available_inputs(&self, tx: &Transaction) -> Result<Vec<Option<TxInput>>, ChainstateError> {
        let chainstate_ref = self
            .chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::from(PropertyQueryError::from(e)))?;
        let utxo_view = chainstate_ref.make_utxo_view();
        let available_inputs = tx
            .inputs()
            .iter()
            .map(|input| utxo_view.utxo(input.outpoint()).map(|_| input).cloned())
            .collect();
        Ok(available_inputs)
    }

    fn get_inputs_outpoints_values(
        &self,
        tx: &Transaction,
    ) -> Result<Vec<Option<Amount>>, ChainstateError> {
        let chainstate_ref = self
            .chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::from(PropertyQueryError::from(e)))?;
        let utxo_view = chainstate_ref.make_utxo_view();

        let outpoint_values = tx.inputs().iter().map(|input| input.outpoint()).try_fold(
            Vec::new(),
            |mut values, outpoint| {
                if let Some(utxo) = utxo_view.utxo(outpoint) {
                    match utxo.output().value() {
                        OutputValue::Coin(amount) => values.push(Some(*amount)),
                        _ => {
                            return Err(ChainstateError::FailedToReadProperty(
                                PropertyQueryError::ExpectedCoinOutpointAndFoundToken,
                            ))
                        }
                    }
                } else {
                    values.push(None)
                }
                Ok(values)
            },
        );

        outpoint_values
    }

    fn get_mainchain_blocks_list(&self) -> Result<Vec<Id<Block>>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_mainchain_blocks_list()
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn get_block_id_tree_as_list(&self) -> Result<Vec<Id<Block>>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_block_id_tree_as_list()
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn import_bootstrap_stream<'a>(
        &mut self,
        reader: std::io::BufReader<Box<dyn std::io::Read + Send + 'a>>,
    ) -> Result<(), ChainstateError> {
        let magic_bytes = self.chainstate.chain_config().magic_bytes().to_vec();

        let mut reader = reader;

        // We clone because borrowing with the closure below prevents immutable borrows,
        // and the cost of cloning is small compared to the bootstrapping
        let chainstate_config = self.chainstate.chainstate_config().clone();

        let mut block_processor = |block| self.chainstate.process_block(block, BlockSource::Local);

        import_bootstrap_stream(
            &magic_bytes,
            &mut reader,
            &mut block_processor,
            &chainstate_config,
        )?;

        Ok(())
    }

    fn export_bootstrap_stream<'a>(
        &self,
        writer: std::io::BufWriter<Box<dyn std::io::Write + Send + 'a>>,
        include_orphans: bool,
    ) -> Result<(), ChainstateError> {
        let magic_bytes = self.chainstate.chain_config().magic_bytes();
        let mut writer = writer;
        export_bootstrap_stream(
            magic_bytes,
            &mut writer,
            include_orphans,
            &self.chainstate.query().map_err(ChainstateError::from)?,
        )?;
        Ok(())
    }

    fn utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, ChainstateError> {
        let chainstate_ref = self
            .chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))?;
        let utxo_view = chainstate_ref.make_utxo_view();
        Ok(utxo_view.utxo(outpoint))
    }
}
