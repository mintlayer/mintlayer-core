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
    detail::{
        self,
        block_checking::BlockChecker,
        block_invalidation::BlockInvalidator,
        bootstrap::{export_bootstrap_stream, import_bootstrap_stream},
        calculate_median_time_past,
        tx_verification_strategy::TransactionVerificationStrategy,
        BlockSource, OrphanBlocksRef, CHAINSTATE_TRACING_TARGET_VERBOSE_BLOCK_IDS,
    },
    ChainInfo, ChainstateConfig, ChainstateError, ChainstateEvent, ChainstateInterface, Locator,
    NonZeroPoolBalances,
};
use chainstate_storage::BlockchainStorage;
use chainstate_types::{BlockIndex, EpochData, GenBlockIndex, PropertyQueryError};
use common::{
    chain::{
        block::{signed_block_header::SignedBlockHeader, Block, BlockReward, GenBlock},
        config::ChainConfig,
        tokens::{RPCTokenInfo, TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, DelegationId, OrderId, PoolId, RpcOrderInfo, Transaction,
        TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{id::WithId, Amount, BlockHeight, Id, Idable},
};
use orders_accounting::OrderData;
use pos_accounting::{DelegationData, PoSAccountingStorageRead, PoolData};
use utils::{displayable_option::DisplayableOption, eventhandler::EventHandler};
use utils_networking::broadcaster;
use utxo::{Utxo, UtxosView};

pub struct ChainstateInterfaceImpl<S, V> {
    chainstate: detail::Chainstate<S, V>,
}

impl<S, V> ChainstateInterfaceImpl<S, V> {
    pub fn new(chainstate: detail::Chainstate<S, V>) -> Self {
        Self { chainstate }
    }
}

impl<S, V> ChainstateInterface for ChainstateInterfaceImpl<S, V>
where
    S: BlockchainStorage + Sync,
    V: TransactionVerificationStrategy + Sync,
{
    #[tracing::instrument(skip_all)]
    fn subscribe_to_subsystem_events(&mut self, handler: EventHandler<ChainstateEvent>) {
        self.chainstate.subscribe_to_events(handler)
    }

    #[tracing::instrument(skip_all)]
    fn subscribe_to_rpc_events(&mut self) -> broadcaster::Receiver<ChainstateEvent> {
        self.chainstate.subscribe_to_event_broadcast()
    }

    // Note: in this and some other functions below (in particular, in those that are called from
    // p2p when processing blocks coming from peers) we add an additional DEBUG span that prints
    // the block via `format!("{:x}")`. This is because the other span prints the id via Display
    // (due to the '%' sigil), in which case it is shortened, e.g. "778b…b100".
    // Always printing the full id would clutter the log, so we don't want to do that.
    // So we add an additional span for the cases when the full id is needed.
    // Also note that we add the extra span first, but in the output it will be printed after
    // the normal one.
    #[tracing::instrument(
        skip_all, level = tracing::Level::DEBUG, name = "",
        fields(id = format!("{:x}", block.get_id())),
        target = CHAINSTATE_TRACING_TARGET_VERBOSE_BLOCK_IDS
    )]
    #[tracing::instrument(skip_all, fields(id = %block.get_id()))]
    fn process_block(
        &mut self,
        block: Block,
        source: BlockSource,
    ) -> Result<Option<BlockIndex>, ChainstateError> {
        self.chainstate
            .process_block(block.into(), source)
            .map_err(ChainstateError::ProcessBlockError)
    }

    #[tracing::instrument(skip_all, fields(id = %block_id))]
    fn invalidate_block(&mut self, block_id: &Id<Block>) -> Result<(), ChainstateError> {
        self.chainstate
            .invalidate_block(block_id)
            .map_err(ChainstateError::BlockInvalidatorError)
    }

    #[tracing::instrument(skip_all, fields(id = %block_id))]
    fn reset_block_failure_flags(&mut self, block_id: &Id<Block>) -> Result<(), ChainstateError> {
        BlockInvalidator::new(&mut self.chainstate)
            .reset_block_failure_flags(block_id)
            .map_err(ChainstateError::BlockInvalidatorError)
    }

    #[tracing::instrument(
        skip_all, level = tracing::Level::DEBUG, name = "",
        fields(first_id =
            if let Some(first_header) = headers.first() {
                format!("{:x}", first_header.get_id())
            } else {
                "None".to_owned()
            }
        ),
        target = CHAINSTATE_TRACING_TARGET_VERBOSE_BLOCK_IDS
    )]
    #[tracing::instrument(
        skip_all,
        fields(first_id = %headers.first().map(|header| header.get_id()).as_displayable())
    )]
    fn preliminary_headers_check(
        &self,
        headers: &[SignedBlockHeader],
    ) -> Result<(), ChainstateError> {
        BlockChecker::new(&self.chainstate)
            .preliminary_headers_check(headers)
            .map_err(ChainstateError::ProcessBlockError)
    }

    #[tracing::instrument(
        skip_all, level = tracing::Level::DEBUG, name = "",
        fields(id = format!("{:x}", block.get_id())),
        target = CHAINSTATE_TRACING_TARGET_VERBOSE_BLOCK_IDS
    )]
    #[tracing::instrument(skip_all, fields(id = %block.get_id()))]
    fn preliminary_block_check(&self, block: Block) -> Result<Block, ChainstateError> {
        let block = BlockChecker::new(&self.chainstate)
            .preliminary_block_check(block.into())
            .map_err(ChainstateError::ProcessBlockError)?;
        Ok(WithId::take(block))
    }

    #[tracing::instrument(skip_all)]
    fn get_best_block_id(&self) -> Result<Id<GenBlock>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_best_block_id()
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all, fields(id = %block_id))]
    fn is_block_in_main_chain(&self, block_id: &Id<GenBlock>) -> Result<bool, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .is_block_in_main_chain(block_id)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all)]
    fn get_min_height_with_allowed_reorg(&self) -> Result<BlockHeight, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_min_height_with_allowed_reorg()
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all, fields(id = %block_id))]
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

    #[tracing::instrument(skip_all, fields(height = %height))]
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

    #[tracing::instrument(skip_all, fields(id = %block_id))]
    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_block(block_id)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all, fields(from = %from, max_count = max_count))]
    fn get_mainchain_blocks(
        &self,
        from: BlockHeight,
        max_count: usize,
    ) -> Result<Vec<Block>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_mainchain_blocks(from, max_count)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all, fields(id = %block_id))]
    fn get_block_header(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<SignedBlockHeader>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_block_header(block_id)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all)]
    fn get_locator(&self) -> Result<Locator, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_locator()
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all, fields(height = %height))]
    fn get_locator_from_height(&self, height: BlockHeight) -> Result<Locator, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_locator_from_height(height)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip(self))]
    fn get_block_ids_as_checkpoints(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
        step: NonZeroUsize,
    ) -> Result<Vec<(BlockHeight, Id<GenBlock>)>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_block_ids_as_checkpoints(start_height, end_height, step)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all)]
    fn get_mainchain_headers_by_locator(
        &self,
        locator: &Locator,
        header_count_limit: usize,
    ) -> Result<Vec<SignedBlockHeader>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_mainchain_headers_by_locator(locator, header_count_limit)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all)]
    fn get_mainchain_headers_since_latest_fork_point(
        &self,
        block_ids: &[Id<GenBlock>],
        header_count_limit: usize,
    ) -> Result<Vec<SignedBlockHeader>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_mainchain_headers_since_latest_fork_point(block_ids, header_count_limit)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all)]
    fn split_off_leading_known_headers(
        &self,
        headers: Vec<SignedBlockHeader>,
    ) -> Result<(Vec<SignedBlockHeader>, Vec<SignedBlockHeader>), ChainstateError> {
        let first_non_existing_block_idx = {
            let mut idx = 0;
            for header in headers.iter() {
                if self.get_block_index_for_persisted_block(&header.get_id())?.is_none() {
                    break;
                }
                idx += 1;
            }
            idx
        };

        assert!(first_non_existing_block_idx <= headers.len());
        let mut headers = headers;
        let non_existing_block_headers = headers.split_off(first_non_existing_block_idx);
        Ok((headers, non_existing_block_headers))
    }

    #[tracing::instrument(skip_all)]
    fn get_best_block_height(&self) -> Result<BlockHeight, ChainstateError> {
        let best_block_index = self
            .chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_best_block_index()
            .map_err(ChainstateError::FailedToReadProperty)?;
        Ok(best_block_index.block_height())
    }

    #[tracing::instrument(skip_all)]
    fn get_best_block_header(&self) -> Result<SignedBlockHeader, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_best_block_header()
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all)]
    fn get_best_block_index(&self) -> Result<GenBlockIndex, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_best_block_index()
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all, fields(id = %block_id))]
    fn get_block_index_for_persisted_block(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_block_index_for_persisted_block(block_id)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all, fields(id = %block_id))]
    fn get_block_index_for_any_block(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_block_index_for_any_block(block_id)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all, fields(id = %id))]
    fn get_gen_block_index_for_persisted_block(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_gen_block_index_for_persisted_block(id)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all, fields(id = %id))]
    fn get_gen_block_index_for_any_block(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_gen_block_index_for_any_block(id)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all)]
    fn get_chain_config(&self) -> &Arc<ChainConfig> {
        self.chainstate.chain_config()
    }

    #[tracing::instrument(skip_all)]
    fn get_chainstate_config(&self) -> ChainstateConfig {
        self.chainstate.chainstate_config().clone()
    }

    #[tracing::instrument(skip_all)]
    fn wait_for_all_events(&self) {
        self.chainstate.wait_for_all_events()
    }

    #[tracing::instrument(skip_all)]
    fn subscribers(&self) -> &[EventHandler<ChainstateEvent>] {
        self.chainstate.subscribers()
    }

    #[tracing::instrument(skip_all, fields(starting_block = %starting_block))]
    fn calculate_median_time_past(
        &self,
        starting_block: &Id<GenBlock>,
    ) -> Result<common::chain::block::timestamp::BlockTimestamp, ChainstateError> {
        let err_f = |e| ChainstateError::FailedToReadProperty(PropertyQueryError::from(e));
        let dbtx = self.chainstate.make_db_tx_ro().map_err(err_f)?;
        Ok(calculate_median_time_past(&dbtx, starting_block))
    }

    #[tracing::instrument(skip_all, fields(id = %block_id))]
    fn is_already_an_orphan(&self, block_id: &Id<Block>) -> bool {
        self.chainstate.orphan_blocks_pool().is_already_an_orphan(block_id)
    }

    #[tracing::instrument(skip_all)]
    fn orphans_count(&self) -> usize {
        self.chainstate.orphan_blocks_pool().len()
    }

    #[tracing::instrument(
        skip_all,
        fields(id = %block_index.block_id(), ancestor_height = %ancestor_height)
    )]
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

    #[tracing::instrument(
        skip_all,
        fields(
            first_id = %first_block_index.block_id(),
            second_id = %second_block_index.block_id()
        )
    )]
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

    #[tracing::instrument(
        skip_all, fields(first_block = %first_block, second_block = %second_block)
    )]
    fn last_common_ancestor_by_id(
        &self,
        first_block: &Id<GenBlock>,
        second_block: &Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, ChainstateError> {
        let tx = self
            .chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))?;
        let first_block = tx.get_gen_block_index(first_block)?;
        let second_block = tx.get_gen_block_index(second_block)?;
        if let (Some(first_block), Some(second_block)) = (first_block, second_block) {
            let common_ancestor = tx.last_common_ancestor(&first_block, &second_block)?;
            Ok(Some((
                common_ancestor.block_id(),
                common_ancestor.block_height(),
            )))
        } else {
            Ok(None)
        }
    }

    #[tracing::instrument(skip_all, fields(id = %block_index.block_id()))]
    fn get_block_reward(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<BlockReward>, ChainstateError> {
        self.chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))?
            .get_block_reward(block_index)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip(self))]
    fn get_epoch_data(&self, epoch_index: u64) -> Result<Option<EpochData>, ChainstateError> {
        self.chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))?
            .get_epoch_data(epoch_index)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all, fields(token_id = %token_id))]
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

    #[tracing::instrument(skip_all, fields(token_id = %token_id))]
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

    #[tracing::instrument(skip_all, fields(tx_id = %tx_id))]
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

    #[tracing::instrument(skip_all)]
    fn get_inputs_outpoints_coin_amount(
        &self,
        inputs: &[TxInput],
    ) -> Result<Vec<Option<Amount>>, ChainstateError> {
        let chainstate_ref = self
            .chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::from(PropertyQueryError::from(e)))?;
        let utxo_view = chainstate_ref.make_utxo_view();
        let pos_accounting_view = chainstate_ref.make_pos_accounting_view();

        inputs
            .iter()
            .map(|input| match input {
                TxInput::Utxo(outpoint) => {
                    let utxo = utxo_view
                        .utxo(outpoint)
                        .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))?;
                    match utxo {
                        Some(utxo) => get_output_coin_amount(&pos_accounting_view, utxo.output()),
                        None => Ok(None),
                    }
                }
                TxInput::Account(..)
                | TxInput::AccountCommand(..)
                | TxInput::OrderAccountCommand(..) => Ok(None),
            })
            .collect::<Result<Vec<_>, _>>()
    }

    #[tracing::instrument(skip_all)]
    fn get_mainchain_blocks_list(&self) -> Result<Vec<Id<Block>>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_mainchain_blocks_list()
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all)]
    fn get_block_id_tree_as_list(&self) -> Result<Vec<Id<Block>>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_block_id_tree_as_list()
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all)]
    fn import_bootstrap_stream<'a>(
        &mut self,
        reader: std::io::BufReader<Box<dyn std::io::Read + Send + 'a>>,
    ) -> Result<(), ChainstateError> {
        let magic_bytes = *self.chainstate.chain_config().magic_bytes();

        let mut reader = reader;

        // We clone because borrowing with the closure below prevents immutable borrows,
        // and the cost of cloning is small compared to the bootstrapping
        let chainstate_config = self.chainstate.chainstate_config().clone();

        let mut block_processor = |block| self.chainstate.process_block(block, BlockSource::Local);

        import_bootstrap_stream(
            &magic_bytes.bytes(),
            &mut reader,
            &mut block_processor,
            &chainstate_config,
        )?;

        Ok(())
    }

    #[tracing::instrument(skip_all)]
    fn export_bootstrap_stream<'a>(
        &self,
        writer: std::io::BufWriter<Box<dyn std::io::Write + Send + 'a>>,
        include_orphans: bool,
    ) -> Result<(), ChainstateError> {
        let magic_bytes = self.chainstate.chain_config().magic_bytes();
        let mut writer = writer;
        export_bootstrap_stream(
            &magic_bytes.bytes(),
            &mut writer,
            include_orphans,
            &self.chainstate.query().map_err(ChainstateError::from)?,
        )?;
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    fn utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, ChainstateError> {
        let chainstate_ref = self
            .chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))?;
        let utxo_view = chainstate_ref.make_utxo_view();
        utxo_view
            .utxo(outpoint)
            .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))
    }

    fn is_initial_block_download(&self) -> bool {
        self.chainstate.is_initial_block_download()
    }

    #[tracing::instrument(skip_all, fields(pool_id = %pool_id))]
    fn stake_pool_exists(&self, pool_id: PoolId) -> Result<bool, ChainstateError> {
        self.get_stake_pool_data(pool_id).map(|v| v.is_some())
    }

    #[tracing::instrument(skip_all, fields(pool_id = %pool_id))]
    fn get_stake_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, ChainstateError> {
        self.chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))?
            .get_pool_balance(pool_id)
            .map_err(|e| ChainstateError::ProcessBlockError(e.into()))
    }

    #[tracing::instrument(skip_all)]
    fn get_stake_pool_balances_at_heights(
        &self,
        pool_ids: &[PoolId],
        min_height: BlockHeight,
        max_height: BlockHeight,
    ) -> Result<BTreeMap<BlockHeight, BTreeMap<PoolId, NonZeroPoolBalances>>, ChainstateError> {
        self.chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))?
            .get_stake_pool_balances_at_heights(pool_ids, min_height, max_height)
            .map_err(ChainstateError::ProcessBlockError)
    }

    #[tracing::instrument(skip_all, fields(pool_id = %pool_id))]
    fn get_stake_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, ChainstateError> {
        self.chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))?
            .get_pool_data(pool_id)
            .map_err(|e| ChainstateError::ProcessBlockError(e.into()))
    }

    #[tracing::instrument(skip_all, fields(pool_id = %pool_id))]
    fn get_stake_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, ChainstateError> {
        self.chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))?
            .get_pool_delegations_shares(pool_id)
            .map_err(|e| ChainstateError::ProcessBlockError(e.into()))
    }

    #[tracing::instrument(skip_all, fields(delegation_id = %delegation_id))]
    fn get_stake_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, ChainstateError> {
        self.chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))?
            .get_delegation_balance(delegation_id)
            .map_err(|e| ChainstateError::ProcessBlockError(e.into()))
    }

    #[tracing::instrument(skip_all, fields(delegation_id = %delegation_id))]
    fn get_stake_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, ChainstateError> {
        self.chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))?
            .get_delegation_data(delegation_id)
            .map_err(|e| ChainstateError::ProcessBlockError(e.into()))
    }

    #[tracing::instrument(skip_all, fields(pool_id = %pool_id, delegation_id = %delegation_id))]
    fn get_stake_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, ChainstateError> {
        self.chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))?
            .get_pool_delegation_share(pool_id, delegation_id)
            .map_err(|e| ChainstateError::ProcessBlockError(e.into()))
    }

    #[tracing::instrument(skip_all)]
    fn info(&self) -> Result<ChainInfo, ChainstateError> {
        let best_block_index = self.get_best_block_index()?;
        let best_block_height = best_block_index.block_height();
        let best_block_id = best_block_index.block_id();
        let best_block_timestamp = best_block_index.block_timestamp();

        let median_time = self.calculate_median_time_past(&best_block_id)?;

        let is_initial_block_download = self.is_initial_block_download();

        Ok(ChainInfo {
            best_block_height,
            best_block_id,
            best_block_timestamp,
            median_time,
            is_initial_block_download,
        })
    }

    #[tracing::instrument(skip_all)]
    fn get_account_nonce_count(
        &self,
        account: AccountType,
    ) -> Result<Option<AccountNonce>, ChainstateError> {
        self.chainstate
            .make_db_tx_ro()
            .map_err(|e| ChainstateError::FailedToReadProperty(e.into()))?
            .get_account_nonce_count(account)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    #[tracing::instrument(skip_all, fields(id = %id))]
    fn get_token_data(
        &self,
        id: &TokenId,
    ) -> Result<Option<tokens_accounting::TokenData>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_token_data(id)
            .map_err(ChainstateError::from)
    }

    #[tracing::instrument(skip_all, fields(id = %id))]
    fn get_token_circulating_supply(
        &self,
        id: &TokenId,
    ) -> Result<Option<Amount>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_token_circulating_supply(id)
            .map_err(ChainstateError::from)
    }

    #[tracing::instrument(skip_all, fields(id = %id))]
    fn get_order_data(&self, id: &OrderId) -> Result<Option<OrderData>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_order_data(id)
            .map_err(ChainstateError::from)
    }

    #[tracing::instrument(skip_all, fields(id = %id))]
    fn get_order_ask_balance(&self, id: &OrderId) -> Result<Option<Amount>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_order_ask_balance(id)
            .map_err(ChainstateError::from)
    }

    #[tracing::instrument(skip_all, fields(id = %id))]
    fn get_order_give_balance(&self, id: &OrderId) -> Result<Option<Amount>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_order_give_balance(id)
            .map_err(ChainstateError::from)
    }

    #[tracing::instrument(skip_all, fields(id = %id))]
    fn get_order_info_for_rpc(&self, id: OrderId) -> Result<Option<RpcOrderInfo>, ChainstateError> {
        self.chainstate
            .query()
            .map_err(ChainstateError::from)?
            .get_order_info_for_rpc(id)
            .map_err(ChainstateError::from)
    }
}

// TODO: remove this function. The value of an output cannot be generalized and exposed from ChainstateInterface in such way
// because it can be invalid for certain contexts.
// Note: this is used (indirectly) by mempool tests only. Move it to mempool tests (note that PoSAccountingView
// is also implemented for ChainstateHandle).
fn get_output_coin_amount(
    pos_accounting_view: &impl pos_accounting::PoSAccountingView,
    output: &TxOutput,
) -> Result<Option<Amount>, ChainstateError> {
    let amount = match output {
        TxOutput::Transfer(v, _)
        | TxOutput::LockThenTransfer(v, _, _)
        | TxOutput::Burn(v)
        | TxOutput::Htlc(v, _) => v.coin_amount(),
        TxOutput::CreateStakePool(_, data) => Some(data.pledge()),
        TxOutput::ProduceBlockFromStake(_, pool_id) => {
            let pledge_amount = pos_accounting_view
                .get_pool_data(*pool_id)
                .map_err(|_| {
                    ChainstateError::FailedToReadProperty(
                        PropertyQueryError::StakePoolDataNotFound(*pool_id),
                    )
                })?
                .ok_or(ChainstateError::FailedToReadProperty(
                    PropertyQueryError::StakePoolDataNotFound(*pool_id),
                ))?
                .staker_balance()
                .map_err(|_| {
                    ChainstateError::FailedToReadProperty(
                        PropertyQueryError::StakerBalanceOverflow(*pool_id),
                    )
                })?;
            Some(pledge_amount)
        }
        TxOutput::DelegateStaking(v, _) => Some(*v),
        TxOutput::CreateDelegationId(_, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::IssueNft(_, _, _)
        | TxOutput::DataDeposit(_)
        | TxOutput::CreateOrder(_) => None,
    };

    Ok(amount)
}

impl subsystem::Subsystem for Box<dyn ChainstateInterface> {
    type Interface = dyn ChainstateInterface;

    fn interface_ref(&self) -> &Self::Interface {
        self.as_ref()
    }

    fn interface_mut(&mut self) -> &mut Self::Interface {
        self.as_mut()
    }
}
