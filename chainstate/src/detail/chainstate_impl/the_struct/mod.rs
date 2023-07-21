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

use std::sync::Arc;

use super::{ChainstateEventHandler, OrphanErrorHandler, TxRo, TxRw};
use crate::{
    detail::{chainstateref::ChainstateRef, orphan_blocks::OrphansProxy, query::ChainstateQuery},
    ChainstateConfig, ChainstateEvent, TransactionVerificationStrategy,
};
use chainstate_storage::BlockchainStorage;
use chainstate_types::PropertyQueryError;
use common::{
    chain::{block::timestamp::BlockTimestamp, ChainConfig},
    time_getter::TimeGetter,
};
use utils::eventhandler::EventsController;

mod initialization;

#[must_use]
pub struct Chainstate<S, V> {
    chain_config: Arc<ChainConfig>,
    chainstate_config: ChainstateConfig,
    chainstate_storage: S,
    tx_verification_strategy: V,
    orphan_blocks: OrphansProxy,
    custom_orphan_error_hook: Option<Arc<OrphanErrorHandler>>,
    events_controller: EventsController<ChainstateEvent>,
    time_getter: TimeGetter,
    is_initial_block_download_finished: bool,
}

impl<S: BlockchainStorage, V: TransactionVerificationStrategy> Chainstate<S, V> {
    pub fn chain_config(&self) -> &Arc<ChainConfig> {
        &self.chain_config
    }

    pub fn chainstate_config(&self) -> &ChainstateConfig {
        &self.chainstate_config
    }

    pub fn orphan_blocks_pool(&self) -> &OrphansProxy {
        &self.orphan_blocks
    }

    pub(super) fn orphan_blocks_pool_mut(&mut self) -> &mut OrphansProxy {
        &mut self.orphan_blocks
    }

    pub(super) fn custom_orphan_error_hook(&self) -> &Option<Arc<OrphanErrorHandler>> {
        &self.custom_orphan_error_hook
    }

    pub fn events_controller(&self) -> &EventsController<ChainstateEvent> {
        &self.events_controller
    }

    pub(super) fn set_is_initial_block_download_finished(&mut self, val: bool) {
        self.is_initial_block_download_finished = val;
    }

    pub(super) fn make_db_tx(
        &mut self,
    ) -> chainstate_storage::Result<ChainstateRef<TxRw<'_, S>, V>> {
        let db_tx = self.chainstate_storage.transaction_rw(None)?;
        Ok(ChainstateRef::new_rw(
            &self.chain_config,
            &self.chainstate_config,
            &self.tx_verification_strategy,
            db_tx,
            &self.time_getter,
        ))
    }

    pub(crate) fn make_db_tx_ro(
        &self,
    ) -> chainstate_storage::Result<ChainstateRef<TxRo<'_, S>, V>> {
        let db_tx = self.chainstate_storage.transaction_ro()?;
        Ok(ChainstateRef::new_ro(
            &self.chain_config,
            &self.chainstate_config,
            &self.tx_verification_strategy,
            db_tx,
            &self.time_getter,
        ))
    }

    #[allow(dead_code)]
    pub fn wait_for_all_events(&self) {
        self.events_controller.wait_for_all_events();
    }

    pub fn subscribe_to_events(&mut self, handler: ChainstateEventHandler) {
        self.events_controller.subscribe_to_events(handler);
    }

    pub fn query(&self) -> Result<ChainstateQuery<TxRo<'_, S>, V>, PropertyQueryError> {
        self.make_db_tx_ro().map(ChainstateQuery::new).map_err(PropertyQueryError::from)
    }

    pub fn is_initial_block_download(&self) -> Result<bool, PropertyQueryError> {
        if self.is_initial_block_download_finished {
            return Ok(false);
        }

        // TODO: Add a check for importing and reindex.

        // TODO: Add a check for the chain trust.

        let tip_timestamp = match self.query()?.get_best_block_header() {
            Ok(h) => Ok(h.timestamp()),
            // There is only the genesis block, so the initial block download isn't finished yet.
            Err(PropertyQueryError::GenesisHeaderRequested) => return Ok(true),
            Err(e) => Err(e),
        }?;
        Ok(!self.is_fresh_block(&tip_timestamp))
    }

    /// Returns true if the given block timestamp is newer than `ChainstateConfig::max_tip_age`.
    pub(super) fn is_fresh_block(&self, time: &BlockTimestamp) -> bool {
        let now = self.time_getter.get_time();
        time.as_duration_since_epoch() + self.chainstate_config.max_tip_age.clone().into() > now
    }
}
