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

//! Support for updating the mempool upon a reorg

use std::collections::BTreeSet;

use chainstate::chainstate_interface::ChainstateInterface;
use common::{
    chain::{Block, GenBlock},
    primitives::{time::Time, Id, Idable},
};
use logging::log;
use utils::ensure;
use utxo::UtxosStorageRead;

use super::{MemoryUsageEstimator, TxAdditionOutcome, TxEntry, TxPool};
use crate::error::ReorgError;

/// Collect blocks between the given two points
fn collect_blocks<C: ChainstateInterface + ?Sized>(
    chainstate: &C,
    mut curr_id: Id<GenBlock>,
    stop_id: Id<GenBlock>,
) -> Result<Vec<Block>, ReorgError> {
    let chain_config = chainstate.get_chain_config();
    let mut result = Vec::new();
    while curr_id != stop_id {
        let curr_block_id = curr_id
            .classify(chain_config)
            .chain_block_id()
            .expect("Reached genesis before the stopping block");
        let block = chainstate
            .get_block(curr_block_id)?
            .ok_or(ReorgError::BlockNotFound(curr_block_id))?;
        curr_id = block.prev_block_id();
        result.push(block);
    }
    Ok(result)
}

/// Blocks affected by a reorg
struct ReorgData {
    // List of connected / disconnected blocks, both in reverse chronological order
    disconnected: Vec<Block>,
    connected: Vec<Block>,
}

impl ReorgData {
    /// Extract blocks that have been disconnected and connected from the chainstate.
    fn from_chainstate<C: ChainstateInterface + ?Sized>(
        chainstate: &C,
        old_tip_id: Id<GenBlock>,
        new_tip_id: Id<GenBlock>,
    ) -> Result<Self, ReorgError> {
        let common_id = {
            let old_index = chainstate
                .get_gen_block_index_for_persisted_block(&old_tip_id)?
                .ok_or(ReorgError::OldTipIndex)?;
            let new_index = chainstate
                .get_gen_block_index_for_persisted_block(&new_tip_id)?
                .ok_or(ReorgError::NewTipIndex)?;
            let common_index = chainstate.last_common_ancestor(&old_index, &new_index)?;
            common_index.block_id()
        };

        Ok(Self {
            disconnected: collect_blocks(chainstate, old_tip_id, common_id)?,
            connected: collect_blocks(chainstate, new_tip_id, common_id)?,
        })
    }

    /// Get transactions that have been disconnected and not reconnected
    fn into_disconnected_transactions(self, now: Time) -> impl Iterator<Item = TxEntry> {
        let connected_txs: BTreeSet<_> = self
            .connected
            .into_iter()
            .flat_map(|block| {
                block.into_transactions().into_iter().map(|tx| tx.transaction().get_id())
            })
            .collect();

        // The blocks are returned in the order of them being disconnected which is the
        // opposite of what we want for connecting, so we need to reverse the iterator here.
        self.disconnected
            .into_iter()
            .rev()
            .flat_map(|block| block.into_transactions())
            .filter_map(move |tx| {
                let origin = crate::tx_origin::LocalTxOrigin::PastBlock.into();
                let options = crate::tx_options::TxOptions::default_for(origin);
                let tx = TxEntry::new(tx, now, origin, options);
                ensure!(!connected_txs.contains(tx.tx_id()));
                Some(tx)
            })
    }
}

fn fetch_disconnected_txs<M>(
    tx_pool: &TxPool<M>,
    new_tip: Id<Block>,
) -> Result<impl Iterator<Item = TxEntry>, ReorgError> {
    let old_tip = tx_pool
        .tx_verifier
        .get_best_block_for_utxos()
        .map_err(|_| ReorgError::BestBlockForUtxos)?;

    log::debug!("Fetching disconnected txs, old_tip = {old_tip:?}");

    let now = tx_pool.clock.get_time();

    tx_pool
        .blocking_chainstate_handle()
        .call(move |c| ReorgData::from_chainstate(c, old_tip, new_tip.into()))?
        .map(|data| data.into_disconnected_transactions(now))
}

pub fn handle_new_tip<M: MemoryUsageEstimator>(
    tx_pool: &mut TxPool<M>,
    new_tip: Id<Block>,
    finalizer: impl FnMut(TxAdditionOutcome, &TxPool<M>),
) -> Result<(), ReorgError> {
    tx_pool.rolling_fee_rate.get_mut().set_block_since_last_rolling_fee_bump(true);

    let (is_ibd, actual_tip) = tx_pool.blocking_chainstate_handle().call(|cs| {
        let is_ibd = cs.is_initial_block_download();
        let actual_tip = cs.get_best_block_id()?;
        Ok::<_, chainstate::ChainstateError>((is_ibd, actual_tip))
    })??;

    // Note:
    // 1) When chainstate receives multiple blocks in rapid succession, mempool may start lagging
    // behind it significantly. So a situation is possible when the chainstate is out of ibd
    // already, but new_tip corresponds to an earlier block, which was obtained when the node
    // was still in ibd.
    // 2) If we allowed mempool to handle new_tip events normally while it's lagging, it would lead
    // to issues. E.g. in the past it was possible for mempool to try connecting transactions of
    // a past block to some of that block's descendants because of this.
    // So we bail out if new_tip isn't equal to the actual tip of the chainstate.
    // (Note that this check doesn't fully prevent mempool from falling out of sync with chainstate.
    // E.g a new chainstate tip may appear while mempool is in the process of reorging transactions,
    // which still may cause issues).
    if is_ibd || new_tip != actual_tip {
        log::debug!("Not updating mempool: is_ibd = {is_ibd}, new_tip = {new_tip:?}, actual_tip = {actual_tip:?}");

        if is_ibd {
            // Note: mempool.reset() will also re-create the tx verifier from the current chainstate,
            // which will also change its "best block for utxos". This is not really needed here,
            // but some existing functional tests, namely blockprod_ibd.py and mempool_ibd.py,
            // use this fact to detect that the corresponding new tip event has already reached
            // the mempool. TODO: refactor the tests, remove this call of "tx_pool.reset()".
            let mut old_transactions = tx_pool.reset();
            if old_transactions.next().is_some() {
                // Note: actually, this should never happen during ibd.
                log::warn!("Discarding mempool transactions during IBD");
            }
        }
        return Ok(());
    }

    // TODO: also check whether any of the existing txs in the orphan pool are no longer orphans
    // due to the newly mined txs.

    match fetch_disconnected_txs(tx_pool, new_tip) {
        Ok(to_insert) => reorg_mempool_transactions(tx_pool, to_insert, finalizer),
        Err(err) => {
            log::error!("Error fetching disconnected transactions after reorg: {err}");
            refresh_mempool(tx_pool, finalizer)
        }
    }
}

fn reorg_mempool_transactions<M: MemoryUsageEstimator>(
    tx_pool: &mut TxPool<M>,
    txs_to_insert: impl Iterator<Item = TxEntry>,
    mut finalizer: impl FnMut(TxAdditionOutcome, &TxPool<M>),
) -> Result<(), ReorgError> {
    let old_transactions = tx_pool.reset();

    log::debug!(
        "Reorging mempool txs, tx_verifier's best block for utxos after mempool reset: {:?}",
        tx_pool
            .tx_verifier
            .get_best_block_for_utxos()
            .map_err(|_| ReorgError::BestBlockForUtxos)?
    );

    for tx in txs_to_insert {
        let tx_id = *tx.tx_id();
        log::trace!("Adding {tx_id} after reorg");
        if let Err(e) = tx_pool.add_transaction(tx, &mut finalizer) {
            log::debug!("Disconnected transaction {tx_id:?} no longer validates: {e:?}")
        }
    }

    // Re-populate the verifier with transactions from mempool
    for tx in old_transactions {
        let tx_id = *tx.tx_id();
        log::trace!("Adding {tx_id} after reorg");
        if let Err(e) = tx_pool.add_transaction(tx, &mut finalizer) {
            log::debug!("Evicting {tx_id:?} from mempool: {e:?}")
        }
    }

    Ok(())
}

pub fn refresh_mempool<M: MemoryUsageEstimator>(
    tx_pool: &mut TxPool<M>,
    finalizer: impl FnMut(TxAdditionOutcome, &TxPool<M>),
) -> Result<(), ReorgError> {
    reorg_mempool_transactions(tx_pool, std::iter::empty(), finalizer)
}
