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
    chain::{Block, GenBlock, SignedTransaction},
    primitives::{Id, Idable},
};
use logging::log;
use utils::tap_log::TapLog;
use utxo::UtxosStorageRead;

use super::{MemoryUsageEstimator, Mempool, WorkQueue};
use crate::tx_origin::LocalTxOrigin;

/// An error that can happen in mempool on chain reorg
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReorgError {
    #[error(transparent)]
    Chainstate(#[from] chainstate::ChainstateError),
    #[error("Could not obtain the best block for utxos")]
    BestBlockForUtxos,
    #[error("Could not find the previous tip index")]
    OldTipIndex,
    #[error("Could not find the new tip index")]
    NewTipIndex,
    #[error("Block {0:?} not found while traversing history")]
    BlockNotFound(Id<Block>),
    #[error("Chainstate call: {0}")]
    ChainstateCall(#[from] subsystem::error::CallError),
}

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
            .ok_or_else(|| ReorgError::BlockNotFound(curr_block_id))?;
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
                .get_persistent_gen_block_index(&old_tip_id)?
                .ok_or(ReorgError::OldTipIndex)?;
            let new_index = chainstate
                .get_persistent_gen_block_index(&new_tip_id)?
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
    fn into_disconnected_transactions(self) -> impl Iterator<Item = SignedTransaction> {
        let connected_txs: BTreeSet<_> = self
            .connected
            .into_iter()
            .flat_map(|block| {
                block.into_transactions().into_iter().map(|tx| tx.transaction().get_id())
            })
            .collect();

        // The transactions are returned in the order of them being disconnected which is the
        // opposite of what we want for connecting, so we need to reverse the iterator here.
        self.disconnected
            .into_iter()
            .rev()
            .flat_map(|block| block.into_transactions())
            .filter(move |tx| !connected_txs.contains(&tx.transaction().get_id()))
    }
}

fn fetch_disconnected_txs<M>(
    mempool: &Mempool<M>,
    new_tip: Id<Block>,
) -> Result<impl Iterator<Item = SignedTransaction>, ReorgError> {
    let old_tip = mempool
        .tx_verifier
        .get_best_block_for_utxos()
        .map_err(|_| ReorgError::BestBlockForUtxos)?;

    log::debug!("Fetching disconnected txs, old_tip = {old_tip:?}");

    mempool
        .blocking_chainstate_handle()
        .call(move |c| ReorgData::from_chainstate(c, old_tip, new_tip.into()))?
        .map(ReorgData::into_disconnected_transactions)
}

pub fn handle_new_tip<M: MemoryUsageEstimator>(
    mempool: &mut Mempool<M>,
    new_tip: Id<Block>,
    work_queue: &mut WorkQueue,
) -> Result<(), ReorgError> {
    mempool.rolling_fee_rate.get_mut().set_block_since_last_rolling_fee_bump(true);

    let (is_ibd, actual_tip) = mempool.blocking_chainstate_handle().call(|cs| {
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
            // the mempool. TODO: refactor the tests, remove this call of "mempool.reset()".
            let mut old_transactions = mempool.reset();
            if old_transactions.next().is_some() {
                // Note: actually, this should never happen during ibd.
                log::warn!("Discarding mempool transactions during IBD");
            }
        }
        return Ok(());
    }

    let disconnected_txs = fetch_disconnected_txs(mempool, new_tip)
        .log_err_pfx("Fetching disconnected transactions on a reorg");

    match disconnected_txs {
        Ok(to_insert) => reorg_mempool_transactions(mempool, to_insert, work_queue),
        Err(_) => refresh_mempool(mempool),
    }
}

fn reorg_mempool_transactions<M: MemoryUsageEstimator>(
    mempool: &mut Mempool<M>,
    txs_to_insert: impl Iterator<Item = SignedTransaction>,
    work_queue: &mut WorkQueue,
) -> Result<(), ReorgError> {
    let old_transactions = mempool.reset();

    log::debug!(
        "Reorging mempool txs, tx_verifier's best block for utxos after mempool reset: {:?}",
        mempool
            .tx_verifier
            .get_best_block_for_utxos()
            .map_err(|_| ReorgError::BestBlockForUtxos)?
    );

    for tx in txs_to_insert {
        let tx_id = tx.transaction().get_id();
        let origin = LocalTxOrigin::PastBlock.into();
        if let Err(e) = mempool.add_transaction(tx, origin, work_queue) {
            log::debug!("Disconnected transaction {tx_id:?} no longer validates: {e:?}")
        }
    }

    // Re-populate the verifier with transactions from mempool
    for tx in old_transactions {
        let tx_id = *tx.tx_id();
        if let Err(e) = mempool.add_transaction_entry(tx) {
            log::debug!("Evicting {tx_id:?} from mempool: {e:?}")
        }
    }

    Ok(())
}

pub fn refresh_mempool<M: MemoryUsageEstimator>(
    mempool: &mut Mempool<M>,
) -> Result<(), ReorgError> {
    reorg_mempool_transactions(mempool, std::iter::empty(), &mut WorkQueue::new())
}
