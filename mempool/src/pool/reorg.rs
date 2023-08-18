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
use utils::tap_error_log::LogError;
use utxo::UtxosStorageRead;

use super::{MemoryUsageEstimator, Mempool};
use crate::tx_origin::LocalTxOrigin;

/// An error that can happen in mempool on chain reorg
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReorgError {
    #[error(transparent)]
    Chainstate(#[from] chainstate::ChainstateError),
    #[error("Could not find the previous tip")]
    OldTip,
    #[error("Could not find the previous tip index")]
    OldTipIndex,
    #[error("Could not find the new tip index")]
    NewTipIndex,
    #[error("Block {0:?} not found while traversing history")]
    BlockNotFound(Id<Block>),
    #[error("Chainstate call: {0}")]
    ChainstateCall(#[from] subsystem::subsystem::CallError),
}

/// Collect blocks between the given two points
fn collect_blocks<C: ChainstateInterface>(
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
    fn from_chainstate<C: ChainstateInterface>(
        chainstate: &C,
        old_tip_id: Id<GenBlock>,
        new_tip_id: Id<GenBlock>,
    ) -> Result<Self, ReorgError> {
        let common_id = {
            let old_index =
                chainstate.get_gen_block_index(&old_tip_id)?.ok_or(ReorgError::OldTipIndex)?;
            let new_index =
                chainstate.get_gen_block_index(&new_tip_id)?.ok_or(ReorgError::NewTipIndex)?;
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
    let old_tip = mempool.tx_verifier.get_best_block_for_utxos().map_err(|_| ReorgError::OldTip)?;
    mempool
        .blocking_chainstate_handle()
        .call(move |c| ReorgData::from_chainstate(c, old_tip, new_tip.into()))?
        .map(ReorgData::into_disconnected_transactions)
}

pub fn handle_new_tip<M: MemoryUsageEstimator>(
    mempool: &mut Mempool<M>,
    new_tip: Id<Block>,
) -> Result<(), ReorgError> {
    mempool.rolling_fee_rate.get_mut().set_block_since_last_rolling_fee_bump(true);

    let is_ibd = mempool.blocking_chainstate_handle().call(|cs| cs.is_initial_block_download())?;
    if is_ibd {
        log::debug!("Not updating mempool tx verifier during IBD");

        // We still need to update the current tx_verifier tip
        let mut old_transactions = mempool.reset();
        if old_transactions.next().is_some() {
            log::warn!("Discarding mempool transactions during IBD");
        }
        return Ok(());
    }

    let disconnected_txs = fetch_disconnected_txs(mempool, new_tip)
        .log_err_pfx("Fetching disconnected transactions on a reorg");

    match disconnected_txs {
        Ok(to_insert) => refresh_mempool(mempool, to_insert),
        Err(_) => refresh_mempool(mempool, std::iter::empty()),
    }

    Ok(())
}

pub fn refresh_mempool<M: MemoryUsageEstimator>(
    mempool: &mut Mempool<M>,
    txs_to_insert: impl Iterator<Item = SignedTransaction>,
) {
    let old_transactions = mempool.reset();

    for tx in txs_to_insert {
        let tx_id = tx.transaction().get_id();
        if let Err(e) = mempool.add_transaction(tx, LocalTxOrigin::PastBlock.into()) {
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
}
