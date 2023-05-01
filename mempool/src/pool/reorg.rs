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

use crate::{get_memory_usage::GetMemoryUsage, pool::Mempool};

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

/// Iterate over blocks following the parent link. Apply given function to each block.
fn for_each_block<C: ChainstateInterface + ?Sized>(
    chainstate: &C,
    mut curr_id: Id<Block>,
    stop_id: Id<GenBlock>,
    mut func: impl FnMut(Block),
) -> Result<(), ReorgError> {
    let chain_config = chainstate.get_chain_config();
    while curr_id != stop_id {
        let block = chainstate
            .get_block(curr_id)?
            .ok_or_else(|| ReorgError::BlockNotFound(curr_id))?;
        curr_id = match block.prev_block_id().classify(chain_config) {
            common::chain::GenBlockId::Genesis(_) => break,
            common::chain::GenBlockId::Block(block_id) => block_id,
        };
        func(block);
    }
    Ok(())
}

fn find_disconnected_txs<C: ChainstateInterface + ?Sized>(
    chainstate: &C,
    old_tip_id: Id<GenBlock>,
    new_tip_id: Id<Block>,
) -> Result<Vec<SignedTransaction>, ReorgError> {
    let chain_config = chainstate.get_chain_config();
    let old_tip_id = match old_tip_id.classify(chain_config) {
        common::chain::GenBlockId::Genesis(_) => return Ok(Vec::new()),
        common::chain::GenBlockId::Block(id) => id,
    };

    let common_id = {
        let old_index = chainstate.get_block_index(&old_tip_id)?.ok_or(ReorgError::OldTipIndex)?;
        let new_index = chainstate.get_block_index(&new_tip_id)?.ok_or(ReorgError::NewTipIndex)?;
        let common_index = chainstate.last_common_ancestor(&old_index.into(), &new_index.into())?;
        common_index.block_id()
    };

    // Short circuit the expensive processing below if no blocks are being disconnected
    if old_tip_id == common_id {
        return Ok(Vec::new());
    }

    // Collect IDs of transactions included in the newly connected chain
    let mut connected_txs = BTreeSet::new();
    for_each_block(chainstate, new_tip_id, common_id, |block| {
        connected_txs.extend(block.transactions().iter().map(|t| t.transaction().get_id()))
    })?;

    // Collect txns that have been removed from the blockchain and not added on the new fork
    let mut disconnected_txs = Vec::new();
    for_each_block(chainstate, old_tip_id, common_id, |block| {
        // We iterate blocks in the reverse order, so for consistent transaction input/output
        // dependencies, take transactions in reverse too,
        let txns = block.transactions().iter().rev();
        // We disregard transactions that are re-added on the newly connected chain
        let txns = txns.filter(|txn| !connected_txs.contains(&txn.transaction().get_id()));
        disconnected_txs.extend(txns.cloned())
    })?;

    Ok(disconnected_txs)
}

fn fetch_disconnected_txs<M>(
    mempool: &Mempool<M>,
    new_tip: Id<Block>,
) -> Result<Vec<SignedTransaction>, ReorgError> {
    let chainstate = mempool.blocking_chainstate_handle();

    let old_tip = mempool.tx_verifier.get_best_block_for_utxos().map_err(|_| ReorgError::OldTip)?;
    if old_tip == new_tip {
        return Ok(Vec::new());
    }

    chainstate.call(move |c| find_disconnected_txs(c.as_ref(), old_tip, new_tip))?
}

pub fn handle_new_tip<M: GetMemoryUsage>(mempool: &mut Mempool<M>, new_tip: Id<Block>) {
    mempool.rolling_fee_rate.get_mut().set_block_since_last_rolling_fee_bump(true);

    let mut disconnected_txs = fetch_disconnected_txs(mempool, new_tip)
        .log_err_pfx("Fetching disconnected transactions on a reorg")
        .unwrap_or_default();

    let old_transactions = mempool.reset();

    // Re-populate the verifier with transactions from disconnected chain.
    // The transactions are returned in the order of them being disconnected which is the opposite
    // of what we want, so we need to reverse the iterator here.
    while let Some(tx) = disconnected_txs.pop() {
        let tx_id = tx.transaction().get_id();
        if let Err(e) = mempool.add_transaction(tx) {
            log::debug!("Disconnected transaction {tx_id:?} no longer validates: {e:?}")
        }
    }

    // Re-populate the verifier with transactions from mempool
    for tx in old_transactions {
        let tx_id = tx.transaction().get_id();
        if let Err(e) = mempool.add_transaction(tx) {
            log::debug!("Evicting {tx_id:?} from mempool: {e:?}")
        }
    }
}
