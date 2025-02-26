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

use crate::{
    error::{BlockConstructionError, TxValidationError},
    pool::tx_pool::{tx_verifier, TxMempoolEntry, TxPool},
    tx_accumulator::{PackingStrategy, TransactionAccumulator},
};

use std::{
    cmp::Ordering,
    collections::{binary_heap, btree_map, BTreeMap, BTreeSet, BinaryHeap},
    ops::Deref,
};

use chainstate::tx_verifier::transaction_verifier::TransactionSourceWithHeight;
use common::{
    chain::transaction::Transaction,
    primitives::{Id, Idable},
};
use logging::log;
use utils::{ensure, graph_traversals, shallow_clone::ShallowClone};

/// Transaction entry together with priority
#[derive(Clone, Debug, Eq, PartialEq)]
struct EntryByScore<'a> {
    entry: &'a TxMempoolEntry,
}

impl PartialOrd for EntryByScore<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::ops::Deref for EntryByScore<'_> {
    type Target = TxMempoolEntry;
    fn deref(&self) -> &Self::Target {
        self.entry
    }
}

impl Ord for EntryByScore<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ancestor_score()
            .cmp(&other.ancestor_score())
            .then_with(|| self.tx_id().cmp(other.tx_id()))
    }
}

impl<'a> From<&'a TxMempoolEntry> for EntryByScore<'a> {
    fn from(entry: &'a TxMempoolEntry) -> Self {
        Self { entry }
    }
}

/// Fill the TransactionAccumulator with transactions from the mempool
/// Returns the updated TransactionAccumulator. Ok(None) means that a
/// recoverable error happened (such as that the mempool tip moved).
pub fn collect_txs<M>(
    mempool: &TxPool<M>,
    mut tx_accumulator: Box<dyn TransactionAccumulator>,
    transaction_ids: Vec<Id<Transaction>>,
    packing_strategy: PackingStrategy,
) -> Result<Option<Box<dyn TransactionAccumulator>>, BlockConstructionError> {
    let mempool_tip = mempool.best_block_id();
    let unlock_timestamp = tx_accumulator.unlock_timestamp();

    if tx_accumulator.expected_tip() != mempool_tip {
        return Ok(None);
    }

    let chainstate = tx_verifier::ChainstateHandle::new(mempool.chainstate_handle.shallow_clone());
    let chain_config = mempool.chain_config.deref();
    let utxo_view = tx_verifier::MempoolUtxoView::new(mempool, chainstate.shallow_clone());

    // Transaction verifier to detect cases where mempool is not fully up-to-date with
    // transaction dependencies.
    let mut tx_verifier = tx_verifier::create(
        mempool.chain_config.shallow_clone(),
        mempool.chainstate_handle.shallow_clone(),
    );

    let best_index = mempool
        .blocking_chainstate_handle()
        .call(|c| c.get_best_block_index())?
        .expect("best index to exist");
    let tx_source = TransactionSourceWithHeight::for_mempool(&best_index);

    // Use transactions already in the Accumulator to check for uniqueness and to update the
    // verifier state to update UTXOs they consume / provide.
    let accum_ids = tx_accumulator
        .transactions()
        .iter()
        .map(|transaction| {
            let _fee =
                tx_verifier.connect_transaction(&tx_source, transaction, &unlock_timestamp)?;
            Ok(transaction.transaction().get_id())
        })
        .collect::<Result<Vec<_>, TxValidationError>>()?;

    // Set of transactions already placed into the accumulator
    let mut emitted: BTreeSet<_> = accum_ids.iter().collect();
    // Set of already processed transactions, for de-duplication
    let mut processed = emitted.clone();

    // Transaction IDs specified by the user
    let given_txids = {
        for tx_id in &transaction_ids {
            ensure!(
                mempool.store.get_entry(tx_id).is_some(),
                BlockConstructionError::TxNotFound(*tx_id),
            );
        }
        // Pull in the parents before the user-specified transactions so we get a valid sequence
        graph_traversals::dag_depth_postorder_multiroot(&transaction_ids, |tx_id| {
            mempool.store.get_entry(tx_id).expect("already checked").parents()
        })
    };

    // Transaction IDs taken from mempool to fill in the rest of the block
    let mempool_txids = {
        // Get transactions from mempool by score
        let txids = mempool.store.txs_by_ancestor_score.iter().map(|x| &x.1).rev();
        // Take the appropriate amount of them as determined by the packing strategy
        txids.take(match packing_strategy {
            PackingStrategy::FillSpaceFromMempool => usize::MAX,
            PackingStrategy::LeaveEmptySpace => 0,
        })
    };

    // Put all the transaction IDs together
    let mut tx_iter = given_txids
        .chain(mempool_txids)
        .filter_map(|tx_id| {
            // If the transaction with this ID has already been processed, skip it
            ensure!(processed.insert(tx_id));
            let tx = mempool.store.txs_by_id.get(tx_id).expect("already checked").deref();

            tx_verifier::input_check::verify_timelocks(
                tx.transaction(),
                chain_config,
                &utxo_view,
                &chainstate,
                mempool_tip,
                best_index.block_height().next_height(),
                unlock_timestamp,
            )
            .ok()?;
            Some(tx)
        })
        .fuse()
        .peekable();

    // Set of transaction waiting for one or more parents to be emitted
    let mut pending = BTreeMap::new();
    // A queue of transactions that can be emitted
    let mut ready = BinaryHeap::<EntryByScore>::new();

    while !tx_accumulator.done() {
        // Take out the transactions from tx_iter until there is one ready
        while let Some(tx) = tx_iter.peek() {
            let missing_parents: usize = tx.parents().filter(|p| !emitted.contains(p)).count();
            if missing_parents == 0 {
                break;
            } else {
                pending.insert(tx.tx_id(), missing_parents);
                let _ = tx_iter.next();
            }
        }

        let next_tx = match (tx_iter.peek(), ready.peek_mut()) {
            (Some(store_tx), Some(ready_tx)) => {
                if store_tx.ancestor_score() > ready_tx.ancestor_score() {
                    tx_iter.next().expect("just checked")
                } else {
                    binary_heap::PeekMut::pop(ready_tx).entry
                }
            }
            (Some(_store_tx), None) => tx_iter.next().expect("just checked"),
            (None, Some(ready_tx)) => binary_heap::PeekMut::pop(ready_tx).entry,
            (None, None) => break,
        };

        let verification_result =
            tx_verifier.connect_transaction(&tx_source, next_tx.transaction(), &unlock_timestamp);

        if let Err(err) = verification_result {
            // TODO Narrow down when the critical error is presented. Printing the error may be a
            // false positive if the tip moves during the execution of this function.
            log::error!(
                "CRITICAL: Verifier and mempool do not agree on transaction deps for {}: {err}",
                next_tx.tx_id()
            );
            continue;
        }

        if let Err(err) = tx_accumulator.add_tx(next_tx.transaction().clone(), next_tx.fee()) {
            log::error!(
                "CRITICAL: Failed to add transaction {} from mempool. Error: {err}",
                next_tx.tx_id(),
            );
            break;
        }

        emitted.insert(next_tx.tx_id());

        // Release newly ready transactions
        for child in next_tx.children() {
            match pending.entry(child) {
                btree_map::Entry::Vacant(_) => (),
                btree_map::Entry::Occupied(mut c) => match c.get_mut() {
                    0 => panic!("pending with 0 missing parents"),
                    1 => {
                        // This was the last missing parent, put the tx into the ready queue
                        ready.push(mempool.store.txs_by_id[c.key()].deref().into());
                        c.remove();
                    }
                    n => *n -= 1,
                },
            }
        }
    }

    let final_chainstate_tip =
        utxo::UtxosView::best_block_hash(&chainstate).expect("cannot fetch tip");
    ensure!(
        mempool_tip == final_chainstate_tip,
        BlockConstructionError::TipMoved(mempool_tip, final_chainstate_tip),
    );

    Ok(Some(tx_accumulator))
}
