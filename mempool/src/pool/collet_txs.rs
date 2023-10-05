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
    pool::{store, tx_verifier, Mempool, TxMempoolEntry},
    tx_accumulator::{PackingStrategy, TransactionAccumulator},
};

use std::{
    collections::{binary_heap, btree_map, BTreeMap, BTreeSet, BinaryHeap},
    ops::Deref,
};

use chainstate::tx_verifier::transaction_verifier::TransactionSourceForConnect;
use common::{
    chain::transaction::Transaction,
    primitives::{Id, Idable},
};
use logging::log;
use utils::shallow_clone::ShallowClone;

pub fn collect_txs<M>(
    mempool: &Mempool<M>,
    mut tx_accumulator: Box<dyn TransactionAccumulator>,
    transaction_ids: Vec<Id<Transaction>>,
    packing_strategy: PackingStrategy,
) -> Option<Box<dyn TransactionAccumulator>> {
    let mempool_tip = mempool.best_block_id();

    if tx_accumulator.expected_tip() != mempool_tip {
        log::debug!(
                "Mempool rejected transaction accumulator due to different tip: expected tip {:?} (current tip {:?})",
                tx_accumulator.expected_tip(),
                mempool.best_block_id(),
            );
        return None;
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

    let verifier_time = tx_accumulator.block_timestamp();

    let best_index = mempool
        .blocking_chainstate_handle()
        .call(|c| c.get_best_block_index())
        .expect("chainstate to live")
        .expect("best index to exist");
    let tx_source = TransactionSourceForConnect::for_mempool(&best_index);

    // Use transactions already in the Accumulator to sort for
    // uniqueness only i.e don't send them through the verifier
    let mut unique_txids = BTreeSet::from_iter(
        tx_accumulator.transactions().iter().map(|tx| tx.transaction().get_id()),
    );

    let mut ordered_txids =
        Vec::from_iter(transaction_ids.iter().filter(|&tx_id| unique_txids.insert(*tx_id)));

    if packing_strategy == PackingStrategy::FillSpaceFromMempool {
        ordered_txids.extend(
            mempool
                .store
                .txs_by_ancestor_score
                .iter()
                .map(|(_, id)| id)
                .rev()
                .filter(|&tx_id| unique_txids.insert(*tx_id)),
        );
    }

    let block_timestamp = tx_accumulator.block_timestamp();

    let mut tx_iter = ordered_txids
        .iter()
        .filter_map(|tx_id| {
            let tx = mempool.store.txs_by_id.get(tx_id)?.deref();
            chainstate::tx_verifier::timelock_check::check_timelocks(
                &chainstate,
                chain_config,
                &utxo_view,
                tx.transaction(),
                &tx_source,
                &block_timestamp,
            )
            .ok()?;
            Some(tx)
        })
        .fuse()
        .peekable();

    // Set of transactions already placed into the accumulator
    let mut emitted = BTreeSet::new();
    // Set of transaction waiting for one or more parents to be emitted
    let mut pending = BTreeMap::new();
    // A queue of transactions that can be emitted
    let mut ready = BinaryHeap::<store::TxMempoolEntryByScore<&TxMempoolEntry>>::new();

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
                    binary_heap::PeekMut::pop(ready_tx).take_entry()
                }
            }
            (Some(_store_tx), None) => tx_iter.next().expect("just checked"),
            (None, Some(ready_tx)) => binary_heap::PeekMut::pop(ready_tx).take_entry(),
            (None, None) => break,
        };

        let verification_result = tx_verifier.connect_transaction(
            &tx_source,
            next_tx.transaction(),
            &verifier_time,
            None,
        );

        if let Err(err) = verification_result {
            log::error!(
                    "CRITICAL ERROR: Verifier and mempool do not agree on transaction deps for {}. Error: {err}",
                    next_tx.tx_id()
                );
            continue;
        }

        if let Err(err) = tx_accumulator.add_tx(next_tx.transaction().clone(), next_tx.fee()) {
            log::error!(
                "CRITICAL: Failed to add transaction {} from mempool. Error: {}",
                next_tx.tx_id(),
                err
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
    if final_chainstate_tip != mempool_tip {
        log::debug!(
            "Chainstate moved while collecting txns: mempool {:?}, chainstate {:?}",
            mempool_tip,
            final_chainstate_tip,
        );
        return None;
    }

    Some(tx_accumulator)
}
