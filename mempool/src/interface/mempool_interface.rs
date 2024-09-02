// Copyright (c) 2022-2023 RBB S.r.l
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
    error::{BlockConstructionError, Error},
    event::MempoolEvent,
    tx_accumulator::{PackingStrategy, TransactionAccumulator},
    tx_origin::{LocalTxOrigin, RemoteTxOrigin},
    FeeRate, MempoolMaxSize, TxOptions, TxStatus,
};
use common::{
    chain::{GenBlock, SignedTransaction, Transaction},
    primitives::Id,
};
use std::{num::NonZeroUsize, sync::Arc};

pub trait MempoolInterface: Send + Sync {
    /// Add a transaction from remote peer to mempool
    fn add_transaction_remote(
        &mut self,
        tx: SignedTransaction,
        origin: RemoteTxOrigin,
        options: TxOptions,
    ) -> Result<TxStatus, Error>;

    /// Add a local transaction
    fn add_transaction_local(
        &mut self,
        tx: SignedTransaction,
        origin: LocalTxOrigin,
        options: TxOptions,
    ) -> Result<(), Error>;

    /// Get all transactions from mempool
    fn get_all(&self) -> Vec<SignedTransaction>;

    /// Get a specific transaction from the main mempool (non-orphan)
    fn transaction(&self, id: &Id<Transaction>) -> Option<SignedTransaction>;

    /// Get a specific transaction from the orphan pool
    fn orphan_transaction(&self, id: &Id<Transaction>) -> Option<SignedTransaction>;

    /// Check given transaction is contained in the main mempool (non-orphan)
    fn contains_transaction(&self, tx: &Id<Transaction>) -> bool;

    /// Check given transaction is contained in the main mempool (non-orphan)
    fn contains_orphan_transaction(&self, tx: &Id<Transaction>) -> bool;

    /// Best block ID according to mempool. May be temporarily out of sync with chainstate.
    fn best_block_id(&self) -> Id<GenBlock>;

    /// Collect transactions by putting them in given accumulator
    /// Returns the accumulator with the collected transactions
    /// Ok(None) is returned on recoverable errors, such as if
    /// the tip changed before collecting transactions started.
    fn collect_txs(
        &self,
        tx_accumulator: Box<dyn TransactionAccumulator + Send>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Option<Box<dyn TransactionAccumulator>>, BlockConstructionError>;

    /// Subscribe to events emitted by mempool subsystem
    fn subscribe_to_subsystem_events(&mut self, handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>);

    /// Subscribe to broadcast mempool events
    fn subscribe_to_rpc_events(&mut self) -> utils_networking::broadcaster::Receiver<MempoolEvent>;

    /// Get current memory usage
    fn memory_usage(&self) -> usize;

    /// Get the maximum allowed mempool size, as in, the maximum total byte-size of all transactions in the mempool.
    fn get_size_limit(&self) -> MempoolMaxSize;

    /// Set the allowed size limit for the total of all transactions in the mempool.
    fn set_size_limit(&mut self, max_size: MempoolMaxSize) -> Result<(), Error>;

    /// Get the fee rate such that it would put the new transaction in the top X MB of the mempool
    /// making it less likely to get rejected or trimmed in the case the mempool is full
    fn get_fee_rate(&self, in_top_x_mb: usize) -> FeeRate;

    /// Get the fee rate at multiple uniformly distributed points along the mempool's transactions
    fn get_fee_rate_points(&self, num_points: NonZeroUsize)
        -> Result<Vec<(usize, FeeRate)>, Error>;

    /// Notify mempool given peer has disconnected
    fn notify_peer_disconnected(&mut self, peer_id: p2p_types::PeerId);

    /// Notify mempool about given chainstate event
    fn notify_chainstate_event(&mut self, event: chainstate::ChainstateEvent);
}
