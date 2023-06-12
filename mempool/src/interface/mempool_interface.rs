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

use crate::{error::Error, tx_accumulator::TransactionAccumulator, MempoolEvent, TxStatus};
use common::{
    chain::{GenBlock, SignedTransaction, Transaction},
    primitives::Id,
};
use std::sync::Arc;
use subsystem::{CallRequest, ShutdownRequest};

pub trait MempoolInterface: Send + Sync {
    /// Add a transaction to mempool
    fn add_transaction(&mut self, tx: SignedTransaction) -> Result<TxStatus, Error>;

    /// Get all transactions from mempool
    fn get_all(&self) -> Result<Vec<SignedTransaction>, Error>;

    /// Get a specific transaction from the main mempool (non-orphan)
    fn transaction(&self, id: &Id<Transaction>) -> Result<Option<SignedTransaction>, Error>;

    /// Get a specific transaction from the orphan pool
    fn orphan_transaction(&self, id: &Id<Transaction>) -> Result<Option<SignedTransaction>, Error>;

    /// Check given transaction is contained in the main mempool (non-orphan)
    fn contains_transaction(&self, tx: &Id<Transaction>) -> Result<bool, Error>;

    /// Check given transaction is contained in the main mempool (non-orphan)
    fn contains_orphan_transaction(&self, tx: &Id<Transaction>) -> Result<bool, Error>;

    /// Best block ID according to mempool. May be temporarily out of sync with chainstate.
    fn best_block_id(&self) -> Id<GenBlock>;

    /// Collect transactions by putting them in given accumulator
    fn collect_txs(
        &self,
        tx_accumulator: Box<dyn TransactionAccumulator + Send>,
    ) -> Result<Box<dyn TransactionAccumulator>, Error>;

    /// Subscribe to events emitted by mempool
    fn subscribe_to_events(
        &mut self,
        handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>,
    ) -> Result<(), Error>;
}

#[async_trait::async_trait]
pub trait MempoolSubsystemInterface: 'static {
    async fn run(self, call_rq: CallRequest<dyn MempoolInterface>, shut_rq: ShutdownRequest);
}
