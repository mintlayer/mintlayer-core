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

#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use common::{
    chain::{GenBlock, SignedTransaction, Transaction},
    primitives::Id,
};
use mempool::{
    error::{Error, TxValidationError},
    event::MempoolEvent,
    tx_accumulator::TransactionAccumulator,
    MempoolInterface, MempoolMaxSize, MempoolSubsystemInterface, TxOrigin, TxStatus,
};
use subsystem::{subsystem::CallError, CallRequest, ShutdownRequest};
use utils::atomics::AcqRelAtomicBool;

#[derive(Clone)]
pub struct MempoolInterfaceMock {
    pub add_transaction_called: Arc<AcqRelAtomicBool>,
    pub add_transaction_should_error: Arc<AcqRelAtomicBool>,
    pub get_all_called: Arc<AcqRelAtomicBool>,
    pub contains_transaction_called: Arc<AcqRelAtomicBool>,
    pub collect_txs_called: Arc<AcqRelAtomicBool>,
    pub collect_txs_should_error: Arc<AcqRelAtomicBool>,
    pub subscribe_to_events_called: Arc<AcqRelAtomicBool>,
    pub run_called: Arc<AcqRelAtomicBool>,
    pub run_should_error: Arc<AcqRelAtomicBool>,
}

impl Default for MempoolInterfaceMock {
    fn default() -> Self {
        Self::new()
    }
}

impl MempoolInterfaceMock {
    pub fn new() -> MempoolInterfaceMock {
        MempoolInterfaceMock {
            add_transaction_called: Arc::new(AcqRelAtomicBool::new(false)),
            add_transaction_should_error: Arc::new(AcqRelAtomicBool::new(false)),
            get_all_called: Arc::new(AcqRelAtomicBool::new(false)),
            contains_transaction_called: Arc::new(AcqRelAtomicBool::new(false)),
            collect_txs_called: Arc::new(AcqRelAtomicBool::new(false)),
            collect_txs_should_error: Arc::new(AcqRelAtomicBool::new(false)),
            subscribe_to_events_called: Arc::new(AcqRelAtomicBool::new(false)),
            run_called: Arc::new(AcqRelAtomicBool::new(false)),
            run_should_error: Arc::new(AcqRelAtomicBool::new(false)),
        }
    }
}

const SUBSYSTEM_ERROR: Error =
    Error::Validity(TxValidationError::CallError(CallError::ResultFetchFailed));

#[async_trait::async_trait]
impl MempoolInterface for MempoolInterfaceMock {
    fn add_transaction(
        &mut self,
        _tx: SignedTransaction,
        _origin: TxOrigin,
    ) -> Result<TxStatus, Error> {
        self.add_transaction_called.store(true);

        if self.add_transaction_should_error.load() {
            Err(SUBSYSTEM_ERROR)
        } else {
            Ok(TxStatus::InMempool)
        }
    }

    fn get_all(&self) -> Vec<SignedTransaction> {
        self.get_all_called.store(true);
        Vec::new()
    }

    fn contains_transaction(&self, _tx: &Id<Transaction>) -> bool {
        self.contains_transaction_called.store(true);
        true
    }

    fn contains_orphan_transaction(&self, _tx: &Id<Transaction>) -> bool {
        true
    }

    fn transaction(&self, _id: &Id<Transaction>) -> Option<SignedTransaction> {
        None
    }

    fn orphan_transaction(&self, _: &Id<Transaction>) -> Option<SignedTransaction> {
        None
    }

    fn best_block_id(&self) -> Id<GenBlock> {
        unimplemented!()
    }

    fn collect_txs(
        &self,
        tx_accumulator: Box<dyn TransactionAccumulator + Send>,
    ) -> Result<Option<Box<dyn TransactionAccumulator>>, Error> {
        self.collect_txs_called.store(true);

        if self.collect_txs_should_error.load() {
            Err(SUBSYSTEM_ERROR)
        } else {
            Ok(Some(tx_accumulator))
        }
    }

    fn subscribe_to_events(&mut self, _handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>) {
        self.subscribe_to_events_called.store(true);
    }

    fn memory_usage(&self) -> usize {
        unimplemented!()
    }

    fn get_max_size(&self) -> MempoolMaxSize {
        unimplemented!()
    }

    fn set_max_size(&mut self, _max_size: MempoolMaxSize) -> Result<(), Error> {
        unimplemented!()
    }
}

#[async_trait::async_trait]
impl MempoolSubsystemInterface for MempoolInterfaceMock {
    async fn run(
        mut self,
        mut call_rq: CallRequest<dyn MempoolInterface>,
        mut shut_rq: ShutdownRequest,
    ) {
        self.run_called.store(true);

        if !self.run_should_error.load() {
            tokio::select! {
                call = call_rq.recv() => call(&mut self).await,
                () = shut_rq.recv() => return,
            }
        }
    }
}
