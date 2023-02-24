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

use crate::error::Error;
use crate::tx_accumulator::TransactionAccumulator;
use crate::MempoolEvent;
use common::chain::{SignedTransaction, Transaction};
use common::primitives::Id;
use std::sync::{Arc, Mutex};
use subsystem::{CallRequest, ShutdownRequest};

use super::mempool_interface::{MempoolInterface, MempoolSubsystemInterface};

#[derive(Clone)]
pub struct MempoolInterfaceMock {
    pub add_transaction_called: Arc<Mutex<bool>>,
    pub add_transaction_should_error: Arc<Mutex<bool>>,
    pub get_all_called: Arc<Mutex<bool>>,
    pub get_all_should_error: Arc<Mutex<bool>>,
    pub contains_transaction_called: Arc<Mutex<bool>>,
    pub contains_transaction_should_error: Arc<Mutex<bool>>,
    pub collect_txs_called: Arc<Mutex<bool>>,
    pub collect_txs_should_error: Arc<Mutex<bool>>,
    pub subscribe_to_events_called: Arc<Mutex<bool>>,
    pub subscribe_to_events_should_error: Arc<Mutex<bool>>,
    pub run_called: Arc<Mutex<bool>>,
    pub run_should_error: Arc<Mutex<bool>>,
}

impl Default for MempoolInterfaceMock {
    fn default() -> Self {
        Self::new()
    }
}

impl MempoolInterfaceMock {
    pub fn new() -> MempoolInterfaceMock {
        MempoolInterfaceMock {
            add_transaction_called: Arc::new(Mutex::new(false)),
            add_transaction_should_error: Arc::new(Mutex::new(false)),
            get_all_called: Arc::new(Mutex::new(false)),
            get_all_should_error: Arc::new(Mutex::new(false)),
            contains_transaction_called: Arc::new(Mutex::new(false)),
            contains_transaction_should_error: Arc::new(Mutex::new(false)),
            collect_txs_called: Arc::new(Mutex::new(false)),
            collect_txs_should_error: Arc::new(Mutex::new(false)),
            subscribe_to_events_called: Arc::new(Mutex::new(false)),
            subscribe_to_events_should_error: Arc::new(Mutex::new(false)),
            run_called: Arc::new(Mutex::new(false)),
            run_should_error: Arc::new(Mutex::new(false)),
        }
    }
}

#[async_trait::async_trait]
impl MempoolInterface for MempoolInterfaceMock {
    async fn add_transaction(&mut self, _tx: SignedTransaction) -> Result<(), Error> {
        *self.add_transaction_called.lock().unwrap() = true;

        if *self.add_transaction_should_error.lock().unwrap() {
            Err(Error::SubsystemFailure)
        } else {
            Ok(())
        }
    }

    async fn get_all(&self) -> Result<Vec<SignedTransaction>, Error> {
        *self.get_all_called.lock().unwrap() = true;

        if *self.get_all_should_error.lock().unwrap() {
            Err(Error::SubsystemFailure)
        } else {
            Ok(vec![])
        }
    }

    async fn contains_transaction(&self, _tx: &Id<Transaction>) -> Result<bool, Error> {
        *self.contains_transaction_called.lock().unwrap() = true;

        if *self.contains_transaction_should_error.lock().unwrap() {
            Err(Error::SubsystemFailure)
        } else {
            Ok(true)
        }
    }

    async fn collect_txs(
        &self,
        tx_accumulator: Box<dyn TransactionAccumulator + Send>,
    ) -> Result<Box<dyn TransactionAccumulator>, Error> {
        *self.collect_txs_called.lock().unwrap() = true;

        if *self.collect_txs_should_error.lock().unwrap() {
            Err(Error::SubsystemFailure)
        } else {
            Ok(tx_accumulator)
        }
    }

    async fn subscribe_to_events(
        &mut self,
        _handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>,
    ) -> Result<(), Error> {
        *self.subscribe_to_events_called.lock().unwrap() = true;

        if *self.subscribe_to_events_should_error.lock().unwrap() {
            Err(Error::SubsystemFailure)
        } else {
            Ok(())
        }
    }
}

#[async_trait::async_trait]
impl MempoolSubsystemInterface for MempoolInterfaceMock {
    async fn run(
        mut self,
        mut call_rq: CallRequest<dyn MempoolInterface>,
        _shut_rq: ShutdownRequest,
    ) {
        *self.run_called.lock().unwrap() = true;

        if !*self.run_should_error.lock().unwrap() {
            tokio::select! {
                call = call_rq.recv() => call(&mut self).await
            }
        }
    }
}
