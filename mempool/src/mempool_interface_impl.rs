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

use std::sync::Arc;

use crate::config::GetMemoryUsage;
use crate::error::Error;
use crate::tx_accumulator::TransactionAccumulator;
use crate::MempoolEvent;
use crate::MempoolInterface;
use chainstate::chainstate_interface::ChainstateInterface;
use common::chain::signed_transaction::SignedTransaction;
use common::chain::ChainConfig;
use common::chain::Transaction;
use common::primitives::Id;
use common::time_getter::TimeGetter;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use utils::eventhandler::EventHandler;

use pool::Mempool;
pub use pool::SystemUsageEstimator;

mod pool;

pub struct MempoolInterfaceImpl {
    sender: mpsc::UnboundedSender<MempoolMethodCall>,
}

impl MempoolInterfaceImpl {
    pub async fn new<M: GetMemoryUsage + Sync + Send + 'static>(
        chain_config: Arc<ChainConfig>,
        chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
        time_getter: TimeGetter,
        memory_usage_estimator: M,
    ) -> Result<Self, crate::error::Error> {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();

        Mempool::new(
            chain_config,
            chainstate_handle,
            time_getter,
            memory_usage_estimator,
            receiver,
        )
        .run()
        .await?;

        Ok(Self { sender })
    }
}

pub type MempoolEventHandler = EventHandler<MempoolEvent>;

pub enum MempoolMethodCall {
    AddTransaction {
        tx: SignedTransaction,
        rtx: oneshot::Sender<Result<(), Error>>,
    },
    GetAll {
        rtx: oneshot::Sender<Vec<SignedTransaction>>,
    },
    CollectTxs {
        tx_accumulator: Box<dyn TransactionAccumulator + Send>,
        rtx: oneshot::Sender<Box<dyn TransactionAccumulator>>,
    },
    ContainsTransaction {
        tx_id: Id<Transaction>,
        rtx: oneshot::Sender<bool>,
    },
    SubscribeToEvents {
        handler: MempoolEventHandler,
        rtx: oneshot::Sender<()>,
    },
}

#[async_trait::async_trait]
impl MempoolInterface for MempoolInterfaceImpl {
    async fn add_transaction(&mut self, tx: SignedTransaction) -> Result<(), Error> {
        let (rtx, rrx) = tokio::sync::oneshot::channel();
        self.sender
            .send(MempoolMethodCall::AddTransaction { tx, rtx })
            .map_err(|_| Error::SendError)?;
        rrx.await.map_err(|_| Error::RecvError)?
    }

    async fn get_all(&self) -> Result<Vec<SignedTransaction>, Error> {
        let (rtx, rrx) = tokio::sync::oneshot::channel();
        self.sender
            .send(MempoolMethodCall::GetAll { rtx })
            .map_err(|_| Error::SendError)?;
        rrx.await.map_err(|_| Error::RecvError)
    }

    // Returns `true` if the mempool contains a transaction with the given id, `false` otherwise.
    async fn contains_transaction(&self, tx_id: &Id<Transaction>) -> Result<bool, Error> {
        let (rtx, rrx) = tokio::sync::oneshot::channel();
        self.sender
            .send(MempoolMethodCall::ContainsTransaction { tx_id: *tx_id, rtx })
            .map_err(|_| Error::SendError)?;
        rrx.await.map_err(|_| Error::RecvError)
    }

    async fn collect_txs(
        &self,
        tx_accumulator: Box<dyn TransactionAccumulator + Send>,
    ) -> Result<Box<dyn TransactionAccumulator>, Error> {
        let (rtx, rrx) = tokio::sync::oneshot::channel();
        self.sender
            .send(MempoolMethodCall::CollectTxs {
                tx_accumulator,
                rtx,
            })
            .map_err(|_| Error::SendError)?;
        rrx.await.map_err(|_| Error::RecvError)
    }

    async fn subscribe_to_events(
        &mut self,
        handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>,
    ) -> Result<(), Error> {
        let (rtx, rrx) = tokio::sync::oneshot::channel();
        self.sender
            .send(MempoolMethodCall::SubscribeToEvents { handler, rtx })
            .map_err(|_| Error::SendError)?;
        rrx.await.map_err(|_| Error::RecvError)
    }
}
