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

use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;

use crate::error::Error;
use crate::interface::mempool_interface::MempoolInterface;
use crate::MempoolEvent;
use common::chain::signed_transaction::SignedTransaction;
use common::chain::transaction::Transaction;
use common::primitives::Id;

use crate::tx_accumulator::TransactionAccumulator;

#[async_trait::async_trait]
impl<
        T: Deref<Target = dyn MempoolInterface>
            + DerefMut<Target = dyn MempoolInterface>
            + Send
            + Sync,
    > MempoolInterface for T
{
    async fn add_transaction(&mut self, tx: SignedTransaction) -> Result<(), Error> {
        self.deref_mut().add_transaction(tx).await
    }
    async fn get_all(&self) -> Result<Vec<SignedTransaction>, Error> {
        self.deref().get_all().await
    }

    async fn contains_transaction(&self, tx: &Id<Transaction>) -> Result<bool, Error> {
        self.deref().contains_transaction(tx).await
    }

    async fn collect_txs(
        &self,
        tx_accumulator: Box<dyn TransactionAccumulator + Send>,
    ) -> Result<Box<dyn TransactionAccumulator>, Error> {
        self.deref().collect_txs(tx_accumulator).await
    }

    async fn subscribe_to_events(
        &mut self,
        handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>,
    ) -> Result<(), Error> {
        self.deref_mut().subscribe_to_events(handler).await
    }
}
