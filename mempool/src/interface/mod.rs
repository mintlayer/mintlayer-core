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

use crate::{error::Error, tx_accumulator::TransactionAccumulator, MempoolEvent};
use common::{
    chain::{signed_transaction::SignedTransaction, Transaction},
    primitives::Id,
};

#[async_trait::async_trait]
pub trait MempoolInterface: Send {
    async fn add_transaction(&mut self, tx: SignedTransaction) -> Result<(), Error>;
    async fn get_all(&self) -> Result<Vec<SignedTransaction>, Error>;

    // Returns `true` if the mempool contains a transaction with the given id, `false` otherwise.
    async fn contains_transaction(&self, tx: &Id<Transaction>) -> Result<bool, Error>;

    async fn collect_txs(
        &self,
        tx_accumulator: Box<dyn TransactionAccumulator + Send>,
    ) -> Result<Box<dyn TransactionAccumulator>, Error>;

    async fn subscribe_to_events(
        &mut self,
        handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>,
    ) -> Result<(), Error>;
}
