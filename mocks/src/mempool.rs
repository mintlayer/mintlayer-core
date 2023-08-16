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
    error::Error, event::MempoolEvent, tx_accumulator::TransactionAccumulator, FeeRate,
    MempoolInterface, MempoolMaxSize, MempoolSubsystemInterface, TxOrigin, TxStatus,
};
use subsystem::{CallRequest, ShutdownRequest};

mockall::mock! {
    pub MempoolInterfaceMock {}

    impl MempoolInterface for MempoolInterfaceMock {
        fn add_transaction(
            &mut self,
            tx: SignedTransaction,
            origin: TxOrigin,
        ) -> Result<TxStatus, Error>;

        fn get_all(&self) -> Vec<SignedTransaction>;
        fn transaction(&self, id: &Id<Transaction>) -> Option<SignedTransaction>;
        fn orphan_transaction(&self, id: &Id<Transaction>) -> Option<SignedTransaction>;
        fn contains_transaction(&self, tx: &Id<Transaction>) -> bool;
        fn contains_orphan_transaction(&self, tx: &Id<Transaction>) -> bool;
        fn best_block_id(&self) -> Id<GenBlock>;

        fn collect_txs(
            &self,
            tx_accumulator: Box<dyn TransactionAccumulator + Send>,
        ) -> Result<Option<Box<dyn TransactionAccumulator>>, Error>;

        fn subscribe_to_events(&mut self, handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>);
        fn memory_usage(&self) -> usize;
        fn get_max_size(&self) -> MempoolMaxSize;
        fn set_max_size(&mut self, max_size: MempoolMaxSize) -> Result<(), Error>;
        fn get_fee_rate(&self, in_top_x_mb: usize) -> Result<FeeRate, Error>;
        fn notify_peer_disconnected(&mut self, peer_id: p2p_types::PeerId);
    }
}

#[async_trait::async_trait]
impl MempoolSubsystemInterface for MockMempoolInterfaceMock {
    async fn run(
        mut self,
        mut call_rq: CallRequest<dyn MempoolInterface>,
        mut shut_rq: ShutdownRequest,
    ) {
        tokio::select! {
            call = call_rq.recv() => call(&mut self).await,
            () = shut_rq.recv() => return,
        }
    }
}
