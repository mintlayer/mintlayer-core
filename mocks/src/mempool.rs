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

use std::{num::NonZeroUsize, sync::Arc};

use common::{
    chain::{GenBlock, SignedTransaction, Transaction},
    primitives::Id,
};
use mempool::{
    error::{BlockConstructionError, Error},
    event::MempoolEvent,
    tx_accumulator::{PackingStrategy, TransactionAccumulator},
    tx_origin::{LocalTxOrigin, RemoteTxOrigin},
    FeeRate, MempoolInterface, MempoolMaxSize, TxOptions, TxStatus,
};

mockall::mock! {
    pub MempoolInterface {}

    impl MempoolInterface for MempoolInterface {
        fn add_transaction_local(
            &mut self,
            tx: SignedTransaction,
            origin: LocalTxOrigin,
            options: TxOptions,
        ) -> Result<(), Error>;

        fn add_transaction_remote(
            &mut self,
            tx: SignedTransaction,
            origin: RemoteTxOrigin,
            options: TxOptions,
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
            transaction_ids: Vec<Id<Transaction>>,
            packing_strategy: PackingStrategy,
        ) -> Result<Option<Box<dyn TransactionAccumulator>>, BlockConstructionError>;

        fn subscribe_to_subsystem_events(&mut self, handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>);
        fn subscribe_to_rpc_events(&mut self) -> utils_networking::broadcaster::Receiver<MempoolEvent>;

        fn memory_usage(&self) -> usize;
        fn get_size_limit(&self) -> MempoolMaxSize;
        fn set_size_limit(&mut self, max_size: MempoolMaxSize) -> Result<(), Error>;
        fn get_fee_rate(&self, in_top_x_mb: usize) -> FeeRate;
        fn get_fee_rate_points(&self, num_points: NonZeroUsize) -> Result<Vec<(usize, FeeRate)>, Error>;

        fn notify_peer_disconnected(&mut self, peer_id: p2p_types::PeerId);
        fn notify_chainstate_event(&mut self, event: chainstate::ChainstateEvent);
    }
}

impl subsystem::Subsystem for MockMempoolInterface {
    type Interface = dyn MempoolInterface;

    fn interface_ref(&self) -> &Self::Interface {
        self
    }

    fn interface_mut(&mut self) -> &mut Self::Interface {
        self
    }
}
