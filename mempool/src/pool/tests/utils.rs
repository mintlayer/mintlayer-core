// Copyright (c) 2024 RBB S.r.l
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

use chainstate::chainstate_interface::ChainstateInterface;
use common::{
    chain::{SignedTransaction, Transaction},
    primitives::Id,
};
use mempool_types::{tx_origin::TxOrigin, TxOptions, TxStatus};

pub use crate::pool::tx_pool::tests::utils::*;
pub use rstest::rstest;

use super::{Error, MemoryUsageEstimator, Mempool, TxEntry};

pub fn setup_with_chainstate(
    chainstate: Box<dyn ChainstateInterface>,
) -> Mempool<StoreMemoryUsageEstimator> {
    let chain_config = std::sync::Arc::clone(chainstate.get_chain_config());
    let mempool_config = create_mempool_config();
    let chainstate_handle = start_chainstate(chainstate);
    Mempool::new(
        chain_config,
        mempool_config,
        chainstate_handle,
        Default::default(),
        StoreMemoryUsageEstimator,
    )
}

pub fn fetch_status<T>(mempool: &Mempool<T>, tx_id: &Id<Transaction>) -> Option<TxStatus> {
    let in_mempool = mempool.contains_transaction(tx_id);
    let in_orphan_pool = mempool.contains_orphan_transaction(tx_id);
    match (in_mempool, in_orphan_pool) {
        (false, false) => None,
        (false, true) => Some(TxStatus::InOrphanPool),
        (true, false) => Some(TxStatus::InMempool),
        (true, true) => panic!("Transaction {tx_id} both in mempool and orphan pool"),
    }
}

impl<M: MemoryUsageEstimator> Mempool<M> {
    pub fn add_transaction_with_origin(
        &mut self,
        tx: SignedTransaction,
        origin: TxOrigin,
    ) -> Result<TxStatus, Error> {
        let options = TxOptions::default_for(origin);
        let entry = TxEntry::new(tx, self.clock.get_time(), origin, options);
        self.add_transaction(entry)
    }

    pub fn add_transaction_test(&mut self, tx: SignedTransaction) -> Result<TxStatus, Error> {
        let entry = self.tx_pool().make_transaction_test(tx);
        let result = self.add_transaction(entry)?;
        self.process_queue();
        Ok(result)
    }

    pub fn process_queue(&mut self) {
        while self.has_work() {
            self.perform_work_unit();
        }
    }
}
