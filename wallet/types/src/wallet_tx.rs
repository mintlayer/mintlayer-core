// Copyright (c) 2023 RBB S.r.l
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

use serialization::{Decode, Encode};
use std::cmp::Ordering;

use common::chain::{GenBlock, Transaction};
use common::primitives::{Id, Idable};

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub enum TxState {
    // TxStateConfirmed, TxStateInMempool, TxStateConflicted, TxStateInactive, TxStateUnrecognized
    /// Confirmed transaction in a block
    #[codec(index = 0)]
    Confirmed(Id<GenBlock>),
    /// Unconfirmed transaction in the mempool
    #[codec(index = 1)]
    InMempool,
    /// Conflicted transaction with a confirmed block
    #[codec(index = 2)]
    Conflicted(Id<GenBlock>),
    /// Transaction that is not confirmed or conflicted and is not in the mempool.
    #[codec(index = 3)]
    Inactive,
    /// Unrecognized state
    #[codec(index = 4)]
    Unrecognized,
}

#[derive(Debug, Eq, Clone, Decode, Encode)]
pub struct WalletTx {
    /// The actual transaction
    tx: Transaction,
    /// The state of this transaction
    state: TxState,
    /// The order of the transaction
    order: i64,
}

impl PartialEq for WalletTx {
    fn eq(&self, other: &Self) -> bool {
        self.tx.get_id().eq(&other.tx.get_id())
    }
}

impl Ord for WalletTx {
    fn cmp(&self, other: &Self) -> Ordering {
        let ordering = self.order.cmp(&other.order);
        match ordering {
            // If the order is the same compare the tx ids
            Ordering::Equal => self.tx.get_id().cmp(&other.tx.get_id()),
            Ordering::Greater | Ordering::Less => ordering,
        }
    }
}

impl PartialOrd<Self> for WalletTx {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl WalletTx {
    pub fn new(tx: Transaction, state: TxState) -> Self {
        WalletTx {
            tx,
            state,
            order: -1,
        }
    }

    pub fn get_tx(&self) -> &Transaction {
        &self.tx
    }

    pub fn set_order(&mut self, order: i64) {
        debug_assert!(order >= -1);
        self.order = order;
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet_tx::TxState::InMempool;
    use crate::wallet_tx::WalletTx;
    use common::chain::Transaction;

    #[test]
    fn transaction_ordering() {
        let mut tx1 = WalletTx::new(Transaction::new(1, vec![], vec![], 0).unwrap(), InMempool);
        tx1.set_order(1);
        let mut tx2 = WalletTx::new(Transaction::new(2, vec![], vec![], 0).unwrap(), InMempool);
        tx2.set_order(2);
        let mut tx3 = WalletTx::new(Transaction::new(3, vec![], vec![], 0).unwrap(), InMempool);
        tx3.set_order(3);

        // After sorting the order should be the same
        let mut sorted_txs = vec![tx1.clone(), tx2.clone(), tx3.clone()];
        sorted_txs.sort();
        assert_eq!(sorted_txs, vec![tx1.clone(), tx2.clone(), tx3.clone()]);

        // Change the order of the transactions
        sorted_txs[0].order = 10;
        sorted_txs[2].order = 0;
        sorted_txs.sort();
        assert_eq!(sorted_txs, vec![tx3, tx2, tx1]);
    }
}
