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

use common::chain::{GenBlock, Transaction};
use common::primitives::id::WithId;
use common::primitives::Id;

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub enum TxState {
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
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub struct WalletTx {
    /// The actual transaction
    tx: WithId<Transaction>,
    /// The state of this transaction
    state: TxState,
}

impl WalletTx {
    pub fn new(tx: Transaction, state: TxState) -> Self {
        WalletTx {
            tx: WithId::new(tx),
            state,
        }
    }

    pub fn get_tx(&self) -> &Transaction {
        &self.tx
    }
}
