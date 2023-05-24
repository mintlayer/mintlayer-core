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

use common::chain::{OutPoint, OutPointSourceId, Transaction};
use common::primitives::id::WithId;
use common::primitives::{BlockHeight, Idable};

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub enum TxState {
    /// Confirmed transaction in a block
    #[codec(index = 0)]
    Confirmed(BlockHeight),
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub struct WalletTx {
    tx: WithId<Transaction>,

    state: TxState,
}

impl WalletTx {
    pub fn new(tx: WithId<Transaction>, state: TxState) -> Self {
        WalletTx { tx, state }
    }

    pub fn tx(&self) -> &WithId<Transaction> {
        &self.tx
    }

    pub fn state(&self) -> &TxState {
        &self.state
    }

    pub fn outpoints(&self) -> impl Iterator<Item = OutPoint> + '_ {
        self.tx.outputs().iter().enumerate().map(|(index, _output)| {
            OutPoint::new(
                OutPointSourceId::Transaction(self.tx.get_id()),
                index as u32,
            )
        })
    }
}
