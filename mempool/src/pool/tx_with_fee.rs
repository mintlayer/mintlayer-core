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

use common::chain::SignedTransaction;

use super::fee::Fee;

pub struct TxWithFee {
    tx: SignedTransaction,
    fee: Fee,
}

impl TxWithFee {
    pub fn new_with_fee(tx: SignedTransaction, fee: Fee) -> Self {
        Self { tx, fee }
    }

    pub fn tx(&self) -> &SignedTransaction {
        &self.tx
    }

    pub fn fee(&self) -> Fee {
        self.fee
    }

    pub fn into_tx_and_fee(self) -> (SignedTransaction, Fee) {
        let Self { tx, fee } = self;
        (tx, fee)
    }
}
