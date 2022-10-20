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

use common::{chain::signed_transaction::SignedTransaction, primitives::Amount};
use serialization::Encode;

#[derive(thiserror::Error, Debug, Clone)]
pub enum TxAccumulatorError {
    #[error("Fee overflow: {0:?} + {1:?} failed")]
    FeeAccumulationError(Amount, Amount),
}

pub trait TransactionAccumulator: Send {
    /// Add a transaction to the accumulator and its fee
    /// This method should not mutate self unless it's successful
    /// Meaning: If this call returns an error, the callee should guarantee that &self never changed
    fn add_tx(&mut self, tx: SignedTransaction, tx_fee: Amount) -> Result<(), TxAccumulatorError>;
    fn done(&self) -> bool;
    fn txs(&self) -> &Vec<SignedTransaction>;
    fn total_fee(&self) -> Amount;
}

pub struct DefaultTxAccumulator {
    txs: Vec<SignedTransaction>,
    total_size: usize,
    target_size: usize,
    done: bool,
    total_fee: Amount,
}

impl DefaultTxAccumulator {
    pub fn new(target_size: usize) -> Self {
        Self {
            txs: Vec::new(),
            total_size: 0,
            target_size,
            done: false,
            total_fee: Amount::ZERO,
        }
    }
}

impl TransactionAccumulator for DefaultTxAccumulator {
    fn add_tx(&mut self, tx: SignedTransaction, tx_fee: Amount) -> Result<(), TxAccumulatorError> {
        if self.total_size + tx.encoded_size() <= self.target_size {
            self.total_size += tx.encoded_size();
            self.total_fee = (self.total_fee + tx_fee).ok_or(
                TxAccumulatorError::FeeAccumulationError(self.total_fee, tx_fee),
            )?;
            self.txs.push(tx);
        } else {
            self.done = true
        };
        Ok(())
    }

    fn done(&self) -> bool {
        self.done
    }

    fn txs(&self) -> &Vec<SignedTransaction> {
        &self.txs
    }

    fn total_fee(&self) -> Amount {
        self.total_fee
    }
}
