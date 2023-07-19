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

use common::{
    chain::{block::timestamp::BlockTimestamp, GenBlock, SignedTransaction},
    primitives::{Amount, Id},
};
use serialization::Encode;

use crate::pool::fee::Fee;

#[derive(thiserror::Error, Debug, Clone)]
pub enum TxAccumulatorError {
    #[error("Fee overflow: {0:?} + {1:?} failed")]
    FeeAccumulationError(Fee, Fee),
}

pub trait TransactionAccumulator: Send {
    /// Add a transaction to the accumulator and its fee
    /// This method should not mutate self unless it's successful
    /// Meaning: If this call returns an error, the callee should guarantee that &self never changed
    // TODO: Add a test for this property, at least for DefaultTxAccumulator
    fn add_tx(&mut self, tx: SignedTransaction, tx_fee: Fee) -> Result<(), TxAccumulatorError>;
    fn done(&self) -> bool;
    fn transactions(&self) -> &Vec<SignedTransaction>;
    fn total_fees(&self) -> Fee;

    /// The tip that the accumulator expects. This is used so that the mempool remains in sync with block production,
    /// and to prevent having transactions pulled for a different state than the one the block producer is working on.
    fn expected_tip(&self) -> Id<GenBlock>;

    /// Candidate block timestamp to verify time locks against
    fn block_timestamp(&self) -> BlockTimestamp;
}

pub struct DefaultTxAccumulator {
    txs: Vec<SignedTransaction>,
    total_size: usize,
    target_size: usize,
    done: bool,
    total_fees: Fee,
    expected_tip: Id<GenBlock>,
    timestamp: BlockTimestamp,
}

impl DefaultTxAccumulator {
    pub fn new(target_size: usize, expected_tip: Id<GenBlock>, timestamp: BlockTimestamp) -> Self {
        Self {
            txs: Vec::new(),
            total_size: 0,
            target_size,
            done: false,
            total_fees: Amount::ZERO.into(),
            expected_tip,
            timestamp,
        }
    }
}

impl TransactionAccumulator for DefaultTxAccumulator {
    fn add_tx(&mut self, tx: SignedTransaction, tx_fee: Fee) -> Result<(), TxAccumulatorError> {
        if self.total_size + tx.encoded_size() <= self.target_size {
            self.total_size += tx.encoded_size();
            self.total_fees = (self.total_fees + tx_fee).ok_or(
                TxAccumulatorError::FeeAccumulationError(self.total_fees, tx_fee),
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

    fn transactions(&self) -> &Vec<SignedTransaction> {
        &self.txs
    }

    fn total_fees(&self) -> Fee {
        self.total_fees
    }

    fn expected_tip(&self) -> Id<GenBlock> {
        self.expected_tip
    }

    fn block_timestamp(&self) -> BlockTimestamp {
        self.timestamp
    }
}
