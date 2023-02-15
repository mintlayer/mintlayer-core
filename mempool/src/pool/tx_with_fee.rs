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

use super::{fee::Fee, try_get_fee::TryGetFee, Mempool};
use crate::{error::TxValidationError, get_memory_usage::GetMemoryUsage};

pub struct TxWithFee {
    tx: SignedTransaction,
    fee: Fee,
}

impl TxWithFee {
    pub async fn new<M: GetMemoryUsage + Sync + Send>(
        mempool: &Mempool<M>,
        tx: SignedTransaction,
    ) -> Result<Self, TxValidationError> {
        let fee = mempool.try_get_fee(&tx).await?;
        Ok(Self { tx, fee })
    }

    pub fn tx(&self) -> &SignedTransaction {
        &self.tx
    }

    pub fn fee(&self) -> Fee {
        self.fee
    }
}
