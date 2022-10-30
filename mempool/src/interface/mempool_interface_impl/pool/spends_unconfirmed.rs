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

use common::chain::TxInput;

use crate::get_memory_usage::GetMemoryUsage;

use super::Mempool;

pub trait SpendsUnconfirmed<M>
where
    M: GetMemoryUsage + Send + std::marker::Sync,
{
    fn spends_unconfirmed(&self, mempool: &Mempool<M>) -> bool;
}

impl<M> SpendsUnconfirmed<M> for TxInput
where
    M: GetMemoryUsage + Send + std::marker::Sync,
{
    fn spends_unconfirmed(&self, mempool: &Mempool<M>) -> bool {
        let outpoint_id = self.outpoint().tx_id().get_tx_id().cloned();
        outpoint_id.is_some()
            && mempool
                .contains_transaction(self.outpoint().tx_id().get_tx_id().expect("Not coinbase"))
    }
}
