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
    M: GetMemoryUsage,
{
    fn spends_unconfirmed(&self, mempool: &Mempool<M>) -> bool;
}

impl<M: GetMemoryUsage> SpendsUnconfirmed<M> for TxInput {
    fn spends_unconfirmed(&self, mempool: &Mempool<M>) -> bool {
        // TODO: if TxInput spends from an account there is no way to know tx_id
        match self {
            TxInput::Utxo(outpoint) => outpoint
                .tx_id()
                .get_tx_id()
                .map_or(false, |tx_id| mempool.contains_transaction(tx_id)),
            TxInput::Account(_, _) => false,
        }
    }
}
