// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use common::chain::{OutPointSourceId, Transaction, TxMainChainIndex, TxMainChainPosition};

use crate::detail::PropertyQueryError;

pub trait TransactionIndexHandle {
    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<TxMainChainIndex>, PropertyQueryError>;

    fn get_mainchain_tx_by_position(
        &self,
        tx_index: &TxMainChainPosition,
    ) -> Result<Option<Transaction>, PropertyQueryError>;
}
