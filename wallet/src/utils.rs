// Copyright (c) 2024 RBB S.r.l
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

use common::chain::{TxInput, UtxoOutPoint};

use crate::{WalletError, WalletResult};

pub fn get_first_utxo_outpoint(inputs: &[TxInput]) -> WalletResult<&UtxoOutPoint> {
    inputs
        .first()
        .ok_or(WalletError::NoUtxos)?
        .utxo_outpoint()
        .ok_or(WalletError::NotUtxoInput)
}
