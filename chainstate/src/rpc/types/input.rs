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

use common::{
    address::AddressError,
    chain::{ChainConfig, TxInput, UtxoOutPoint},
};

use super::account::{RpcAccountCommand, RpcAccountOutPoint};

#[derive(Debug, Clone, serde::Serialize)]
pub enum RpcTxInput {
    Utxo(UtxoOutPoint),
    Account(RpcAccountOutPoint),
    AccountCommand(u64, RpcAccountCommand),
}

impl RpcTxInput {
    pub fn new(chain_config: &ChainConfig, input: &TxInput) -> Result<Self, AddressError> {
        let result = match input {
            TxInput::Utxo(outpoint) => RpcTxInput::Utxo(outpoint.clone()),
            TxInput::Account(outpoint) => {
                RpcTxInput::Account(RpcAccountOutPoint::new(chain_config, outpoint.clone())?)
            }
            TxInput::AccountCommand(nonce, command) => {
                let command = RpcAccountCommand::new(chain_config, command)?;
                RpcTxInput::AccountCommand(nonce.value(), command)
            }
        };
        Ok(result)
    }
}
