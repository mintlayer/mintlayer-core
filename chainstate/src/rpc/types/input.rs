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
    chain::{ChainConfig, GenBlock, OutPointSourceId, Transaction, TxInput},
    primitives::Id,
};

use super::account::{RpcAccountCommand, RpcAccountSpending};

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type")]
pub enum RpcTxInput {
    Utxo {
        source_id: RpcOutPointSourceId,
        index: u32,
    },
    Account {
        nonce: u64,
        account: RpcAccountSpending,
    },
    AccountCommand {
        nonce: u64,
        command: RpcAccountCommand,
    },
}

impl RpcTxInput {
    pub fn new(chain_config: &ChainConfig, input: &TxInput) -> Result<Self, AddressError> {
        let result = match input {
            TxInput::Utxo(outpoint) => match outpoint.source_id() {
                OutPointSourceId::Transaction(id) => RpcTxInput::Utxo {
                    source_id: RpcOutPointSourceId::Transaction { tx_id: id },
                    index: outpoint.output_index(),
                },
                OutPointSourceId::BlockReward(id) => RpcTxInput::Utxo {
                    source_id: RpcOutPointSourceId::BlockReward { block_id: id },
                    index: outpoint.output_index(),
                },
            },
            TxInput::Account(outpoint) => RpcTxInput::Account {
                nonce: outpoint.nonce().value(),
                account: RpcAccountSpending::new(chain_config, outpoint.account().clone())?,
            },
            TxInput::AccountCommand(nonce, command) => RpcTxInput::AccountCommand {
                nonce: nonce.value(),
                command: RpcAccountCommand::new(chain_config, command)?,
            },
        };
        Ok(result)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type")]
pub enum RpcOutPointSourceId {
    Transaction { tx_id: Id<Transaction> },
    BlockReward { block_id: Id<GenBlock> },
}
