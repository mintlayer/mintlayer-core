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
    chain::{ChainConfig, GenBlock, OutPointSourceId, Transaction, TxInput, UtxoOutPoint},
    primitives::Id,
};

use super::account::{RpcAccountCommand, RpcAccountSpending, RpcOrderAccountCommand};

#[derive(Debug, Clone, serde::Serialize, rpc_description::HasValueHint)]
#[serde(tag = "type", content = "content")]
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
    OrderAccountCommand {
        command: RpcOrderAccountCommand,
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
            TxInput::OrderAccountCommand(cmd) => RpcTxInput::OrderAccountCommand {
                command: RpcOrderAccountCommand::new(chain_config, cmd)?,
            },
        };
        Ok(result)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, rpc_description::HasValueHint)]
#[serde(tag = "type", content = "content")]
pub enum RpcOutPointSourceId {
    Transaction { tx_id: Id<Transaction> },
    BlockReward { block_id: Id<GenBlock> },
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, rpc_description::HasValueHint)]
pub struct RpcUtxoOutpoint {
    source_id: RpcOutPointSourceId,
    index: u32,
}

impl RpcUtxoOutpoint {
    pub fn new(outpoint: UtxoOutPoint) -> Self {
        let source_id = match outpoint.source_id() {
            OutPointSourceId::Transaction(tx_id) => RpcOutPointSourceId::Transaction { tx_id },
            OutPointSourceId::BlockReward(block_id) => {
                RpcOutPointSourceId::BlockReward { block_id }
            }
        };
        Self {
            source_id,
            index: outpoint.output_index(),
        }
    }

    pub fn into_outpoint(self) -> UtxoOutPoint {
        let source_id = match self.source_id {
            RpcOutPointSourceId::Transaction { tx_id } => tx_id.into(),
            RpcOutPointSourceId::BlockReward { block_id } => block_id.into(),
        };
        UtxoOutPoint::new(source_id, self.index)
    }
}

impl From<UtxoOutPoint> for RpcUtxoOutpoint {
    fn from(outpoint: UtxoOutPoint) -> Self {
        Self::new(outpoint)
    }
}
