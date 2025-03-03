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

use serialization::{Decode, Encode};

use crate::{chain::AccountNonce, text_summary::TextSummary};

use super::{
    AccountCommand, AccountOutPoint, AccountSpending, OrderAccountCommand, OutPointSourceId,
    UtxoOutPoint,
};

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum TxInput {
    #[codec(index = 0)]
    Utxo(UtxoOutPoint),
    // TODO: after the fork AccountOutPoint can be replaced with (AccountNonce, AccountSpending)
    #[codec(index = 1)]
    Account(AccountOutPoint),
    #[codec(index = 2)]
    AccountCommand(AccountNonce, AccountCommand),
    #[codec(index = 3)]
    OrderAccountCommand(OrderAccountCommand),
}

impl TxInput {
    pub fn from_utxo(outpoint_source_id: OutPointSourceId, output_index: u32) -> Self {
        TxInput::Utxo(UtxoOutPoint::new(outpoint_source_id, output_index))
    }

    pub fn from_account(nonce: AccountNonce, account: AccountSpending) -> Self {
        TxInput::Account(AccountOutPoint::new(nonce, account))
    }

    pub fn from_command(nonce: AccountNonce, op: AccountCommand) -> Self {
        TxInput::AccountCommand(nonce, op)
    }

    pub fn utxo_outpoint(&self) -> Option<&UtxoOutPoint> {
        match self {
            TxInput::Utxo(outpoint) => Some(outpoint),
            TxInput::Account(_)
            | TxInput::AccountCommand(_, _)
            | TxInput::OrderAccountCommand(_) => None,
        }
    }
}

impl From<UtxoOutPoint> for TxInput {
    fn from(outpoint: UtxoOutPoint) -> TxInput {
        TxInput::Utxo(outpoint)
    }
}

impl TextSummary for TxInput {
    fn text_summary(&self, _chain_config: &crate::chain::ChainConfig) -> String {
        match self {
            TxInput::Utxo(utxo) => {
                let source_id = utxo.source_id();
                let n = utxo.output_index();
                match source_id {
                    OutPointSourceId::Transaction(ref id) => {
                        let id_str = format!("{:?}", id.to_hash());
                        format!("Transaction({id_str}, {n})")
                    }
                    OutPointSourceId::BlockReward(id) => {
                        let id_str = format!("{:?}", id.to_hash()).to_string();
                        format!("BlockReward({id_str}, {n})")
                    }
                }
            }
            TxInput::Account(acc_out) => format!("{acc_out:?}"),
            TxInput::AccountCommand(nonce, cmd) => format!("AccountCommand({nonce}, {cmd:?})"),
            TxInput::OrderAccountCommand(cmd) => format!("OrderAccountCommand({cmd:?})"),
        }
    }
}
