// Copyright (c) 2023 RBB S.r.l
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
    chain::{ChainConfig, SignedTransaction, Transaction},
    primitives::{Id, Idable},
    TokenDecimalsProvider,
};
use serialization::hex_encoded::HexEncoded;

use super::{input::RpcTxInput, output::RpcTxOutput, RpcTypeError};

#[derive(Debug, Clone, serde::Serialize, rpc_description::HasValueHint)]
pub struct RpcSignedTransaction {
    id: Id<Transaction>,
    flags: u128,
    input_count: u32,
    inputs: Vec<RpcTxInput>,
    output_count: u32,
    outputs: Vec<RpcTxOutput>,
    tx_hex: HexEncoded<SignedTransaction>,
}

impl RpcSignedTransaction {
    pub fn new(
        chain_config: &ChainConfig,
        token_decimals_provider: &impl TokenDecimalsProvider,
        tx: SignedTransaction,
    ) -> Result<Self, RpcTypeError> {
        let rpc_tx_inputs = tx
            .transaction()
            .inputs()
            .iter()
            .map(|input| RpcTxInput::new(chain_config, input))
            .collect::<Result<Vec<_>, _>>()?;

        let rpc_tx_outputs = tx
            .transaction()
            .outputs()
            .iter()
            .map(|output| RpcTxOutput::new(chain_config, token_decimals_provider, output.clone()))
            .collect::<Result<Vec<_>, _>>()?;

        let rpc_tx = Self {
            id: tx.transaction().get_id(),
            flags: tx.transaction().flags(),
            input_count: tx.transaction().inputs().len() as u32,
            inputs: rpc_tx_inputs,
            output_count: tx.transaction().outputs().len() as u32,
            outputs: rpc_tx_outputs,
            tx_hex: tx.into(),
        };

        Ok(rpc_tx)
    }

    pub fn into_signed_transaction(self) -> SignedTransaction {
        self.tx_hex.take()
    }
}
