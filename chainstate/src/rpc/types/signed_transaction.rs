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
    address::AddressError,
    chain::{ChainConfig, SignedTransaction, Transaction},
    primitives::{Id, Idable},
};
use serialization::hex_encoded::HexEncoded;

use super::output::RpcTxOutput;

#[derive(Debug, Clone, serde::Serialize)]
pub struct RpcSignedTransaction {
    id: Id<Transaction>,
    input_count: u32,
    output_count: u32,
    outputs: Vec<RpcTxOutput>,
    tx_hex: HexEncoded<SignedTransaction>,
}

impl RpcSignedTransaction {
    pub fn new(chain_config: &ChainConfig, tx: SignedTransaction) -> Result<Self, AddressError> {
        let rpc_tx_outputs = tx
            .transaction()
            .outputs()
            .iter()
            .map(|output| RpcTxOutput::new(chain_config, output))
            .collect::<Result<Vec<_>, _>>()?;

        let rpc_tx = Self {
            id: tx.transaction().get_id(),
            input_count: tx.transaction().inputs().len() as u32,
            output_count: tx.transaction().outputs().len() as u32,
            outputs: rpc_tx_outputs,
            tx_hex: tx.into(),
        };

        Ok(rpc_tx)
    }
}
