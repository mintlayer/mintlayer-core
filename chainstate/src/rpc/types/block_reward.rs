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
    chain::{block::BlockReward, ChainConfig},
};

use super::output::RpcTxOutput;

#[derive(Debug, Clone, serde::Serialize)]
pub struct RpcBlockReward {
    output_count: u32,
    outputs: Vec<RpcTxOutput>,
}

impl RpcBlockReward {
    pub fn new(chain_config: &ChainConfig, reward: &BlockReward) -> Result<Self, AddressError> {
        let rpc_outputs = reward
            .outputs()
            .iter()
            .map(|output| RpcTxOutput::new(chain_config, output.clone()))
            .collect::<Result<Vec<_>, _>>()?;

        let rpc_tx = Self {
            output_count: reward.outputs().len() as u32,
            outputs: rpc_outputs,
        };

        Ok(rpc_tx)
    }
}
