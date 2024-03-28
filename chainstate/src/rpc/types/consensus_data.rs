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

use std::str::FromStr;

use common::{
    address::RpcAddress,
    chain::{block::ConsensusData, ChainConfig, PoolId},
};
use rpc::types::RpcHexString;

use super::{block::RpcTypeSerializationError, input::RpcTxInput};

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", content = "content")]
pub enum RpcConsensusData {
    None,
    PoW,
    PoS { pos_data: RpcPoSData },
}

impl RpcConsensusData {
    pub fn new(
        chain_config: &ChainConfig,
        consensus_data: &ConsensusData,
    ) -> Result<Self, RpcTypeSerializationError> {
        let rpc_consensus_data = match consensus_data {
            ConsensusData::None => RpcConsensusData::None,
            ConsensusData::PoW(_) => RpcConsensusData::PoW,
            ConsensusData::PoS(pos_data) => {
                let rpc_inputs = pos_data
                    .kernel_inputs()
                    .iter()
                    .map(|input| RpcTxInput::new(chain_config, input))
                    .collect::<Result<Vec<_>, _>>()?;

                let compact_target =
                    RpcHexString::from_str(format!("{:x}", pos_data.compact_target().0).as_str())?;

                let target = RpcHexString::from_str(
                    format!(
                        "{:x}",
                        TryInto::<common::Uint256>::try_into(pos_data.compact_target())
                            .expect("valid target")
                    )
                    .as_str(),
                )?;

                RpcConsensusData::PoS {
                    pos_data: RpcPoSData {
                        kernel_input_count: rpc_inputs.len() as u32,
                        kernel_inputs: rpc_inputs,
                        stake_pool_id: RpcAddress::new(chain_config, *pos_data.stake_pool_id())?,
                        compact_target,
                        target,
                    },
                }
            }
        };

        Ok(rpc_consensus_data)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RpcPoSData {
    kernel_input_count: u32,
    kernel_inputs: Vec<RpcTxInput>,
    stake_pool_id: RpcAddress<PoolId>,
    compact_target: RpcHexString,
    target: RpcHexString,
}
