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

use crate::chain::signature::inputsig::InputWitness;
use crate::chain::{ChainConfig, PoolId};
use crate::{chain::TxInput, primitives::BlockDistance, primitives::Compact, Uint256};
use crypto::vrf::VRFReturn;

use serialization::{Decode, Encode};

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum ConsensusData {
    #[codec(index = 0)]
    None,
    #[codec(index = 1)]
    PoW(PoWData),
    #[codec(index = 2)]
    PoS(PoSData),
}

impl ConsensusData {
    pub fn get_block_proof(&self) -> Option<Uint256> {
        match self {
            ConsensusData::None => Some(1u64.into()),
            ConsensusData::PoW(ref pow_data) => pow_data.get_block_proof(),
            ConsensusData::PoS(_) => Some(1u64.into()),
        }
    }

    pub fn reward_maturity_distance(&self, chain_config: &ChainConfig) -> BlockDistance {
        match self {
            ConsensusData::None => chain_config.empty_consensus_reward_maturity_distance(),
            ConsensusData::PoW(_) => {
                chain_config.get_proof_of_work_config().reward_maturity_distance()
            }
            ConsensusData::PoS(_) => BlockDistance::new(2000),
        }
    }
}

/// Data required to validate a block according to the PoS consensus rules.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct PoSData {
    /// Inputs for block reward
    kernel_inputs: Vec<TxInput>,
    kernel_witness: Vec<InputWitness>,

    /// Id of the stake pool used for target calculations
    stake_pool_id: PoolId,

    /// VRF data used for calculating hash below the target.
    /// It represents random seed generated based on the randomness of the sealed epoch.
    vrf_data_from_sealed_epoch: VRFReturn,

    /// VRF data used for calculating randomness for the current block.
    /// It represents random seed generated based on the randomness of the previous block.
    vrf_data_from_prev_block: VRFReturn,

    target: Compact, // TODO: do we really need to store it?
}

impl PoSData {
    pub fn new(
        kernel_inputs: Vec<TxInput>,
        kernel_witness: Vec<InputWitness>,
        stake_pool_id: PoolId,
        vrf_data_from_sealed_epoch: VRFReturn,
        vrf_data_from_prev_block: VRFReturn,
        target: Compact,
    ) -> Self {
        Self {
            kernel_inputs,
            kernel_witness,
            stake_pool_id,
            vrf_data_from_sealed_epoch,
            vrf_data_from_prev_block,
            target,
        }
    }

    pub fn kernel_inputs(&self) -> &[TxInput] {
        &self.kernel_inputs
    }

    pub fn kernel_witness(&self) -> &[InputWitness] {
        &self.kernel_witness
    }

    pub fn stake_pool_id(&self) -> &PoolId {
        &self.stake_pool_id
    }

    pub fn target(&self) -> &Compact {
        &self.target
    }

    pub fn vrf_data_from_sealed_epoch(&self) -> &VRFReturn {
        &self.vrf_data_from_sealed_epoch
    }

    pub fn vrf_data_from_prev_block(&self) -> &VRFReturn {
        &self.vrf_data_from_prev_block
    }
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq, Encode, Decode)]
pub struct PoWData {
    bits: Compact,
    nonce: u128,
}

impl PoWData {
    pub fn new(bits: Compact, nonce: u128) -> Self {
        PoWData { bits, nonce }
    }
    pub fn bits(&self) -> Compact {
        self.bits
    }

    pub fn nonce(&self) -> u128 {
        self.nonce
    }

    pub fn update_nonce(&mut self, nonce: u128) {
        self.nonce = nonce;
    }

    pub fn get_block_proof(&self) -> Option<Uint256> {
        // 2**256 / (target + 1) == ~target / (target+1) + 1    (eqn shamelessly stolen from bitcoind)
        let target: Uint256 = self.bits.try_into().ok()?;
        let mut ret = !target;
        let mut ret1 = target;
        ret1.increment();
        ret = ret / ret1;
        ret.increment();
        Some(ret)
    }
}
