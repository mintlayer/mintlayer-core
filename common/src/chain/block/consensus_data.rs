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

use crate::chain::ChainConfig;
use crate::primitives::Compact;
use crate::Uint256;
use crate::{chain::TxInput, primitives::BlockDistance};

use serialization::{Decode, Encode};

#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq, Encode, Decode)]
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
            ConsensusData::None => BlockDistance::new(0),
            ConsensusData::PoW(_) => {
                chain_config.get_proof_of_work_config().reward_maturity_distance()
            }
            ConsensusData::PoS(_) => BlockDistance::new(2000),
        }
    }
}

/// Fake PoS just to test spending block rewards; will be removed at some point in the future
#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq, Encode, Decode)]
pub struct PoSData {
    kernel_inputs: Vec<TxInput>,
    bits: Compact,
}

impl PoSData {
    pub fn new(kernel_inputs: Vec<TxInput>, bits: Compact) -> Self {
        Self {
            kernel_inputs,
            bits,
        }
    }

    pub fn kernel_inputs(&self) -> &Vec<TxInput> {
        &self.kernel_inputs
    }

    pub fn bits(&self) -> &Compact {
        &self.bits
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
