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
    chain::{block::timestamp::BlockTimestamp, config::EpochIndex, Block, ChainConfig},
    primitives::{Id, H256},
};
use crypto::vrf::{VRFPublicKey, VRFReturn};
use serialization::{Decode, Encode};
use thiserror::Error;

use crate::vrf_tools::{verify_vrf_and_get_vrf_output, ProofOfStakeVRFError};

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum PoSRandomnessError {
    #[error("Attempted to use a non-locked stake as stake kernel in block {0}")]
    InvalidOutputTypeInStakeKernel(Id<Block>),
    #[error("Failed to verify VRF data with error: {0}")]
    VRFDataVerificationFailed(#[from] ProofOfStakeVRFError),
}

#[derive(Debug, Encode, Decode, Clone, Copy)]
pub struct PoSRandomness {
    value: H256,
}

impl PoSRandomness {
    pub fn new(value: H256) -> Self {
        Self { value }
    }

    pub fn from_block(
        epoch_index: EpochIndex,
        block_timestamp: BlockTimestamp,
        seal_randomness: &PoSRandomness,
        vrf_data: &VRFReturn,
        vrf_pub_key: &VRFPublicKey,
    ) -> Result<Self, PoSRandomnessError> {
        let hash: H256 = verify_vrf_and_get_vrf_output(
            epoch_index,
            &seal_randomness.value(),
            vrf_data,
            vrf_pub_key,
            block_timestamp,
        )?;

        Ok(Self::new(hash))
    }

    /// randomness at genesis
    pub fn at_genesis(chain_config: &ChainConfig) -> Self {
        Self {
            value: chain_config.initial_randomness(),
        }
    }

    pub fn value(&self) -> H256 {
        self.value
    }
}
