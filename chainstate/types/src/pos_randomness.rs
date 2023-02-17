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
    chain::{
        block::{consensus_data::PoSData, BlockHeader},
        Block, ChainConfig, OutputPurpose, TxOutput,
    },
    primitives::{
        id::{hash_encoded_to, DefaultHashAlgoStream},
        BlockHeight, Id, Idable, H256,
    },
};
use serialization::{Decode, Encode};
use thiserror::Error;

use crate::vrf_tools::{verify_vrf_and_get_vrf_output, ProofOfStakeVRFError};

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum PoSRandomnessError {
    #[error("Attempted to use a non-locked stake as stake kernel in block {0}")]
    InvalidOutputPurposeInStakeKernel(Id<Block>),
    #[error("Failed to verify VRF data with error: {0}")]
    VRFDataVerificationFailed(ProofOfStakeVRFError),
}

#[derive(Debug, Encode, Decode, Clone)]
pub struct PoSRandomness {
    value: H256,
}

impl PoSRandomness {
    pub fn new(value: H256) -> Self {
        Self { value }
    }

    pub fn from_block(
        chain_config: &ChainConfig,
        block_height: &BlockHeight,
        header: &BlockHeader,
        previous_randomness: Option<&PoSRandomness>,
        kernel_output: &TxOutput,
        pos_data: &PoSData,
    ) -> Result<Self, PoSRandomnessError> {
        use crypto::hash::StreamHasher;

        let prev_randomness =
            previous_randomness.cloned().unwrap_or_else(|| Self::at_genesis(chain_config));
        let prev_randomness_val = prev_randomness.value();

        let epoch_index = chain_config.epoch_index_from_height(block_height);

        let pool_data = match kernel_output.purpose() {
            OutputPurpose::Transfer(_)
            | OutputPurpose::LockThenTransfer(_, _)
            | OutputPurpose::Burn => {
                // only pool outputs can be staked
                return Err(PoSRandomnessError::InvalidOutputPurposeInStakeKernel(
                    header.get_id(),
                ));
            }
            OutputPurpose::StakePool(d) => d.as_ref(),
        };

        let hash_pos: H256 = verify_vrf_and_get_vrf_output(
            epoch_index,
            &prev_randomness_val,
            pos_data.vrf_data(),
            pool_data.vrf_public_key(),
            header,
        )
        .map_err(PoSRandomnessError::VRFDataVerificationFailed)?;

        let mut hasher = DefaultHashAlgoStream::new();
        hash_encoded_to(&prev_randomness_val, &mut hasher);
        hash_encoded_to(&hash_pos, &mut hasher);
        let hash: H256 = hasher.finalize().into();

        Ok(Self::new(hash))
    }

    /// randomness at genesis
    fn at_genesis(chain_config: &ChainConfig) -> Self {
        Self {
            value: chain_config.initial_randomness(),
        }
    }

    pub fn value(&self) -> H256 {
        self.value
    }
}
