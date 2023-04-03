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

use thiserror::Error;

use chainstate_types::pos_randomness::PoSRandomnessError;
use common::{
    chain::{block::timestamp::BlockTimestamp, Block, PoolId},
    primitives::{Compact, Id},
    UintConversionError,
};

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ConsensusPoSError {
    #[error("Property query error: `{0}`")]
    PropertyQueryError(#[from] chainstate_types::PropertyQueryError),
    #[error("Stake kernel hash failed to meet the target requirement")]
    StakeKernelHashTooHigh,
    #[error(
        "Stake block timestamp cannot be smaller than the kernel's (kernel: {0} < stake: {1})"
    )]
    TimestampViolation(BlockTimestamp, BlockTimestamp),
    #[error("Kernel inputs are empty")]
    NoKernel,
    #[error("Only one kernel allowed")]
    MultipleKernels,
    #[error("Bits to target conversion failed {0:?}")]
    BitsToTargetConversionFailed(Compact),
    #[error("Could not find the previous block index of block: {0}")]
    PrevBlockIndexNotFound(Id<Block>),
    #[error("Balance for pool {0} not found")]
    PoolBalanceNotFound(PoolId),
    #[error("Balance for pool {0} not found")]
    PoolDataNotFound(PoolId),
    #[error("PoS accounting error: `{0}`")]
    PoSAccountingError(#[from] pos_accounting::Error),
    #[error("PoS randomness error: `{0}`")]
    RandomnessError(#[from] PoSRandomnessError),
    #[error("Invalid target value: `{0:?}`")]
    InvalidTarget(Compact),
    #[error("Decoding bits of block failed: `{0:?}`")]
    DecodingBitsFailed(Compact),
    #[error("Failed to convert target type: `{0:?}`")]
    TargetConversionError(#[from] UintConversionError),
    #[error("Not enough timestamps to calculate block time average")]
    NotEnoughTimestampsToAverage,
    #[error("CRITICAL: Target block time must be > 0")]
    InvalidTargetBlockTime,
    #[error("CRITICAL: Block time must be monotonic")]
    InvariantBrokenNotMonotonicBlockTime,
}
