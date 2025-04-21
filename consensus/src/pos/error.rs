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

use crate::ChainstateError;

use super::{block_sig::BlockSignatureError, EffectivePoolBalanceError};

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ConsensusPoSError {
    #[error("Blockchain storage error: {0}")]
    StorageError(#[from] chainstate_types::storage_result::Error),
    #[error("Property query error: `{0}`")]
    PropertyQueryError(#[from] chainstate_types::PropertyQueryError),
    #[error("Chainstate error: `{0}`")]
    ChainstateError(#[from] ChainstateError),

    #[error("Stake kernel hash failed to meet the target requirement")]
    StakeKernelHashTooHigh,
    #[error("Epoch data not provided")]
    NoEpochData,
    #[error(
        "Stake block timestamp cannot be smaller than the kernel's (kernel: {0} < stake: {1})"
    )]
    TimestampViolation(BlockTimestamp, BlockTimestamp),
    #[error("Kernel inputs are empty")]
    NoKernel,
    #[error("Kernel utxo is missing")]
    MissingKernelUtxo,
    #[error("Kernel outpoint must be a utxo")]
    KernelOutpointMustBeUtxo,
    #[error("Only one kernel allowed")]
    MultipleKernels,
    #[error("Bits to target conversion failed {0:?}")]
    BitsToTargetConversionFailed(Compact),
    #[error("Could not find the previous block index of block: {0}")]
    PrevBlockIndexNotFound(Id<Block>),
    #[error("Balance for pool {0} not found")]
    PoolBalanceNotFound(PoolId),
    #[error("Data for pool {0} not found")]
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
    #[error("Overflowed when calculating the maximum block timestamp")]
    TimestampOverflow,
    #[error("CRITICAL: Block time must be monotonic")]
    InvariantBrokenNotMonotonicBlockTime,
    #[error("Timespan cannot be empty when calculating average block time")]
    EmptyTimespan,
    #[error("No input data was provided for PoS block generation")]
    NoInputDataProvided,
    #[error("PoW input data was provided for PoS block generation")]
    PoWInputDataProvided,
    #[error("Failed to read block {0}")]
    FailedReadingBlock(Id<Block>),
    #[error("Maximum block timestamp is before the previous block timestamp")]
    FutureTimestampInThePast,

    // TODO the following error should include the corresponding error from UtxosView
    //      https://github.com/mintlayer/mintlayer-core/issues/811
    #[error("Failed to fetch utxo")]
    FailedToFetchUtxo,
    #[error("Block signature error: `{0}`")]
    BlockSignatureError(#[from] BlockSignatureError),
    #[error("Failed to sign block header")]
    FailedToSignBlockHeader,
    #[error("Failed to sign kernel")]
    FailedToSignKernel,
    #[error("Proof of stake block time ordering error in block: `{0}`")]
    PoSBlockTimeStrictOrderInvalid(Id<Block>),
    #[error("Finite total supply is required")]
    FiniteTotalSupplyIsRequired,
    #[error("Unsupported PoS consensus version")]
    UnsupportedConsensusVersion,
    #[error("Error while calculating pool's effective balance: `{0}`")]
    EffectivePoolBalanceError(#[from] EffectivePoolBalanceError),
    #[error("Failed to calculate capped balance")]
    FailedToCalculateCappedBalance,
    #[error("Invalid kernel output type in block {0}")]
    InvalidOutputTypeInStakeKernel(Id<Block>),
}
