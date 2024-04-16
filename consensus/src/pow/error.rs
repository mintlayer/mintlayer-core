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

use thiserror::Error;

use chainstate_types::PropertyQueryError;
use common::{
    chain::block::Block,
    primitives::{BlockHeight, Compact, Id},
};

/// A proof of work consensus error.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ConsensusPoWError {
    #[error("Chainstate error: `{0}`")]
    ChainstateError(#[from] crate::ChainstateError),
    #[error("Invalid Proof of Work for block {0}")]
    InvalidPoW(Id<Block>),
    #[error("Error while loading previous block with id {0} with error {1}")]
    PrevBlockLoadError(Id<Block>, PropertyQueryError),
    #[error("Previous block {0} not found in database")]
    PrevBlockNotFound(Id<Block>),
    #[error("Error while loading ancestor of block {0} at height {1} with error {2}")]
    AncestorAtHeightNotFound(Id<Block>, BlockHeight, PropertyQueryError),
    #[error("No PoW data for block for block")]
    NoPowDataInPreviousBlock,
    #[error("Decoding bits of block failed: `{0:?}`")]
    DecodingBitsFailed(Compact),
    #[error("Previous bits conversion failed: `{0:?}`")]
    PreviousBitsDecodingFailed(Compact),
    #[error("Invalid target value: `{0:?}`, should be `{1:?}`")]
    InvalidTargetBits(Compact, Compact),
    #[error("PoS input data was provided for PoW block generation")]
    PoSInputDataProvided,
    #[error("No input data was provided for PoW block generation")]
    NoInputDataProvided,
}
