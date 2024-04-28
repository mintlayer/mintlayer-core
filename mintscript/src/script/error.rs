// Copyright (c) 2024 RBB S.r.l
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

use common::chain::{DelegationId, PoolId};

use super::MintScript;

// TODO(PR): more info in errors
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid combination {0:?} with {1:?}")]
    InvalidCombination(MintScript, MintScript),
    #[error("Timelock evaluation error")]
    TimelockEvaluationError,
    #[error("Timelock not satisfied")]
    TimelockNotSatisfied,
    #[error("Block height arithmetic error")]
    BlockHeightArithmeticError,
    #[error("Block timestamp arithmetic error")]
    BlockTimestampArithmeticError,
    #[error("Pool data not found for signature verification {0}")]
    PoolDataNotFound(PoolId),
    #[error("Delegation data not found for signature verification {0}")]
    DelegationDataNotFound(DelegationId),
}
