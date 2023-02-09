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

use common::primitives::Amount;

#[derive(thiserror::Error, Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    #[error("Pool already decommissioned")]
    PoolAlreadyDecommissioned,
    #[error("Attempted add balance to decommissioned pool")]
    AttemptedToAddBalanceToDecommissionedPool,
    #[error("Pool stake addition arithmetic error")]
    PoolStakeAdditionArithmeticError(Amount, Amount),
    #[error("Pool stake addition arithmetic error")]
    PoolStakeSubtractionArithmeticError(Amount, Amount),
    #[error("Pool stake negative addition (double-removal) arithmetic error")]
    PoolStakeNegativeAdditionArithmeticError(Amount, Amount),
    #[error("Pool stake negative substraction arithmetic error")]
    PoolStakeNegativeSubtractionArithmeticError(Amount, Amount),
}
