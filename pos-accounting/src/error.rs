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

use common::chain::DelegationId;

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum Error {
    #[error("Base accounting error: {0}")]
    AccountingError(#[from] accounting::Error),
    #[error("Pool already exists by balance")]
    InvariantErrorPoolBalanceAlreadyExists,
    #[error("Pool already exists by data")]
    InvariantErrorPoolDataAlreadyExists,
    #[error("Attempted to decommission a non-existing pool data")]
    AttemptedDecommissionNonexistingPoolData,
    #[error("Failed to create a delegation because the target pool doesn't exist")]
    DelegationCreationFailedPoolDoesNotExist,
    #[error("Failed to delete a delegation because the delegation doesn't exist")]
    DelegationDeletionFailedIdDoesNotExist,
    #[error("Failed to delete a delegation because the delegation balance must be zero")]
    DelegationDeletionFailedBalanceNonZero,
    #[error("Failed to delete a delegation because the delegation pools share must be zero")]
    DelegationDeletionFailedPoolsShareNonZero,
    #[error("Failed to delete a delegation because the pools still exists")]
    DelegationDeletionFailedPoolStillExists,
    #[error("Failed to create a delegation because the resulting id already exists")]
    InvariantErrorDelegationCreationFailedIdAlreadyExists,
    #[error("Delegate to a non-existing reward id")]
    DelegateToNonexistingId,
    #[error("Delegate to a non-existing pool")]
    DelegateToNonexistingPool,
    #[error("Spending share of non-existing pool")]
    SpendingShareOfNonexistingDelegation(DelegationId),
    #[error("Addition error")]
    AdditionError,
    #[error("Subtraction error")]
    SubError,
    #[error("Delegation arithmetic add error")]
    DelegationBalanceAdditionError,
    #[error("Delegation arithmetic sub error")]
    DelegationBalanceSubtractionError,
    #[error("Pool balance arithmetic add error")]
    PoolBalanceAdditionError,
    #[error("Pool balance arithmetic sub error")]
    PoolBalanceSubtractionError,
    #[error("Delegation shares arithmetic add error")]
    DelegationSharesAdditionError,
    #[error("Delegation shares arithmetic sub error")]
    DelegationSharesSubtractionError,
    #[error("Pool creation undo failed; pool data cannot be found")]
    InvariantErrorPoolCreationReversalFailedDataNotFound,
    #[error("Pledge amount has changed while reversal being done")]
    InvariantErrorPoolCreationReversalFailedAmountChanged,
    #[error("Undo failed as decommission pool balance is still in storage")]
    InvariantErrorDecommissionUndoFailedPoolBalanceAlreadyExists,
    #[error("Undo failed as decommission pool data is still in storage")]
    InvariantErrorDecommissionUndoFailedPoolDataAlreadyExists,
    #[error("Reversal of delegation id creation failed; not found")]
    InvariantErrorDelegationIdUndoFailedNotFound,
    #[error("Reversal of delegation id creation failed; data changed")]
    InvariantErrorDelegationIdUndoFailedDataConflict,
    #[error("Delegation balance arithmetic undo error")]
    InvariantErrorDelegationBalanceAdditionUndoError,
    #[error("Pool balance arithmetic undo error")]
    InvariantErrorPoolBalanceAdditionUndoError,
    #[error("Delegation shares arithmetic undo error")]
    InvariantErrorDelegationSharesAdditionUndoError,
    #[error("Delegation shares arithmetic undo error as it doesn't exist")]
    InvariantErrorDelegationShareNotFound,
    #[error("Failed to convert pledge value to signed")]
    PledgeValueToSignedError,
    #[error("Delegation undo failed; data not found for {0}")]
    InvariantErrorDelegationUndoFailedDataNotFound(DelegationId),
    #[error("Delta reverts merge failed due to duplicates")]
    DuplicatesInDeltaAndUndo,
    #[error("Increase staker rewards of nonexisting pool")]
    IncreaseStakerRewardsOfNonexistingPool,
    #[error("Staker balance addition error")]
    StakerBalanceOverflow,
    #[error("Undo of increase pledge amount failed as pool balance is not in storage")]
    InvariantErrorIncreasePledgeUndoFailedPoolBalanceNotFound,
    #[error("Undo of increase staker reward failed as pool balance is not in storage")]
    InvariantErrorIncreaseStakerRewardUndoFailedPoolBalanceNotFound,
    #[error("Non-zero balance of non-existing delegation")]
    InvariantErrorNonZeroBalanceForNonExistingDelegation,

    // TODO Need a more granular error reporting in the following
    //      https://github.com/mintlayer/mintlayer-core/issues/811
    #[error("PoS accounting view query failed")]
    ViewFail,
    #[error("PoS accounting storage write failed")]
    StorageWrite,
}

pub type Result<T> = core::result::Result<T, Error>;

impl From<std::convert::Infallible> for Error {
    fn from(value: std::convert::Infallible) -> Self {
        match value {}
    }
}
