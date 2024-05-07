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

use common::chain::OrderId;

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum Error {
    #[error("Accounting storage error")]
    StorageError(#[from] chainstate_types::storage_result::Error),
    #[error("Base accounting error: {0}")]
    AccountingError(#[from] accounting::Error),
    #[error("Order already exist: `{0}`")]
    OrderAlreadyExists(OrderId),
    #[error("Data for order {0}` not found")]
    OrderDataNotFound(OrderId),
    #[error("Ask balance for order {0}` not found")]
    OrderAskBalanceNotFound(OrderId),
    #[error("Give balance for order {0}` not found")]
    OrderGiveBalanceNotFound(OrderId),
    #[error("Data for order {0}` not found for undo")]
    InvariantOrderDataNotFoundForUndo(OrderId),
    #[error("Ask balance for order {0}` not found for undo")]
    InvariantOrderAskBalanceNotFoundForUndo(OrderId),
    #[error("Ask balance for order {0}` changed for undo")]
    InvariantOrderAskBalanceChangedForUndo(OrderId),
    #[error("Give balance for order {0}` not found for undo")]
    InvariantOrderGiveBalanceNotFoundForUndo(OrderId),
    #[error("Give balance for order {0}` changed for undo")]
    InvariantOrderGiveBalanceChangedForUndo(OrderId),
    #[error("Data for order {0}` still exist on withdraw undo")]
    InvariantOrderDataExistForCancelUndo(OrderId),
    #[error("Ask balance for order {0}` still exist on withdraw undo")]
    InvariantOrderAskBalanceExistForCancelUndo(OrderId),
    #[error("Give balance for order {0}` still exist on withdraw undo")]
    InvariantOrderGiveBalanceExistForCancelUndo(OrderId),
    #[error("Fill operation for order {0}` left a change")]
    FillOrderChangeLeft(OrderId),
    #[error("Coin type mismatch")]
    CurrencyMismatch,
    #[error("Order overflow: `{0}`")]
    OrderOverflow(OrderId),
    #[error("Attempt to withdraw non-existing order data `{0}`")]
    AttemptedCancelNonexistingOrderData(OrderId),
    #[error("Attempt to withdraw non-existing ask balance `{0}`")]
    AttemptedCancelNonexistingAskBalance(OrderId),
    #[error("Attempt to withdraw non-existing give balance `{0}`")]
    AttemptedCancelNonexistingGiveBalance(OrderId),

    // TODO Need a more granular error reporting in the following
    //      https://github.com/mintlayer/mintlayer-core/issues/811
    #[error("Orders accounting view query failed")]
    ViewFail,
    #[error("Orders accounting storage write failed")]
    StorageWrite,
}

pub type Result<T> = core::result::Result<T, Error>;
