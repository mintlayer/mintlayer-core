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

use common::{chain::OrderId, primitives::Amount};

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum Error {
    #[error("Base accounting error: `{0}`")]
    AccountingError(#[from] accounting::Error),
    #[error("Order already exists: `{0:x}`")]
    OrderAlreadyExists(OrderId),
    #[error("Data for order `{0:x}` not found")]
    OrderDataNotFound(OrderId),
    #[error("Attempt to create an order with zero exchange value `{0:x}`")]
    OrderWithZeroValue(OrderId),
    #[error("Data for order `{0:x}` not found for undo")]
    InvariantOrderDataNotFoundForUndo(OrderId),
    #[error("Ask balance for order `{0:x}` changed for undo")]
    InvariantOrderAskBalanceChangedForUndo(OrderId),
    #[error("Give balance for order `{0:x}` changed for undo")]
    InvariantOrderGiveBalanceChangedForUndo(OrderId),
    #[error("Data for order `{0:x}` still exist on conclude undo")]
    InvariantOrderDataExistForConcludeUndo(OrderId),
    #[error("Data for order `{0:x}` doesn't exist on freeze undo")]
    InvariantOrderDataNotExistForFreezeUndo(OrderId),
    #[error("Ask balance for order `{0:x}` still exist on conclude undo")]
    InvariantOrderAskBalanceExistForConcludeUndo(OrderId),
    #[error("Give balance for order `{0:x}` still exist on conclude undo")]
    InvariantOrderGiveBalanceExistForConcludeUndo(OrderId),
    #[error("Ask balance for non-existing order `{0:x}` is not zero")]
    InvariantNonzeroAskBalanceForMissingOrder(OrderId),
    #[error("Give balance for non-existing order `{0:x}` is not zero")]
    InvariantNonzeroGiveBalanceForMissingOrder(OrderId),
    #[error("Order overflow: `{0:x}`")]
    OrderOverflow(OrderId),
    #[error("Order `{0:x}` can provide `{1:?}` amount; but attempted to fill `{2:?}`")]
    OrderOverbid(OrderId, Amount, Amount),
    #[error("Order `{0:x}` provides amount `{1:?}` that is not enough to fill even a single atom")]
    OrderUnderbid(OrderId, Amount),
    #[error("Attempt to conclude non-existing order data `{0:x}`")]
    AttemptedConcludeNonexistingOrderData(OrderId),
    #[error("Attempt to freeze non-existing order data `{0:x}`")]
    AttemptedFreezeNonexistingOrderData(OrderId),
    #[error("Attempt to freeze already frozen order `{0:x}`")]
    AttemptedFreezeAlreadyFrozenOrder(OrderId),
    #[error("Attempt to fill frozen order `{0:x}`")]
    AttemptedFillFrozenOrder(OrderId),
    #[error("Unsupported token version")]
    UnsupportedTokenVersion,

    // TODO Need a more granular error reporting in the following
    //      https://github.com/mintlayer/mintlayer-core/issues/811
    #[error("Orders accounting view query failed")]
    ViewFail,
    #[error("Orders accounting storage write failed")]
    StorageWrite,
}

pub type Result<T> = core::result::Result<T, Error>;

impl From<std::convert::Infallible> for Error {
    fn from(value: std::convert::Infallible) -> Self {
        match value {}
    }
}

#[cfg(test)]
mod tests {
    use common::primitives::H256;

    use super::*;

    #[test]
    fn order_errors_display_full_order_id() {
        let order_id = OrderId::new(H256::repeat_byte(0xab));
        let full_order_id = "abababababababababababababababababababababababababababababababab";

        let errors = [
            Error::OrderAlreadyExists(order_id),
            Error::OrderDataNotFound(order_id),
            Error::OrderWithZeroValue(order_id),
            Error::InvariantOrderDataNotFoundForUndo(order_id),
            Error::InvariantOrderAskBalanceChangedForUndo(order_id),
            Error::InvariantOrderGiveBalanceChangedForUndo(order_id),
            Error::InvariantOrderDataExistForConcludeUndo(order_id),
            Error::InvariantOrderDataNotExistForFreezeUndo(order_id),
            Error::InvariantOrderAskBalanceExistForConcludeUndo(order_id),
            Error::InvariantOrderGiveBalanceExistForConcludeUndo(order_id),
            Error::InvariantNonzeroAskBalanceForMissingOrder(order_id),
            Error::InvariantNonzeroGiveBalanceForMissingOrder(order_id),
            Error::OrderOverflow(order_id),
            Error::OrderOverbid(order_id, Amount::from_atoms(1), Amount::from_atoms(2)),
            Error::OrderUnderbid(order_id, Amount::from_atoms(1)),
            Error::AttemptedConcludeNonexistingOrderData(order_id),
            Error::AttemptedFreezeNonexistingOrderData(order_id),
            Error::AttemptedFreezeAlreadyFrozenOrder(order_id),
            Error::AttemptedFillFrozenOrder(order_id),
        ];

        for error in errors {
            assert!(error.to_string().contains(full_order_id));
        }
    }
}
