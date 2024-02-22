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

mod block_undo;
mod cache;
mod data;
mod error;
mod operations;
mod storage;
mod view;

pub use {
    block_undo::{BlockUndo, BlockUndoError, TxUndo},
    cache::TokensAccountingCache,
    data::{
        FungibleTokenData, TokenData, TokensAccountingData, TokensAccountingDeltaData,
        TokensAccountingDeltaUndoData,
    },
    error::Error,
    operations::{random_undo_for_test, TokenAccountingUndo, TokensAccountingOperations},
    storage::{
        db::TokensAccountingDB, in_memory::InMemoryTokensAccounting, TokensAccountingStorageRead,
        TokensAccountingStorageWrite,
    },
    view::{FlushableTokensAccountingView, TokensAccountingView},
};

#[cfg(test)]
mod tests;
