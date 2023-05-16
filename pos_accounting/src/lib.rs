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

mod data;
mod error;
mod pool;
mod storage;

pub use crate::{
    data::PoSAccountingData,
    error::{Error, Result},
    pool::{
        block_undo::{
            AccountingBlockRewardUndo, AccountingBlockUndo, AccountingBlockUndoError,
            AccountingTxUndo,
        },
        delegation::DelegationData,
        delta::{data::PoSAccountingDeltaData, DeltaMergeUndo, PoSAccountingDelta},
        helpers::{make_delegation_id, make_pool_id},
        operations::{PoSAccountingOperations, PoSAccountingUndo},
        pool_data::PoolData,
        storage::PoSAccountingDB,
        view::{FlushablePoSAccountingView, PoSAccountingView},
    },
    storage::{
        in_memory::InMemoryPoSAccounting, PoSAccountingStorageRead, PoSAccountingStorageWrite,
        StorageTag,
    },
};
