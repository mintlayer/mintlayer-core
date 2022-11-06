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

use common::primitives::Id;
use typename::TypeName;

mod error;
mod pool;
mod storage;

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, TypeName)]
pub struct Pool;
pub type PoolId = Id<Pool>;

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, TypeName)]
pub struct Delegation;
pub type DelegationId = Id<Delegation>;

pub use crate::{
    error::Error,
    pool::{
        block_undo::{BlockUndo, BlockUndoError, TxUndo},
        delegation::DelegationData,
        delta::{data::PoSAccountingDeltaData, PoSAccountingDelta},
        helpers::make_pool_id,
        operations::{PoSAccountingOperations, PoSAccountingUndo},
        pool_data::PoolData,
        storage::{PoSAccountingDB, PoSAccountingDBMut},
        view::{FlushablePoSAccountingView, PoSAccountingView},
    },
    storage::{PoSAccountingStorageRead, PoSAccountingStorageWrite},
};
