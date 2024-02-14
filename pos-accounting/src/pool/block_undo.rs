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

use std::collections::BTreeMap;

use crate::PoSAccountingUndo;

use common::{chain::Transaction, primitives::Id};
use serialization::{Decode, Encode};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum AccountingBlockUndoError {
    #[error("Attempted to insert a transaction in undo that already exists: `{0}`")]
    UndoAlreadyExists(Id<Transaction>),
    #[error("PoS undo is missing for transaction `{0}`")]
    MissingTxUndo(Id<Transaction>),
    #[error("Attempted to insert a reward in undo that already exists")]
    UndoAlreadyExistsForReward,
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct AccountingBlockRewardUndo(Vec<PoSAccountingUndo>);

impl AccountingBlockRewardUndo {
    pub fn new(utxos: Vec<PoSAccountingUndo>) -> Self {
        Self(utxos)
    }

    pub fn inner(&self) -> &[PoSAccountingUndo] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<PoSAccountingUndo> {
        self.0
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct AccountingTxUndo(Vec<PoSAccountingUndo>);

impl AccountingTxUndo {
    pub fn new(undos: Vec<PoSAccountingUndo>) -> Self {
        Self(undos)
    }

    pub fn inner(&self) -> &[PoSAccountingUndo] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<PoSAccountingUndo> {
        self.0
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Encode, Decode)]
pub struct AccountingBlockUndo {
    reward_undos: Option<AccountingBlockRewardUndo>,
    tx_undos: BTreeMap<Id<Transaction>, AccountingTxUndo>,
}

impl AccountingBlockUndo {
    pub fn new(
        reward_undos: Option<AccountingBlockRewardUndo>,
        tx_undos: BTreeMap<Id<Transaction>, AccountingTxUndo>,
    ) -> Self {
        Self {
            reward_undos,
            tx_undos,
        }
    }

    pub fn consume(
        self,
    ) -> (
        Option<AccountingBlockRewardUndo>,
        BTreeMap<Id<Transaction>, AccountingTxUndo>,
    ) {
        (self.reward_undos, self.tx_undos)
    }
}
