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

use common::{chain::Transaction, primitives::Id};
use serialization::{Decode, Encode};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum BlockUndoError {
    #[error("Attempted to insert a transaction in undo that already exists: `{0}`")]
    UndoAlreadyExists(Id<Transaction>),
    #[error("PoS undo is missing for transaction `{0}`")]
    MissingTxUndo(Id<Transaction>),
    #[error("Attempted to insert a reward in undo that already exists")]
    UndoAlreadyExistsForReward,
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct BlockRewardUndo<U>(Vec<U>);

impl<U> BlockRewardUndo<U> {
    pub fn new(utxos: Vec<U>) -> Self {
        Self(utxos)
    }

    pub fn inner(&self) -> &[U] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<U> {
        self.0
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct TxUndo<U>(Vec<U>);

impl<U> TxUndo<U> {
    pub fn new(undos: Vec<U>) -> Self {
        Self(undos)
    }

    pub fn inner(&self) -> &[U] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<U> {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct BlockUndo<U> {
    reward_undos: Option<BlockRewardUndo<U>>,
    tx_undos: BTreeMap<Id<Transaction>, TxUndo<U>>,
}

impl<U> BlockUndo<U> {
    pub fn new(
        reward_undos: Option<BlockRewardUndo<U>>,
        tx_undos: BTreeMap<Id<Transaction>, TxUndo<U>>,
    ) -> Self {
        Self {
            reward_undos,
            tx_undos,
        }
    }

    pub fn consume(
        self,
    ) -> (
        Option<BlockRewardUndo<U>>,
        BTreeMap<Id<Transaction>, TxUndo<U>>,
    ) {
        (self.reward_undos, self.tx_undos)
    }
}
