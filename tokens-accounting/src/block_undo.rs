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

use std::collections::BTreeMap;

use crate::TokenAccountingUndo;

use common::{chain::Transaction, primitives::Id};
use serialization::{Decode, Encode};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum BlockUndoError {
    #[error("Attempted to insert a transaction in undo that already exists: `{0}`")]
    UndoAlreadyExists(Id<Transaction>),
    #[error("Tokens undo is missing for transaction `{0}`")]
    MissingTxUndo(Id<Transaction>),
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct TxUndo(Vec<TokenAccountingUndo>);

impl TxUndo {
    pub fn new(undos: Vec<TokenAccountingUndo>) -> Self {
        Self(undos)
    }

    pub fn inner(&self) -> &[TokenAccountingUndo] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<TokenAccountingUndo> {
        self.0
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Encode, Decode)]
pub struct BlockUndo {
    tx_undos: BTreeMap<Id<Transaction>, TxUndo>,
}

impl BlockUndo {
    pub fn new(tx_undos: BTreeMap<Id<Transaction>, TxUndo>) -> Self {
        Self { tx_undos }
    }

    pub fn consume(self) -> BTreeMap<Id<Transaction>, TxUndo> {
        self.tx_undos
    }
}
