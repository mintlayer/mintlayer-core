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

use crate::Utxo;
use serialization::{Decode, Encode};
use std::fmt::Debug;

/// Tells the state of the utxo
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
#[allow(clippy::large_enum_variant)]
pub enum UtxoStatus {
    Spent,
    Entry(Utxo),
}

/// The utxo entry is fresh when the parent does not have this utxo or
/// if it exists in parent but not in current cache.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub enum IsFresh {
    Yes,
    No,
}

impl From<bool> for IsFresh {
    fn from(v: bool) -> Self {
        if v {
            IsFresh::Yes
        } else {
            IsFresh::No
        }
    }
}

/// The utxo entry is dirty when this version is different from the parent.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub enum IsDirty {
    Yes,
    No,
}

impl From<bool> for IsDirty {
    fn from(v: bool) -> Self {
        if v {
            IsDirty::Yes
        } else {
            IsDirty::No
        }
    }
}

/// Just the Utxo with additional information.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct UtxoEntry {
    status: UtxoStatus,
    is_fresh: IsFresh,
    is_dirty: IsDirty,
}

impl UtxoEntry {
    pub fn new(utxo: Option<Utxo>, is_fresh: IsFresh, is_dirty: IsDirty) -> UtxoEntry {
        UtxoEntry {
            status: match utxo {
                Some(utxo) => UtxoStatus::Entry(utxo),
                None => UtxoStatus::Spent,
            },
            is_fresh,
            is_dirty,
        }
    }

    pub fn is_dirty(&self) -> bool {
        match self.is_dirty {
            IsDirty::Yes => true,
            IsDirty::No => false,
        }
    }

    pub fn is_fresh(&self) -> bool {
        match self.is_fresh {
            IsFresh::Yes => true,
            IsFresh::No => false,
        }
    }

    pub fn is_spent(&self) -> bool {
        self.status == UtxoStatus::Spent
    }

    pub fn utxo(&self) -> Option<&Utxo> {
        match &self.status {
            UtxoStatus::Spent => None,
            UtxoStatus::Entry(utxo) => Some(utxo),
        }
    }

    pub fn utxo_mut(&mut self) -> Option<&mut Utxo> {
        match &mut self.status {
            UtxoStatus::Spent => None,
            UtxoStatus::Entry(utxo) => Some(utxo),
        }
    }

    pub fn take_utxo(self) -> Option<Utxo> {
        match self.status {
            UtxoStatus::Spent => None,
            UtxoStatus::Entry(utxo) => Some(utxo),
        }
    }
}
