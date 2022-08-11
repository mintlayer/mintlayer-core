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

/// The utxo entry is dirty when this version is different from the parent.
pub const DIRTY: u8 = 0b01;
/// The utxo entry is fresh when the parent does not have this utxo or
/// if it exists in parent but not in current cache.
pub const FRESH: u8 = 0b10;

/// Tells the state of the utxo
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
#[allow(clippy::large_enum_variant)]
pub enum UtxoStatus {
    Spent,
    Entry(Utxo),
}

/// Just the Utxo with additional information.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct UtxoEntry {
    status: UtxoStatus,
    flags: u8,
}

impl UtxoEntry {
    pub fn new(utxo: Option<Utxo>, flags: u8) -> UtxoEntry {
        UtxoEntry {
            status: match utxo {
                Some(utxo) => UtxoStatus::Entry(utxo),
                None => UtxoStatus::Spent,
            },
            flags,
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.flags & DIRTY != 0
    }

    pub fn is_fresh(&self) -> bool {
        self.flags & FRESH != 0
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
