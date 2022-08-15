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
        let entry = UtxoEntry {
            status: match utxo {
                Some(utxo) => UtxoStatus::Entry(utxo),
                None => UtxoStatus::Spent,
            },
            is_fresh,
            is_dirty,
        };

        // Out of these 2^3 = 8 states, only some combinations are valid:
        // - unspent, FRESH, DIRTY (e.g. a new utxo created in the cache)
        // - unspent, not FRESH, DIRTY (e.g. a utxo changed in the cache during a reorg)
        // - unspent, not FRESH, not DIRTY (e.g. an unspent utxo fetched from the parent cache)
        // - spent, FRESH, not DIRTY (e.g. a spent utxo fetched from the parent cache)
        // - spent, not FRESH, DIRTY (e.g. a utxo is spent and spentness needs to be flushed to the parent)
        match &entry.status {
            UtxoStatus::Entry(_) => assert!(!entry.is_fresh() || entry.is_dirty()),
            &UtxoStatus::Spent => assert!(entry.is_fresh() ^ entry.is_dirty()),
        }

        entry
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

#[cfg(test)]
mod unit_test {
    use super::*;
    use crate::UtxoSource;
    use common::{
        chain::{tokens::OutputValue, Destination, OutputPurpose, TxOutput},
        primitives::Amount,
    };
    use rstest::rstest;

    fn some_utxo() -> Option<Utxo> {
        Some(Utxo::new(
            TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(1)),
                OutputPurpose::Transfer(Destination::AnyoneCanSpend),
            ),
            false,
            UtxoSource::Mempool,
        ))
    }

    #[rustfmt::skip]
    #[rstest]
    #[case(some_utxo(), IsFresh::Yes, IsDirty::Yes)]
    #[case(some_utxo(), IsFresh::No,  IsDirty::Yes)]
    #[case(some_utxo(), IsFresh::No,  IsDirty::No)]
    #[case(None,        IsFresh::Yes, IsDirty::No)]
    #[case(None,        IsFresh::No,  IsDirty::Yes)]
    #[should_panic]
    #[case(None,        IsFresh::Yes, IsDirty::Yes)]
    #[should_panic]
    #[case(None,        IsFresh::No,  IsDirty::No)]
    #[should_panic]
    #[case(some_utxo(), IsFresh::Yes, IsDirty::No)]
    fn create_utxo_entry(
        #[case] utxo: Option<Utxo>,
        #[case] is_fresh: IsFresh,
        #[case] is_dirty: IsDirty,
    ) {
        let _ = UtxoEntry::new(utxo, is_fresh, is_dirty);
    }
}
