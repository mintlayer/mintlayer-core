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

use std::ops::Deref;

use crate::{ConsumedUtxoCache, Utxo, UtxosCache};
use common::{
    chain::{GenBlock, UtxoOutPoint},
    primitives::Id,
};

pub trait UtxosView {
    /// Error that can occur during utxo queries
    type Error: std::error::Error;

    /// Retrieves utxo.
    fn utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, Self::Error>;

    /// Checks whether outpoint is unspent.
    fn has_utxo(&self, outpoint: &UtxoOutPoint) -> Result<bool, Self::Error>;

    /// Retrieves the block hash of the best block in this view
    fn best_block_hash(&self) -> Result<Id<GenBlock>, Self::Error>;

    /// Estimated size of the whole view (None if not implemented)
    fn estimated_size(&self) -> Option<usize>;
}

pub trait FlushableUtxoView {
    /// Errors potentially triggered by flushing the view
    type Error: std::error::Error;

    /// Performs bulk modification
    fn batch_write(&mut self, utxos: ConsumedUtxoCache) -> Result<(), Self::Error>;
}

/// Flush the cache into the provided base. This will consume the cache and throw it away.
/// It uses the batch_write function since it's available in different kinds of views.
pub fn flush_to_base<T: FlushableUtxoView, P: UtxosView>(
    cache: UtxosCache<P>,
    base: &mut T,
) -> Result<(), T::Error> {
    let consumed_cache = cache.consume();
    base.batch_write(consumed_cache)
}

impl<T> UtxosView for T
where
    T: Deref,
    <T as Deref>::Target: UtxosView,
{
    type Error = <T::Target as UtxosView>::Error;

    fn utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, Self::Error> {
        self.deref().utxo(outpoint)
    }

    fn has_utxo(&self, outpoint: &UtxoOutPoint) -> Result<bool, Self::Error> {
        self.deref().has_utxo(outpoint)
    }

    fn best_block_hash(&self) -> Result<Id<GenBlock>, Self::Error> {
        self.deref().best_block_hash()
    }

    fn estimated_size(&self) -> Option<usize> {
        self.deref().estimated_size()
    }
}
