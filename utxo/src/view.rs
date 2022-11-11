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

use crate::{ConsumedUtxoCache, Error, Utxo, UtxosCache};
use common::{
    chain::{GenBlock, OutPoint},
    primitives::Id,
};

pub trait UtxosView {
    /// Retrieves utxo.
    fn utxo(&self, outpoint: &OutPoint) -> Option<Utxo>;

    /// Checks whether outpoint is unspent.
    fn has_utxo(&self, outpoint: &OutPoint) -> bool;

    /// Retrieves the block hash of the best block in this view
    fn best_block_hash(&self) -> Id<GenBlock>;

    /// Estimated size of the whole view (None if not implemented)
    fn estimated_size(&self) -> Option<usize>;
}

pub trait FlushableUtxoView {
    /// Performs bulk modification
    fn batch_write(&mut self, utxos: ConsumedUtxoCache) -> Result<(), Error>;
}

/// Flush the cache into the provided base. This will consume the cache and throw it away.
/// It uses the batch_write function since it's available in different kinds of views.
pub fn flush_to_base<T: FlushableUtxoView, P: UtxosView>(
    cache: UtxosCache<P>,
    base: &mut T,
) -> Result<(), Error> {
    let consumed_cache = cache.consume();
    base.batch_write(consumed_cache)
}
