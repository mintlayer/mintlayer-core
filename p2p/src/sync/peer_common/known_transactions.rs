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

use common::{chain::Transaction, primitives::Id};
use randomness::make_pseudo_rng;
use utils::bloom_filters::rolling_bloom_filter::RollingBloomFilter;

/// Use the same parameters as Bitcoin Core (see `m_tx_inventory_known_filter`)
const ROLLING_BLOOM_FILTER_SIZE: usize = 50000;
const ROLLING_BLOOM_FPP: f64 = 0.000001;

/// Helper to use with `RollingBloomFilter` because `Id` does not implement `Hash`
struct TxIdWrapper(Id<Transaction>);

impl std::hash::Hash for TxIdWrapper {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_ref().hash(state);
    }
}

/// A rolling filter of all known transactions for use by Peer implementations.
pub struct KnownTransactions {
    filter: RollingBloomFilter<TxIdWrapper>,
}

impl KnownTransactions {
    pub fn new() -> Self {
        Self {
            filter: RollingBloomFilter::new(
                ROLLING_BLOOM_FILTER_SIZE,
                ROLLING_BLOOM_FPP,
                &mut make_pseudo_rng(),
            ),
        }
    }

    pub fn insert(&mut self, tx_id: &Id<Transaction>) {
        self.filter.insert(&TxIdWrapper(*tx_id), &mut make_pseudo_rng())
    }

    pub fn contains(&self, tx_id: &Id<Transaction>) -> bool {
        self.filter.contains(&TxIdWrapper(*tx_id))
    }
}
