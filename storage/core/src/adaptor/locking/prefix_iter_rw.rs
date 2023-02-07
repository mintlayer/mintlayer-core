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

//! Internal functions and types used in the implementation of prefix iterator for RW transactions

use super::{Data, DbMapId, PrefixIter, TxRw};
use itertools::EitherOrBoth;

// The prefix iterator type for mutable transaction is a fairly complicated type. Here, we
// introduce a bunch of type aliases to simplify its definition a bit.
type DataPair = (Data, Data);
type DataPairRef<'a> = (&'a [u8], &'a Option<Data>);
type KeyCompareFn = fn(&DataPair, &DataPairRef<'_>) -> std::cmp::Ordering;
type ItemMergeFn = fn(itertools::EitherOrBoth<DataPair, DataPairRef<'_>>) -> Option<DataPair>;
type DbIter<'i, T> = <T as PrefixIter<'i>>::Iterator;
type DeltaIter<'i> = crate::util::PrefixIter<'i, Option<Data>>;
type JoinIter<'i, T> = itertools::MergeJoinBy<DbIter<'i, T>, DeltaIter<'i>, KeyCompareFn>;
pub type Iter<'i, T> = std::iter::FilterMap<JoinIter<'i, T>, ItemMergeFn>;

/// Function to compare key-value entries by the key
fn comparator((a, _): &DataPair, (b, _): &DataPairRef<'_>) -> std::cmp::Ordering {
    a.as_slice().cmp(b)
}

/// How to merge the items if the keys collide
fn merger(item: EitherOrBoth<DataPair, DataPairRef<'_>>) -> Option<(Data, Data)> {
    match item {
        // Item only in original db, just present it
        EitherOrBoth::Left(l) => Some(l),
        // If the entry is present in both database and the delta map, the delta map takes
        // precedence. If it only is in the delta map, just take that.
        EitherOrBoth::Right((k, v)) | EitherOrBoth::Both(_, (k, v)) => {
            v.as_ref().map(|v| (k.to_vec(), v.clone()))
        }
    }
}

/// Create the iterator
pub fn iter<'tx, 'i, 'm: 'i, T: PrefixIter<'i>>(
    tx: &'m TxRw<'tx, T>,
    map_id: DbMapId,
    prefix: Data,
) -> crate::Result<Iter<'i, T>> {
    // Initialize the iterator over the underlying db and the deltas
    let db_iter = tx.db.prefix_iter(map_id, prefix.clone())?;
    let delta_iter = crate::util::PrefixIter::new(&tx.deltas[map_id], prefix);

    // Merge the entries from the two iterators
    let iter = itertools::merge_join_by(db_iter, delta_iter, comparator as KeyCompareFn)
        .filter_map(merger as ItemMergeFn);
    Ok(iter)
}
