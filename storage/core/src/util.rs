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

//! Utilities for implementing storage backends

use crate::Data;
use std::collections::BTreeMap;

/// If your map/set has Vec<T> as the key and you need to call `range` on it, you'll want to pass
/// slices for the bounds instead of allocating temporary vectors. However, something like
/// ```ignore
/// my_map.range(my_slice..);
/// ```
/// won't compile because trait bounds on `range` require that the passed range's generic parameter
/// implements `Borrow<&[T]>`, but `Vec<T>` only implements `Borrow<[T]>`.
/// `SliceRange` can be used as a workaround for this.
// TODO: move it elsewhere?
pub struct SliceRange<'a, T> {
    pub start: std::ops::Bound<&'a [T]>,
    pub end: std::ops::Bound<&'a [T]>,
}

impl<'a, T> std::ops::RangeBounds<[T]> for SliceRange<'a, T> {
    fn start_bound(&self) -> std::ops::Bound<&[T]> {
        self.start
    }

    fn end_bound(&self) -> std::ops::Bound<&[T]> {
        self.end
    }
}

/// Iterator over entries of a [BTreeMap] with keys starting with given prefix
pub struct MapPrefixIter<'m, T> {
    inner: std::collections::btree_map::Range<'m, Data, T>,
    prefix: Data,
}

impl<'m, T> MapPrefixIter<'m, T> {
    pub fn new(map: &'m BTreeMap<Data, T>, prefix: Data) -> Self {
        let inner = map.range(SliceRange {
            start: std::ops::Bound::Included(prefix.as_slice()),
            end: std::ops::Bound::Unbounded,
        });
        Self { inner, prefix }
    }
}

impl<'m, T> Iterator for MapPrefixIter<'m, T> {
    type Item = (&'m Data, &'m T);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .and_then(|(k, v)| k.starts_with(&self.prefix[..]).then_some((k, v)))
    }
}
