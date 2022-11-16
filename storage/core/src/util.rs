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

/// Iterator over entries of a [BTreeMap] with keys starting with given prefix
pub struct PrefixIter<'m, T> {
    inner: std::collections::btree_map::Range<'m, Data, T>,
    prefix: Data,
}

impl<'m, T> PrefixIter<'m, T> {
    pub fn new(map: &'m BTreeMap<Data, T>, prefix: Data) -> Self {
        let inner = map.range(prefix.clone()..);
        Self { inner, prefix }
    }
}

impl<'m, T> Iterator for PrefixIter<'m, T> {
    type Item = (&'m [u8], &'m T);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .and_then(|(k, v)| k.starts_with(&self.prefix[..]).then(|| (k.as_ref(), v)))
    }
}
