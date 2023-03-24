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

pub struct CyclicFilter<T, const SUBFILTER_COUNT: usize> {
    list: Vec<T>,
}

/// A simple non-empty container that holds only the last `SUBFILTER_COUNT` elements
impl<T, const SUBFILTER_COUNT: usize> CyclicFilter<T, SUBFILTER_COUNT> {
    pub fn new(new: T) -> Self {
        let mut list = Vec::with_capacity(SUBFILTER_COUNT);
        list.push(new);
        CyclicFilter { list }
    }

    /// Returns the latest inserted element
    pub fn get_current_mut(&mut self) -> &mut T {
        &mut self.list[0]
    }

    /// Inserts a new item, dropping older items if necessary
    pub fn roll_filters(&mut self, new: T) {
        if self.list.len() == SUBFILTER_COUNT {
            self.list.pop();
        }
        self.list.insert(0, new);
    }

    /// Returns the last `SUBFILTER_COUNT` items starting with the most recent
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.list.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cyclic_filter() {
        let mut subfilters = CyclicFilter::<u32, 3>::new(0);
        for i in 0..100 {
            assert_eq!(*subfilters.get_current_mut(), i);

            let count = subfilters.iter().count();
            assert!(count >= 1 && count <= 3);

            subfilters.roll_filters(i + 1);
        }
    }
}
