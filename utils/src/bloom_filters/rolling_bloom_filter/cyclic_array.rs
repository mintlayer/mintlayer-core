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

/// A simple non-empty container that holds only the last `SIZE` elements
pub struct CyclicArray<T, const SIZE: usize> {
    list: [T; SIZE],
    current_index: usize,
}

impl<T, const SIZE: usize> CyclicArray<T, SIZE> {
    pub fn new(list: [T; SIZE]) -> Self {
        CyclicArray {
            list,
            current_index: SIZE - 1,
        }
    }

    /// Returns the latest inserted element
    pub fn get_last_mut(&mut self) -> &mut T {
        &mut self.list[self.current_index]
    }

    /// Inserts a new item, dropping one older item
    pub fn push(&mut self, new: T) {
        self.current_index = (self.current_index + 1) % SIZE;
        self.list[self.current_index] = new;
    }

    /// Returns the last `SUBFILTER_COUNT` items. The order is unspecified!
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.list.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cyclic_filter() {
        let mut subfilters = CyclicArray::<u32, 3>::new([0, 1, 2]);
        for i in 2..100 {
            assert_eq!(*subfilters.get_last_mut(), i);

            let count = subfilters.iter().count();
            assert_eq!(count, 3);

            subfilters.push(i + 1);
        }
    }
}
