// Copyright (c) 2021-2023 RBB S.r.l
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

use std::iter::FusedIterator;

/// An iterator that pads the leaves of a Merkle tree with incremental padding,
/// i.e. the padding function is applied to the last value of the iterator,
/// iteratively, until the next power of two is reached.
/// An empty iterator will return no values.
pub struct IncrementalPaddingIterator<T, I: Iterator<Item = T> + FusedIterator, F: Fn(&T) -> T> {
    leaves: I,
    padding_function: F,
    last_value: Option<T>,
    current_index: usize,
}

impl<T, I: Iterator<Item = T> + FusedIterator, F: Fn(&T) -> T> IncrementalPaddingIterator<T, I, F> {
    pub fn new(leaves: I, padding_function: F) -> Self {
        IncrementalPaddingIterator { leaves, padding_function, last_value: None, current_index: 0 }
    }
}

impl<T: Clone, I: Iterator<Item = T> + FusedIterator, F: Fn(&T) -> T> Iterator
    for IncrementalPaddingIterator<T, I, F>
{
    type Item = T;

    fn next(&mut self) -> Option<T> {
        match self.leaves.next() {
            None => {
                // index == 0 means that we have no leaves at all;
                // otherwise, we have to check if we have reached the next power of two to complete the padding.
                if self.current_index == self.current_index.next_power_of_two()
                    || self.current_index == 0
                {
                    None
                } else {
                    let res =
                        (self.padding_function)(self.last_value.as_ref().expect("Never at zero"));
                    self.current_index += 1;
                    self.last_value = Some(res.clone());
                    Some(res)
                }
            }
            Some(leaf) => {
                self.current_index += 1;
                self.last_value = Some(leaf.clone());
                Some(leaf)
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::internal::{hash_data, HashedData};

    use super::*;

    fn leaves_with_inc_padding(n: usize) -> Vec<HashedData> {
        let mut leaves = Vec::new();
        for i in 0..n {
            leaves.push(HashedData::from_low_u64_be(i as u64));
        }
        for _ in n..n.next_power_of_two() {
            leaves.push(hash_data(*leaves.last().unwrap()));
        }
        leaves
    }

    #[test]
    fn non_zero_size() {
        let f = |i: &HashedData| hash_data(i);

        for i in 1..130 {
            let all_leaves = leaves_with_inc_padding(i);
            let leaves = &leaves_with_inc_padding(i)[0..i];

            let vec =
                IncrementalPaddingIterator::new(leaves.iter().copied(), f).collect::<Vec<_>>();
            assert_eq!(vec, all_leaves);
        }
    }

    #[test]
    fn zero_size() {
        let f = |i: &HashedData| hash_data(i);

        let vec = IncrementalPaddingIterator::new(Vec::new().into_iter(), f).collect::<Vec<_>>();
        assert_eq!(vec, Vec::new());
    }
}
