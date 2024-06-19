// Copyright (c) 2021-2024 RBB S.r.l
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

/// Return an iterator that produces pairs, where the first item comes from the passed iterator and the second one is
/// a clone of the passed value. On the last iteration the value will be moved instead of cloning.
///
/// This is equivalent to `iter.zip(itertools::repeat_n(val_to_clone, iter.len()))`, but doesn't
/// require to know the number of items that will be produced by `iter` in advance.
pub fn zip_clone<Iter, TypeToClone>(
    iter: Iter,
    val_to_clone: TypeToClone,
) -> ZipCloneIterator<Iter, TypeToClone>
where
    Iter: Iterator,
    TypeToClone: Clone,
{
    ZipCloneIterator {
        iter: iter.peekable(),
        val_to_clone: Some(val_to_clone),
    }
}

pub struct ZipCloneIterator<Iter, TypeToClone>
where
    Iter: Iterator,
    TypeToClone: Clone,
{
    iter: std::iter::Peekable<Iter>,
    val_to_clone: Option<TypeToClone>,
}

impl<Iter, TypeToClone> Iterator for ZipCloneIterator<Iter, TypeToClone>
where
    Iter: Iterator,
    TypeToClone: Clone,
{
    type Item = (<Iter as Iterator>::Item, TypeToClone);

    fn next(&mut self) -> Option<Self::Item> {
        self.val_to_clone.as_ref()?;

        if let Some(next_val) = self.iter.next() {
            let second_part = if self.iter.peek().is_some() {
                self.val_to_clone.clone()
            } else {
                self.val_to_clone.take()
            }
            .expect("val_to_clone is known to be Some");

            Some((next_val, second_part))
        } else {
            self.val_to_clone = None;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::atomics::RelaxedAtomicU32;

    use super::*;

    struct CloneCoutingType {
        some_data: u32,
        counter: Arc<RelaxedAtomicU32>,
    }

    impl Clone for CloneCoutingType {
        fn clone(&self) -> Self {
            self.counter.fetch_add(1);
            Self {
                some_data: self.some_data,
                counter: Arc::clone(&self.counter),
            }
        }
    }

    #[test]
    fn test() {
        let some_data = 123;
        let clone_counter = Arc::new(RelaxedAtomicU32::new(0));

        let val_to_clone = CloneCoutingType {
            some_data,
            counter: Arc::clone(&clone_counter),
        };

        let vals = zip_clone(0..100, val_to_clone)
            .map(|(val, cloned_val)| (val, cloned_val.some_data))
            .collect::<Vec<_>>();
        let expected_vals = (0..100).map(|val| (val, some_data)).collect::<Vec<_>>();
        assert_eq!(vals, expected_vals);
        assert_eq!(clone_counter.load(), 99);
    }
}
