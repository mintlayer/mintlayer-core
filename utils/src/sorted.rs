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

pub trait Sorted<T> {
    fn sorted(self) -> Self
    where
        T: Ord;

    fn sorted_by<F>(self, compare: F) -> Self
    where
        F: FnMut(&T, &T) -> std::cmp::Ordering;
}

impl<T: Clone> Sorted<T> for Vec<T> {
    fn sorted(mut self) -> Self
    where
        T: Ord,
    {
        self.sort();
        self
    }

    fn sorted_by<F>(mut self, compare: F) -> Self
    where
        F: FnMut(&T, &T) -> std::cmp::Ordering,
    {
        self.sort_by(compare);
        self
    }
}
