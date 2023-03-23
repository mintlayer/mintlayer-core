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

use std::collections::VecDeque;

pub struct CyclicFilter<T, const SUBFILTER_COUNT: usize> {
    list: VecDeque<T>,
}

impl<T, const SUBFILTER_COUNT: usize> CyclicFilter<T, SUBFILTER_COUNT> {
    pub fn new(new: T) -> Self {
        let mut list = VecDeque::new();
        list.push_back(new);
        CyclicFilter { list }
    }

    pub fn get_current_mut(&mut self) -> &mut T {
        self.list.back_mut().expect("")
    }

    pub fn roll_filters(&mut self, new: T) {
        if self.list.len() == SUBFILTER_COUNT {
            self.list.pop_front();
        }
        // Create a new subfilter with new seeds to get new false positives
        self.list.push_back(new);
    }

    pub fn get_all(&self) -> impl Iterator<Item = &T> {
        self.list.iter()
    }
}
