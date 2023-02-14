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

#![allow(clippy::new_without_default)]
#![allow(unused)]

/// The substringer passive subsystem
pub struct Substringer {
    value: String,
}

impl subsystem::Subsystem for Substringer {}

impl Substringer {
    pub fn new(value: String) -> Self {
        Self { value }
    }

    pub fn append_get(&mut self, other: &str) -> String {
        self.value += other;
        self.value.clone()
    }

    pub fn substr(&self, begin: usize, end: usize) -> String {
        self.value.get(begin..end).map_or_else(String::new, str::to_string)
    }

    pub fn size(&self) -> usize {
        self.value.len()
    }
}

/// The counter passive subsystem
pub struct Counter {
    value: u64,
}

impl subsystem::Subsystem for Counter {}

impl Counter {
    pub fn new() -> Self {
        Self { value: 13 }
    }

    pub fn get(&self) -> u64 {
        self.value
    }

    pub fn add_and_get(&mut self, amount: u64) -> u64 {
        self.value += amount;
        self.value
    }
}
