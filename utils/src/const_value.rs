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

use std::{
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    ops::Deref,
};

/// A wrapper for a type that is not supposed to be modified, no matter one
/// This particularly solves the problem of not being able to mark member variables as const in Rust
pub struct ConstValue<T> {
    value: T,
}

impl<T> ConstValue<T> {
    pub fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T> From<T> for ConstValue<T> {
    fn from(v: T) -> Self {
        Self { value: v }
    }
}

impl<T: Default> Default for ConstValue<T> {
    fn default() -> Self {
        Self {
            value: T::default(),
        }
    }
}

impl<T: Debug> Debug for ConstValue<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ConstValue").field(&self.value).finish()
    }
}

impl<T: Display> Display for ConstValue<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}

impl<T: Copy> Copy for ConstValue<T> {}

impl<T: Clone> Clone for ConstValue<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
        }
    }
}

impl<T: PartialEq> PartialEq for ConstValue<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T: Eq> Eq for ConstValue<T> {}

impl<T: PartialOrd> PartialOrd for ConstValue<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.value.partial_cmp(&other.value)
    }
}

impl<T: Ord> Ord for ConstValue<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl<T: Hash> Hash for ConstValue<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state)
    }
}

impl<T> AsRef<T> for ConstValue<T> {
    fn as_ref(&self) -> &T {
        &self.value
    }
}

impl<T> Deref for ConstValue<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
