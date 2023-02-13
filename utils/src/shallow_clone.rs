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

//! Marker trait for shallow clones

use std::marker::PhantomData;

#[cfg(not(loom))]
use std::sync::Arc;

#[cfg(loom)]
use loom::sync::Arc;

use crate::const_value::ConstValue;

/// Shallow cloning
///
/// This is a trait that is implemented for types that can be cloned without duplicating a state;
/// this applies to references, pointers, and smart pointers, and constants
pub trait ShallowClone: Clone {
    fn shallow_clone(&self) -> Self;
}

// Some impls for types from the standard library
impl<T> ShallowClone for &T {
    fn shallow_clone(&self) -> Self {
        self
    }
}
impl<T> ShallowClone for &[T] {
    fn shallow_clone(&self) -> Self {
        self
    }
}
impl<T> ShallowClone for *const T {
    fn shallow_clone(&self) -> Self {
        *self
    }
}
impl<T> ShallowClone for *mut T {
    fn shallow_clone(&self) -> Self {
        *self
    }
}
impl<T> ShallowClone for std::rc::Rc<T> {
    fn shallow_clone(&self) -> Self {
        self.clone()
    }
}
impl<T> ShallowClone for Arc<T> {
    fn shallow_clone(&self) -> Self {
        self.clone()
    }
}

impl<T> ShallowClone for PhantomData<T> {
    fn shallow_clone(&self) -> Self {
        *self
    }
}

impl<T: Clone> ShallowClone for ConstValue<T> {
    fn shallow_clone(&self) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod impl_checks {
    use super::*;
    use static_assertions::*;

    assert_impl_all!(&u32: ShallowClone);
    assert_impl_all!(&[u32]: ShallowClone);
    assert_impl_all!(&[u32; 10]: ShallowClone);
    assert_impl_all!(std::sync::Arc<Vec<u32>>: ShallowClone);

    assert_not_impl_any!(Vec<u32>: ShallowClone);
    assert_not_impl_any!([u32; 10]: ShallowClone);
}
