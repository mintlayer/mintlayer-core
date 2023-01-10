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

/// Shallow cloning
///
/// This is a marker trait that signifies that the `clone` method performs a shallow clone. I.e.
/// `Self` is some sort of reference, smart pointer or handle and cloning it just duplicates the
/// handle without cloning the contents.
pub trait ShallowClone: Clone {}

// Some impls for types from the standard library
impl<T> ShallowClone for &T {}
impl<T> ShallowClone for &[T] {}
impl<T> ShallowClone for *const T {}
impl<T> ShallowClone for *mut T {}
impl<T> ShallowClone for std::rc::Rc<T> {}
impl<T> ShallowClone for std::sync::Arc<T> {}

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
