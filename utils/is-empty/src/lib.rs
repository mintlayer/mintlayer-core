// Copyright (c) 2026 RBB S.r.l
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

// The derive macro expands to `::is_empty::IsEmpty`, which would not resolve inside this crate
// itself. This alias makes that path work here too, so the trait can be derived in our own tests.
extern crate self as is_empty;

pub use is_empty_derive::IsEmpty;

/// The interface for checking whether a value is "empty".
///
/// This is mainly meant to be derived for aggregate types (see the `IsEmpty` derive macro), where
/// a value is empty when all of its fields are empty. Deriving it instead of writing `is_empty` by
/// hand means a newly added field can't be silently left out of the check.
pub trait IsEmpty {
    /// Returns `true` if the value is empty.
    fn is_empty(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[derive(IsEmpty)]
    struct Aggregate {
        a: BTreeMap<u32, u32>,
        b: Vec<u32>,
        c: String,
    }

    #[test]
    fn empty_when_all_fields_are_empty() {
        let value = Aggregate {
            a: BTreeMap::new(),
            b: Vec::new(),
            c: String::new(),
        };
        assert!(value.is_empty());
    }

    #[test]
    fn not_empty_when_any_field_is_not_empty() {
        let with_map = Aggregate {
            a: BTreeMap::from([(1, 1)]),
            b: Vec::new(),
            c: String::new(),
        };
        assert!(!with_map.is_empty());

        let with_vec = Aggregate {
            a: BTreeMap::new(),
            b: vec![1],
            c: String::new(),
        };
        assert!(!with_vec.is_empty());

        let with_string = Aggregate {
            a: BTreeMap::new(),
            b: Vec::new(),
            c: "x".to_owned(),
        };
        assert!(!with_string.is_empty());
    }

    #[test]
    fn tuple_struct_is_empty_uses_all_fields() {
        #[derive(IsEmpty)]
        struct Pair(Vec<u32>, String);

        assert!(Pair(Vec::new(), String::new()).is_empty());
        assert!(!Pair(vec![1], String::new()).is_empty());
    }

    #[test]
    fn unit_struct_is_always_empty() {
        #[derive(IsEmpty)]
        struct Unit;

        assert!(Unit.is_empty());
    }

    // The generated impl names the trait by its full path, so deriving through a path qualified
    // macro works without the trait being imported, and picks the right trait even if another one
    // of the same name happens to be in scope.
    mod trait_not_in_scope {
        // Deliberately not importing the trait here.

        #[derive(super::super::IsEmpty)]
        struct Aggregate {
            a: Vec<u32>,
        }

        // A decoy that would be picked up if the generated impl named the trait unqualified.
        trait IsEmpty {
            fn is_empty(&self) -> bool;
        }

        fn assert_impls<T: crate::IsEmpty>(value: &T) -> bool {
            value.is_empty()
        }

        #[test]
        fn derives_the_trait_from_its_own_crate() {
            assert!(assert_impls(&Aggregate { a: Vec::new() }));
            assert!(!assert_impls(&Aggregate { a: vec![1] }));
        }
    }
}
