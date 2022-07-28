// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Describe the database schema at type level

/// Describes single key-value map
pub trait DBIndex {
    /// Index name.
    const NAME: &'static str;

    /// Expected size of values in the map. May be used for storage optimization.
    const SIZE_HINT: core::ops::Range<usize> = 0..usize::MAX;

    /// Whether this maps keys to single or multiple values.
    type Kind: MapKind;
}

/// What constitutes a valid database schema
pub trait Schema: internal::Sealed {}

impl Schema for () {}

impl<DBIdx: DBIndex, Rest: Schema> Schema for (DBIdx, Rest) {}

/// Require given schema to contain given index
pub trait HasDBIndex<DBIdx: DBIndex, I>: Schema {}
impl<DBIdx: DBIndex, Rest: Schema> HasDBIndex<DBIdx, ()> for (DBIdx, Rest) {}
impl<DBIdx: DBIndex, Head: DBIndex, Rest: HasDBIndex<DBIdx, I>, I> HasDBIndex<DBIdx, (I,)>
    for (Head, Rest)
{
}

/// Marker for key-value maps
pub struct Single;
/// Marker for key-multivalue maps
pub struct Multi;

/// Specifies map kind, either [Single] or [Multi].
pub trait MapKind {}
impl MapKind for Single {}
impl MapKind for Multi {}

mod internal {
    use super::*;

    // This is to prevent the Schema trait from being implemented on new types.
    pub trait Sealed {}
    impl Sealed for () {}
    impl<DBIdx: DBIndex, Rest: Schema> Sealed for (DBIdx, Rest) {}
}

#[macro_export]
macro_rules! decl_schema {
    (
        $svis:vis $schema:ident {
            $($vis:vis $name:ident: $mul:ident),* $(,)?
        }
    ) => {
        $(
            #[doc = concat!("Database index: ", stringify!($name))]
            $vis struct $name;
            impl $crate::schema::DBIndex for $name {
                const NAME: &'static str = stringify!($name);
                type Kind = $crate::schema::$mul;
            }
        )*
        $svis type $schema = $crate::decl_schema!(@LIST $($name)*);
    };
    (@LIST) => { () };
    (@LIST $head:ident $($tail:ident)*) => { ($head, $crate::decl_schema!(@LIST $($tail)*)) };
}

#[cfg(test)]
mod test {
    use super::*;

    decl_schema! {
        MySchema {
            DBIdx1: Single,
            DBIdx2: Single,
        }
    }

    fn is_schema<T: Schema>() -> bool {
        true
    }

    #[test]
    fn test_is_schema() {
        // we are just interested this compiles
        assert!(is_schema::<MySchema>());
    }
}
