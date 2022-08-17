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

//! Describe the database schema at type level

pub use storage_core::{info::MapDesc, DbIndex};

/// Describes single key-value map
pub trait DbMap: 'static {
    /// Map name.
    const NAME: &'static str;

    /// Expected size of values in the map. May be used for storage optimization.
    const SIZE_HINT: core::ops::Range<usize> = 0..usize::MAX;

    /// Whether this maps keys to single or multiple values.
    type Kind: MapKind;
}

/// What constitutes a valid database schema
pub trait Schema: internal::Sealed + 'static {
    type DescIter: Iterator<Item = MapDesc>;
    fn desc_iter() -> Self::DescIter;
}

impl Schema for () {
    type DescIter = std::iter::Empty<MapDesc>;
    fn desc_iter() -> Self::DescIter {
        std::iter::empty()
    }
}

impl<M: DbMap, Rest: Schema> Schema for (M, Rest) {
    type DescIter = std::iter::Chain<std::iter::Once<MapDesc>, Rest::DescIter>;
    fn desc_iter() -> Self::DescIter {
        let map_desc = MapDesc {
            name: M::NAME,
            size_hint: M::SIZE_HINT,
        };
        std::iter::once(map_desc).chain(Rest::desc_iter())
    }
}

/// Require a schema to contain given map (identified by a type tag)
pub trait HasDbMap<M: DbMap, I>: Schema {
    /// Index of the map in the schema
    const INDEX: DbIndex;
}
impl<M: DbMap, Rest: Schema> HasDbMap<M, ()> for (M, Rest) {
    const INDEX: DbIndex = DbIndex::new(0);
}
impl<M: DbMap, Head: DbMap, Rest: HasDbMap<M, I>, I> HasDbMap<M, (I,)> for (Head, Rest) {
    const INDEX: DbIndex = DbIndex::new(Rest::INDEX.get() + 1);
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
    impl<DBIdx: DbMap, Rest: Schema> Sealed for (DBIdx, Rest) {}
}

#[macro_export]
macro_rules! decl_schema {
    (
        $svis:vis $schema:ident {
            $($vis:vis $name:ident: $mul:ident),* $(,)?
        }
    ) => {
        $(
            #[doc = concat!("Database map: `", stringify!($name), "`")]
            $vis struct $name;
            impl $crate::schema::DbMap for $name {
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
            DBIdx0: Single,
            DBIdx1: Single,
            DBIdx2: Single,
        }
    }

    #[test]
    fn schema() {
        // Check calculated column indices
        assert_eq!(<MySchema as HasDbMap<DBIdx0, _>>::INDEX, DbIndex::new(0));
        assert_eq!(<MySchema as HasDbMap<DBIdx1, _>>::INDEX, DbIndex::new(1));
        assert_eq!(<MySchema as HasDbMap<DBIdx2, _>>::INDEX, DbIndex::new(2));
    }
}
