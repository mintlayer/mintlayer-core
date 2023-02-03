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

pub use storage_core::{DbMapDesc, DbMapId};

/// Describes single key-value map
pub trait DbMap: 'static {
    /// Map name.
    const NAME: &'static str;

    /// Expected size of values in the map. May be used for storage optimization.
    const SIZE_HINT: core::ops::Range<usize> = 0..usize::MAX;

    /// Type of keys in the map
    type Key: serialization::Codec;

    /// Type of values stored in the map
    type Value: serialization::Codec;
}

/// What constitutes a valid database schema
pub trait Schema: internal::Sealed + 'static {
    type DescIter: Iterator<Item = DbMapDesc>;
    fn desc_iter() -> Self::DescIter;
}

impl Schema for () {
    type DescIter = std::iter::Empty<DbMapDesc>;
    fn desc_iter() -> Self::DescIter {
        std::iter::empty()
    }
}

impl<M: DbMap, Rest: Schema> Schema for (M, Rest) {
    type DescIter = std::iter::Chain<std::iter::Once<DbMapDesc>, Rest::DescIter>;
    fn desc_iter() -> Self::DescIter {
        let map_desc = DbMapDesc {
            name: M::NAME.to_string(),
            size_hint: M::SIZE_HINT,
        };
        std::iter::once(map_desc).chain(Rest::desc_iter())
    }
}

/// Require a schema to contain given map (identified by a type tag)
pub trait HasDbMap<M: DbMap, I>: Schema {
    /// Index of the map in the schema
    const INDEX: DbMapId;
}
impl<M: DbMap, Rest: Schema> HasDbMap<M, ()> for (M, Rest) {
    const INDEX: DbMapId = DbMapId::new(0);
}
impl<M: DbMap, Head: DbMap, Rest: HasDbMap<M, I>, I> HasDbMap<M, (I,)> for (Head, Rest) {
    const INDEX: DbMapId = DbMapId::new(Rest::INDEX.as_usize() + 1);
}

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
        $(#[$sch_attrs:meta])* $sch_vis:vis $schema:ident {
            $($(#[$map_attrs:meta])* $map_vis:vis $name:ident: Map<$key:ty, $val:ty>),* $(,)?
        }
    ) => {
        $(
            $(#[$map_attrs])*
            #[doc = concat!("\n\nDatabase map ", $crate::decl_schema!(@DOC $name: $key, $val))]
            $map_vis struct $name;
            impl $crate::schema::DbMap for $name {
                const NAME: &'static str = stringify!($name);
                type Key = $key;
                type Value = $val;
            }
        )*

        $(#[$sch_attrs])*
        #[doc = concat!("\n\nDatabase schema `", stringify!($schema), "`\n\n")]
        #[doc = "## Key-value mappings"]
        #[doc = concat!($("* ", $crate::decl_schema!(@DOC $name: $key, $val), "\n"),*)]
        $sch_vis type $schema = $crate::decl_schema!(@LIST $($name)*);
    };
    (@LIST) => { () };
    (@LIST $head:ident $($tail:ident)*) => { ($head, $crate::decl_schema!(@LIST $($tail)*)) };
    (@DOC $name:ident: $key:ty, $val:ty) => {
        concat!("[`", stringify!($name), "`]`: ", stringify!($key), " -> ", stringify!($val), "`")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    decl_schema! {
        MySchema {
            DBIdx0: Map<u8, u16>,
            DBIdx1: Map<u8, u32>,
            DBIdx2: Map<u8, u64>,
        }
    }

    #[test]
    fn schema() {
        // Check calculated column indices
        assert_eq!(<MySchema as HasDbMap<DBIdx0, _>>::INDEX, DbMapId::new(0));
        assert_eq!(<MySchema as HasDbMap<DBIdx1, _>>::INDEX, DbMapId::new(1));
        assert_eq!(<MySchema as HasDbMap<DBIdx2, _>>::INDEX, DbMapId::new(2));
    }
}
