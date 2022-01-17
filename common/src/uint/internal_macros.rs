// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

/// Implements standard array methods for a given wrapper type
#[macro_export]
macro_rules! impl_array_newtype {
    ($thing:ident, $ty:ty, $len:expr) => {
        impl $thing {
            #[inline]
            /// Converts the object to a raw pointer
            pub fn as_ptr(&self) -> *const $ty {
                let &$thing(ref dat) = self;
                dat.as_ptr()
            }

            #[inline]
            /// Converts the object to a mutable raw pointer
            pub fn as_mut_ptr(&mut self) -> *mut $ty {
                let &mut $thing(ref mut dat) = self;
                dat.as_mut_ptr()
            }

            #[inline]
            /// Returns the length of the object as an array
            pub fn len(&self) -> usize {
                $len
            }

            #[inline]
            /// Returns whether the object, as an array, is empty. Always false.
            pub fn is_empty(&self) -> bool {
                false
            }

            #[inline]
            /// Returns the underlying bytes.
            pub fn as_bytes(&self) -> &[$ty; $len] {
                &self.0
            }

            #[inline]
            /// Returns the underlying bytes.
            pub fn to_bytes(&self) -> [$ty; $len] {
                self.0.clone()
            }

            #[inline]
            /// Returns the underlying bytes.
            pub fn into_bytes(self) -> [$ty; $len] {
                self.0
            }
        }

        impl<'a> ::core::convert::From<&'a [$ty]> for $thing {
            fn from(data: &'a [$ty]) -> $thing {
                assert_eq!(data.len(), $len);
                let mut ret = [0; $len];
                ret.copy_from_slice(&data[..]);
                $thing(ret)
            }
        }

        impl_index_newtype!($thing, $ty);
    };
}

/// Implements standard indexing methods for a given wrapper type
#[macro_export]
macro_rules! impl_index_newtype {
    ($thing:ident, $ty:ty) => {
        impl ::core::ops::Index<usize> for $thing {
            type Output = $ty;

            #[inline]
            fn index(&self, index: usize) -> &$ty {
                &self.0[index]
            }
        }

        impl ::core::ops::Index<::core::ops::Range<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::core::ops::Range<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::core::ops::Index<::core::ops::RangeTo<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::core::ops::RangeTo<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::core::ops::Index<::core::ops::RangeFrom<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::core::ops::RangeFrom<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::core::ops::Index<::core::ops::RangeFull> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, _: ::core::ops::RangeFull) -> &[$ty] {
                &self.0[..]
            }
        }
    };
}
