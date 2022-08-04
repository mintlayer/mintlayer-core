// Copyright (c) 2021 RBB S.r.l
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
//
// Author(s): L. Kuklinek

//! Various uncategorised utilities

/// Implements standard indexing methods for a given wrapper type
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

macro_rules! display_from_debug {
    ($thing:ident) => {
        impl ::core::fmt::Display for $thing {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> Result<(), ::core::fmt::Error> {
                ::core::fmt::Debug::fmt(self, f)
            }
        }
    };
}

#[cfg(test)]
macro_rules! hex_script {
    ($s:expr) => {
        Script::from(Vec::from(hex!($s)))
    };
}

// Export some hash functions.
pub use crypto::hash;

pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    hash::hash::<hash::Ripemd160, _>(data).into()
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    hash::hash::<hash::Sha1, _>(data).into()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    hash::hash::<hash::Sha256, _>(data).into()
}

pub fn hash256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}
