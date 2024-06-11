// Copyright (c) 2021-2024 RBB S.r.l
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

use common::uint::endian::{
    slice_to_u16_be, slice_to_u32_be, slice_to_u64_be, u16_to_array_be, u32_to_array_be,
    u64_to_array_be,
};
use serialization::{Decode, Encode, Input};

/// A wrapper for a value whose `Encode`d representation has the same ordering as the wrapped type
/// itself.
#[derive(Eq, PartialEq, Ord, PartialOrd, Debug, Clone, Copy)]
pub struct OrderPreservingValue<T>(T);

impl<T: Wrappable> OrderPreservingValue<T> {
    pub fn new(val: T) -> Self {
        Self(val)
    }

    pub fn inner(&self) -> T {
        self.0
    }
}

pub trait Wrappable: Copy {}

impl<T: internal::Sealed + Copy> Wrappable for T {}

mod internal {
    pub trait Sealed {}
}

// Note: for unsigned integers, the big-endian representation has the same ordering as
// the number itself.
macro_rules! impl_encode_decode_for_unsigned_int {
    ($type: ty, $to_be_func: ident, $from_be_func: ident) => {
        impl Encode for OrderPreservingValue<$type> {
            fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
                f($to_be_func(self.0).as_slice())
            }
        }

        impl Decode for OrderPreservingValue<$type> {
            fn decode<I: Input>(input: &mut I) -> Result<Self, serialization::Error> {
                let mut dest = [0u8; ::core::mem::size_of::<$type>()];
                input.read(&mut dest)?;
                Ok(Self($from_be_func(&dest)))
            }
        }

        impl internal::Sealed for $type {}
    };
}

impl_encode_decode_for_unsigned_int!(u16, u16_to_array_be, slice_to_u16_be);
impl_encode_decode_for_unsigned_int!(u32, u32_to_array_be, slice_to_u32_be);
impl_encode_decode_for_unsigned_int!(u64, u64_to_array_be, slice_to_u64_be);

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use rstest::rstest;

    use test_utils::random::{
        make_seedable_rng,
        randomness::{self, distributions::Distribution},
        Rng, Seed,
    };

    use super::*;

    fn test_one_type<T>(rng: &mut impl Rng)
    where
        T: Ord + Debug + Wrappable,
        OrderPreservingValue<T>: Encode + Decode,
        randomness::distributions::Standard: Distribution<T>,
    {
        let val16_1 = OrderPreservingValue::new(rng.gen::<T>());
        let val16_2 = OrderPreservingValue::new(rng.gen::<T>());
        let val16_1_encoded = val16_1.encode();
        let val16_2_encoded = val16_2.encode();

        let val16_1_decoded =
            OrderPreservingValue::decode(&mut val16_1_encoded.as_slice()).unwrap();
        assert_eq!(val16_1_decoded, val16_1);

        let val16_2_decoded =
            OrderPreservingValue::decode(&mut val16_2_encoded.as_slice()).unwrap();
        assert_eq!(val16_2_decoded, val16_2);

        let cmp1 = val16_1.cmp(&val16_2);
        let cmp2 = val16_1.inner().cmp(&val16_2.inner());
        let cmp3 = val16_1_encoded.cmp(&val16_2_encoded);

        assert_eq!(cmp1, cmp2);
        assert_eq!(cmp1, cmp3);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        for _ in 0..100 {
            test_one_type::<u16>(&mut rng);
            test_one_type::<u32>(&mut rng);
            test_one_type::<u64>(&mut rng);
        }
    }
}
