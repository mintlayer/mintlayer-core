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

use std::fmt::{Debug, Display};

use crate::{Uint256, Uint512};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Rational<T> {
    numer: T,
    denom: T,
}

impl<T> Rational<T> {
    pub const fn new(numer: T, denom: T) -> Self {
        // TODO: find a way to move this check to compile time;
        //       at the moment static_assertions doesn't work with type parameters
        assert!(std::mem::size_of::<T>() * 2 <= std::mem::size_of::<Uint512>());
        Self { numer, denom }
    }

    pub fn numer(&self) -> &T {
        &self.numer
    }

    pub fn denom(&self) -> &T {
        &self.denom
    }
}

trait ComparableType {}

impl ComparableType for u64 {}
impl ComparableType for u128 {}
impl ComparableType for Uint256 {}

// Comparing a/b and c/d is equivalent to comparing a*d and b*c.
// Only works for types that can be converted to Uint512 to handle overflow on multiplication.
impl<T: Into<Uint512> + ComparableType + Ord + Copy> Ord for Rational<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.denom == other.denom {
            return self.numer.cmp(&other.numer);
        }

        if self.numer == other.numer {
            return other.denom.cmp(&self.denom);
        }

        let self_numer_big: Uint512 = self.numer.into();
        let self_denom_big: Uint512 = self.denom.into();

        let other_numer_big: Uint512 = other.numer.into();
        let other_denom_big: Uint512 = other.denom.into();

        (self_numer_big * other_denom_big).cmp(&(other_numer_big * self_denom_big))
    }
}

impl<T: Into<Uint512> + ComparableType + Ord + Copy> PartialOrd for Rational<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl From<Rational<u128>> for Rational<Uint256> {
    fn from(other: Rational<u128>) -> Self {
        Self::new(other.numer.into(), other.denom.into())
    }
}

impl<T: Display> Display for Rational<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} / {}", self.numer(), self.denom())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use randomness::Rng;
    use rstest::rstest;
    use test_utils::random::Seed;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn check_comparison_against_num(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let a1 = rng.gen_range(1..u128::MAX);
        let a2 = rng.gen_range(1..u128::MAX);
        let b1 = rng.gen_range(1..u128::MAX);
        let b2 = rng.gen_range(1..u128::MAX);

        let expected =
            num::rational::Ratio::<u128>::new_raw(a1, a2)
                .cmp(&num::rational::Ratio::<u128>::new_raw(b1, b2));

        let actual = Rational::new(a1, a2).cmp(&Rational::new(b1, b2));

        assert_eq!(expected, actual);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn check_overflow(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let a = Rational::new(
            Uint256::MAX,
            Uint256::from_u128(rng.gen_range(1..u128::MAX)),
        );
        let b = Rational::new(
            Uint256::from_u128(rng.gen_range(1..u128::MAX)),
            Uint256::MAX,
        );

        assert!(a > b);
    }

    #[test]
    #[should_panic]
    fn check_overflow_type() {
        Rational::new(Uint512::MAX, Uint512::MAX);
    }
}
