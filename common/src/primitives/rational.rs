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

use crate::{Uint256, Uint512};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Rational<T> {
    numer: T,
    denom: T,
}

impl<T> Rational<T> {
    pub const fn new(numer: T, denom: T) -> Self {
        Self { numer, denom }
    }

    pub fn numer(&self) -> &T {
        &self.numer
    }

    pub fn denom(&self) -> &T {
        &self.denom
    }
}

trait ComparableTypes {}

impl ComparableTypes for u64 {}
impl ComparableTypes for u128 {}
impl ComparableTypes for Uint256 {}

// Comparing a/b and c/d is equivalent to comparing a*d and b*c.
// Only works for types that can be converted to Uint512 to handle overflow on multiplication.
impl<T: Into<Uint512> + ComparableTypes + Ord + Copy> Ord for Rational<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.denom == other.denom {
            return self.numer.cmp(&other.numer);
        }

        if self.numer == other.numer {
            return self.denom.cmp(&other.denom).reverse();
        }

        let self_numer_big: Uint512 = self.numer.into();
        let self_denom_big: Uint512 = self.denom.into();

        let other_numer_big: Uint512 = other.numer.into();
        let other_denom_big: Uint512 = other.denom.into();

        (self_numer_big * other_denom_big).cmp(&(other_numer_big * self_denom_big))
    }
}

impl<T: Into<Uint512> + ComparableTypes + Ord + Copy> PartialOrd for Rational<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_u64() {
        let a = Rational::new(2u64, 3u64);
        let b = Rational::new(3u64, 4u64);

        assert!(a < b);
    }

    #[test]
    fn compare_u128() {
        let a = Rational::new(2u128, 3u128);
        let b = Rational::new(3u128, 4u128);

        assert!(a < b);
    }

    #[test]
    fn compare_u256() {
        let a = Rational::new(Uint256::MAX, Uint256::MAX);
        let b = Rational::new(Uint256::MAX, Uint256::MAX);

        assert!(a == b);
    }

    //FIXME: more tests
}
