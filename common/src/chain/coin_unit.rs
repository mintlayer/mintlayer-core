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

use std::str::FromStr;

use crate::primitives::Amount;

/// Represents a certain amount of coins.
/// An atom is the smallest, non-divisible, unit of the currency in the protocol.
/// A coin is the smallest, non-fractional, unit of the currency in the protocol.
/// Given a fixed number of decimals, call it DECIMALS, a coin is equal to 10^DECIMALS atom units.
#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Debug)]
pub struct CoinUnit(Amount);

impl CoinUnit {
    /// Number of decimal digits used to represent the coin
    pub const DECIMALS: u8 = 11;
    /// Number of atoms in 1 coin
    pub const ATOMS_PER_COIN: u128 = 10u128.pow(Self::DECIMALS as u32);
    /// Zero coins
    pub const ZERO: Self = Self(Amount::from_atoms(0));
    /// Maximum representable amount of coins
    pub const MAX: Self = Self(Amount::MAX);

    /// Construct from the number atom units
    pub const fn from_atoms(n: u128) -> Self {
        Self(Amount::from_atoms(n))
    }

    /// Construct from the number of coins
    pub const fn from_coins(n: u64) -> Self {
        // Since the argument is u64 and number of atoms in 1 coin is <= u64::MAX,
        // the result is guaranteed to fit into the internal representation of Amount (u128)
        static_assertions::const_assert!(CoinUnit::ATOMS_PER_COIN <= u64::MAX as u128);
        Self(Amount::from_atoms(n as u128 * CoinUnit::ATOMS_PER_COIN))
    }

    /// Convert the number of atoms to Amount
    pub const fn to_amount_atoms(self) -> Amount {
        self.0
    }
}

impl std::ops::Add for CoinUnit {
    type Output = Option<Self>;
    fn add(self, rhs: Self) -> Option<Self> {
        (self.0 + rhs.0).map(Self)
    }
}

impl std::ops::Sub for CoinUnit {
    type Output = Option<Self>;
    fn sub(self, rhs: Self) -> Option<Self> {
        (self.0 - rhs.0).map(Self)
    }
}

impl std::ops::Mul<u128> for CoinUnit {
    type Output = Option<Self>;
    fn mul(self, rhs: u128) -> Option<Self> {
        (self.0 * rhs).map(Self)
    }
}

impl std::fmt::Display for CoinUnit {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0.into_fixedpoint_str(CoinUnit::DECIMALS))
    }
}

/// Coin amount parsing error
#[derive(Eq, PartialEq, Clone, Debug, thiserror::Error)]
pub enum ParseCoinUnitError {
    #[error("Coin amount parsing error")]
    ParsingNumbericAmountFromStrFailed,
}

impl FromStr for CoinUnit {
    type Err = ParseCoinUnitError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Amount::from_fixedpoint_str(s, CoinUnit::DECIMALS)
            .ok_or(ParseCoinUnitError::ParsingNumbericAmountFromStrFailed)
            .map(CoinUnit)
    }
}
