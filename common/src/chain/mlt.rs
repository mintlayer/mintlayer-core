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

/// Represents a certain amount of MLT.
#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Debug)]
pub struct Mlt(Amount);

impl Mlt {
    /// Number of decimal digits used to represent MLT
    pub const DECIMALS: u8 = 11;
    /// Number of atoms in 1 MLT
    pub const ATOMS_PER_MLT: u128 = 10u128.pow(Self::DECIMALS as u32);
    /// Zero MLTs
    pub const ZERO: Self = Self(Amount::from_atoms(0));
    /// Maximum representable amount of MLTs
    pub const MAX: Self = Self(Amount::MAX);

    /// Construct from the number atomic units
    pub const fn from_atoms(n: u128) -> Self {
        Self(Amount::from_atoms(n))
    }

    /// Construct from the number of MLTs
    pub const fn from_mlt(n: u64) -> Self {
        // Since the argument is u64 and number of atoms in 1 MLT is <= u64::MAX,
        // the result is guaranteed to fit into the internal representation of Amount (u128)
        static_assertions::const_assert!(Mlt::ATOMS_PER_MLT <= u64::MAX as u128);
        Self(Amount::from_atoms(n as u128 * Mlt::ATOMS_PER_MLT))
    }

    /// Convert the number of atoms to Amount
    pub const fn to_amount_atoms(self) -> Amount {
        self.0
    }
}

impl std::ops::Add for Mlt {
    type Output = Option<Self>;
    fn add(self, rhs: Self) -> Option<Self> {
        (self.0 + rhs.0).map(Self)
    }
}

impl std::ops::Sub for Mlt {
    type Output = Option<Self>;
    fn sub(self, rhs: Self) -> Option<Self> {
        (self.0 - rhs.0).map(Self)
    }
}

impl std::ops::Mul<u128> for Mlt {
    type Output = Option<Self>;
    fn mul(self, rhs: u128) -> Option<Self> {
        (self.0 * rhs).map(Self)
    }
}

impl std::fmt::Display for Mlt {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0.into_fixedpoint_str(Mlt::DECIMALS))
    }
}

/// MLT amount parsing error
#[derive(Eq, PartialEq, Clone, Debug, thiserror::Error)]
pub enum ParseMltError {
    // TODO we need better error reporting from Amount::from_fixedpoint_str
    #[error("MLT amount parsing error")]
    Unknown,
}

impl FromStr for Mlt {
    type Err = ParseMltError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Amount::from_fixedpoint_str(s, Mlt::DECIMALS)
            .ok_or(ParseMltError::Unknown)
            .map(Mlt)
    }
}
