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

// use only unsigned types
// if you need a signed amount, we should create a separate type for it and implement proper conversion

#![allow(clippy::eq_op)]

use serialization::{Decode, Encode};
use std::iter::Sum;

pub mod decimal;
pub mod signed;

pub use decimal::{DecimalAmount, DisplayAmount};
pub use signed::SignedAmount;

pub type UnsignedIntType = u128;

/// An unsigned fixed-point type for amounts
/// The smallest unit of count is called an atom
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
#[must_use]
pub struct Amount {
    #[codec(compact)]
    atoms: UnsignedIntType,
}

impl Amount {
    pub const MAX: Self = Self::from_atoms(UnsignedIntType::MAX);
    pub const ZERO: Self = Self::from_atoms(0);

    pub const fn from_atoms(v: UnsignedIntType) -> Self {
        Amount { atoms: v }
    }

    pub const fn into_atoms(&self) -> UnsignedIntType {
        self.atoms
    }

    pub fn from_signed(amount: SignedAmount) -> Option<Self> {
        let signed_atoms = amount.into_atoms();
        let atoms: UnsignedIntType = signed_atoms.try_into().ok()?;
        Some(Self::from_atoms(atoms))
    }

    pub fn into_signed(self) -> Option<SignedAmount> {
        let atoms = self.atoms;
        let signed_atoms: signed::SignedIntType = atoms.try_into().ok()?;
        Some(SignedAmount::from_atoms(signed_atoms))
    }

    pub fn into_fixedpoint_str(self, decimals: u8) -> String {
        DecimalAmount::from_amount_minimal(self, decimals).to_string()
    }

    pub fn from_fixedpoint_str(amount_str: &str, decimals: u8) -> Option<Self> {
        amount_str.parse::<DecimalAmount>().ok()?.to_amount(decimals)
    }

    pub fn abs_diff(self, other: Amount) -> Amount {
        if self > other {
            (self - other).expect("cannot be negative")
        } else {
            (other - self).expect("cannot be negative")
        }
    }
}

impl std::ops::Add for Amount {
    type Output = Option<Self>;

    fn add(self, other: Self) -> Option<Self> {
        self.atoms.checked_add(other.atoms).map(|n| Amount { atoms: n })
    }
}

impl std::ops::Sub for Amount {
    type Output = Option<Self>;

    fn sub(self, other: Self) -> Option<Self> {
        self.atoms.checked_sub(other.atoms).map(|n| Amount { atoms: n })
    }
}

impl std::ops::Mul<UnsignedIntType> for Amount {
    type Output = Option<Self>;

    fn mul(self, other: UnsignedIntType) -> Option<Self> {
        self.atoms.checked_mul(other).map(|n| Amount { atoms: n })
    }
}

impl std::ops::Div<UnsignedIntType> for Amount {
    type Output = Option<Amount>;

    fn div(self, other: UnsignedIntType) -> Option<Amount> {
        self.atoms.checked_div(other).map(|n| Amount { atoms: n })
    }
}

impl std::ops::Rem<UnsignedIntType> for Amount {
    type Output = Option<Self>;

    fn rem(self, other: UnsignedIntType) -> Option<Self> {
        self.atoms.checked_rem(other).map(|n| Amount { atoms: n })
    }
}

impl std::ops::BitAnd for Amount {
    type Output = Self;

    fn bitand(self, other: Self) -> Self {
        Amount {
            atoms: self.atoms.bitand(other.atoms),
        }
    }
}

impl std::ops::BitAndAssign for Amount {
    fn bitand_assign(&mut self, other: Self) {
        self.atoms.bitand_assign(other.atoms)
    }
}

impl std::ops::BitOr for Amount {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Amount {
            atoms: self.atoms.bitor(other.atoms),
        }
    }
}

impl std::ops::BitOrAssign for Amount {
    fn bitor_assign(&mut self, other: Self) {
        self.atoms.bitor_assign(other.atoms)
    }
}

impl std::ops::BitXor for Amount {
    type Output = Self;

    fn bitxor(self, other: Self) -> Self {
        Amount {
            atoms: self.atoms.bitxor(other.atoms),
        }
    }
}

impl std::ops::BitXorAssign for Amount {
    fn bitxor_assign(&mut self, other: Self) {
        self.atoms.bitxor_assign(other.atoms)
    }
}

impl std::ops::Not for Amount {
    type Output = Self;

    fn not(self) -> Self {
        Amount {
            atoms: self.atoms.not(),
        }
    }
}

impl std::ops::Shl<u32> for Amount {
    type Output = Option<Self>;

    fn shl(self, other: u32) -> Option<Self> {
        self.atoms.checked_shl(other).map(|v| Amount { atoms: v })
    }
}

impl std::ops::Shr<u32> for Amount {
    type Output = Option<Self>;

    fn shr(self, other: u32) -> Option<Self> {
        self.atoms.checked_shr(other).map(|v| Amount { atoms: v })
    }
}

impl Sum<Amount> for Option<Amount> {
    fn sum<I>(mut iter: I) -> Self
    where
        I: Iterator<Item = Amount>,
    {
        iter.try_fold(Amount::ZERO, std::ops::Add::add)
    }
}

impl rpc_description::HasValueHint for Amount {
    const HINT: rpc_description::ValueHint =
        rpc_description::ValueHint::Object(&[("atoms", &rpc_description::ValueHint::STRING)]);
}

#[macro_export]
macro_rules! amount_sum {
    ($arg_1:expr, $($arg_n:expr),+) => {{
        let result = Some($arg_1);
        $(
            let result = match result {
                Some(v) => v + $arg_n,
                None => None,
            };
        )*
        result
    }}
}

mod json {
    use super::{Amount, UnsignedIntType};

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    enum StringOrUint {
        String(String),
        UInt(UnsignedIntType),
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct JsonAmount {
        atoms: StringOrUint,
    }

    impl From<Amount> for JsonAmount {
        fn from(amount: Amount) -> Self {
            JsonAmount {
                atoms: StringOrUint::String(amount.atoms.to_string()),
            }
        }
    }

    impl TryFrom<JsonAmount> for Amount {
        type Error = Box<dyn std::error::Error>;

        fn try_from(json_amount: JsonAmount) -> Result<Self, Self::Error> {
            let atoms: UnsignedIntType = match json_amount.atoms {
                StringOrUint::String(s) => s.parse()?,
                StringOrUint::UInt(atoms) => atoms,
            };
            Ok(Amount { atoms })
        }
    }
}

impl serde::Serialize for Amount {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let json_amount: json::JsonAmount = (*self).into();
        json_amount.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Amount {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;

        let json_amount = json::JsonAmount::deserialize(deserializer)?;

        let amount: Amount = json_amount
            .try_into()
            .map_err(|e| D::Error::custom(format!("Failed to parse json amount to Amount: {e}")))?;

        Ok(amount)
    }
}

#[cfg(test)]
mod tests;
