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

#![allow(clippy::eq_op)]

use std::iter::Sum;

// use only unsigned types
// if you need a signed amount, we should create a separate type for it and implement proper conversion
pub type IntType = i128;

/// An unsigned fixed-point type for amounts
/// The smallest unit of count is called an atom
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SignedAmount {
    val: IntType,
}

fn remove_right_most_zeros_and_decimal_point(s: String) -> String {
    let point_pos = s.chars().position(|c| c == '.');
    if point_pos.is_none() {
        return s;
    }
    let s = s.trim_end_matches('0');
    let s = s.trim_end_matches('.');
    s.to_owned()
}

impl SignedAmount {
    pub const MAX: Self = Self::from_atoms(IntType::MAX);

    pub const fn from_atoms(v: IntType) -> Self {
        SignedAmount { val: v }
    }

    pub fn into_atoms(&self) -> IntType {
        self.val
    }

    pub fn into_fixedpoint_str(self, decimals: u8) -> String {
        let amount_str = self.val.to_string();
        let decimals = decimals as usize;
        let sign = if self.val < 0 { "-" } else { "" };
        if amount_str.len() <= decimals {
            let zeros = "0".repeat(decimals - amount_str.len());
            let result = sign.to_owned() + "0." + &zeros + &amount_str;

            remove_right_most_zeros_and_decimal_point(result)
        } else {
            let ten: IntType = 10;
            let unit = ten.pow(decimals as u32);
            let whole = self.val / unit;
            let fraction = self.val % unit;
            let result = format!("{sign}{whole}.{fraction:00$}", decimals as usize);

            remove_right_most_zeros_and_decimal_point(result)
        }
    }

    pub fn from_fixedpoint_str(amount_str: &str, decimals: u8) -> Option<Self> {
        let decimals = decimals as usize;
        let amount_str = amount_str.trim_matches(' '); // trim spaces
        let amount_str = amount_str.replace('_', "");

        // empty not allowed
        if amount_str.is_empty() {
            return None;
        }
        // too long
        if amount_str.len() > 100 {
            return None;
        }
        // must be only numbers or decimal point
        if !amount_str.chars().all(|c| char::is_numeric(c) || c == '.' || c == '-') {
            return None;
        }

        #[allow(clippy::if_same_then_else)]
        if amount_str.matches('.').count() > 1 {
            // only 1 decimal point allowed
            None
        } else if amount_str.matches('-').count() > 1 {
            None
        } else if amount_str.contains('-') && !amount_str.starts_with('-') {
            None
        } else if amount_str.matches('.').count() == 0 {
            // if there is no decimal point, then just add N zeros to the right and we're done
            let zeros = "0".repeat(decimals);
            let amount_str = amount_str + &zeros;

            amount_str.parse::<IntType>().ok().map(|v| SignedAmount { val: v })
        } else {
            // if there's 1 decimal point, split, join the numbers, then add zeros to the right
            let amount_split = amount_str.split('.').collect::<Vec<&str>>();
            debug_assert!(amount_split.len() == 2); // we already checked we have 1 decimal exactly
            if amount_split[1].len() > decimals {
                // there cannot be more decimals than the assumed amount
                return None;
            }
            let zeros = "0".repeat(decimals - amount_split[1].len());
            let atoms_str = amount_split[0].to_owned() + amount_split[1] + &zeros;
            let atoms_str = atoms_str.trim_start_matches('0');

            atoms_str.parse::<IntType>().ok().map(|v| SignedAmount { val: v })
        }
    }
}

impl std::ops::Add for SignedAmount {
    type Output = Option<Self>;

    fn add(self, other: Self) -> Option<Self> {
        self.val.checked_add(other.val).map(|n| SignedAmount { val: n })
    }
}

impl std::ops::Sub for SignedAmount {
    type Output = Option<Self>;

    fn sub(self, other: Self) -> Option<Self> {
        self.val.checked_sub(other.val).map(|n| SignedAmount { val: n })
    }
}

impl std::ops::Mul<IntType> for SignedAmount {
    type Output = Option<Self>;

    fn mul(self, other: IntType) -> Option<Self> {
        self.val.checked_mul(other).map(|n| SignedAmount { val: n })
    }
}

impl std::ops::Div<IntType> for SignedAmount {
    type Output = Option<SignedAmount>;

    fn div(self, other: IntType) -> Option<SignedAmount> {
        self.val.checked_div(other).map(|n| SignedAmount { val: n })
    }
}

impl std::ops::Rem<IntType> for SignedAmount {
    type Output = Option<Self>;

    fn rem(self, other: IntType) -> Option<Self> {
        self.val.checked_rem(other).map(|n| SignedAmount { val: n })
    }
}

impl Sum<SignedAmount> for Option<SignedAmount> {
    fn sum<I>(mut iter: I) -> Self
    where
        I: Iterator<Item = SignedAmount>,
    {
        iter.try_fold(SignedAmount::from_atoms(0), std::ops::Add::add)
    }
}
