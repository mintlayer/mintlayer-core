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

use super::Amount;

// use only unsigned types
// if you need a signed amount, we should create a separate type for it and implement proper conversion
pub type SignedIntType = i128;

/// An unsigned fixed-point type for amounts
/// The smallest unit of count is called an atom
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SignedAmount {
    val: SignedIntType,
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
    pub const MAX: Self = Self::from_atoms(SignedIntType::MAX);

    pub const fn from_atoms(v: SignedIntType) -> Self {
        SignedAmount { val: v }
    }

    pub fn into_atoms(&self) -> SignedIntType {
        self.val
    }

    pub fn from_unsigned(amount: Amount) -> Option<Self> {
        let unsigned_atoms = amount.into_atoms();
        let atoms: SignedIntType = unsigned_atoms.try_into().ok()?;
        Some(Self::from_atoms(atoms))
    }

    pub fn into_unsigned(self) -> Option<Amount> {
        let atoms = self.val;
        let unsigned_atoms: super::amount::UnsignedIntType = atoms.try_into().ok()?;
        Some(Amount::from_atoms(unsigned_atoms))
    }

    pub fn into_fixedpoint_str(self, decimals: u8) -> String {
        let amount_str = self.val.abs().to_string();
        let decimals = decimals as usize;
        let sign = if self.val < 0 { "-" } else { "" };
        if amount_str.len() <= decimals {
            let zeros = "0".repeat(decimals - amount_str.len());
            let result = sign.to_owned() + "0." + &zeros + &amount_str;

            remove_right_most_zeros_and_decimal_point(result)
        } else {
            let ten: SignedIntType = 10;
            let unit = ten.pow(decimals as u32);
            let whole = self.val.abs() / unit;
            let fraction = self.val.abs() % unit;
            let result = format!("{sign}{whole}.{fraction:00$}", decimals as usize);

            remove_right_most_zeros_and_decimal_point(result)
        }
    }

    pub fn from_fixedpoint_str(amount_str: &str, decimals: u8) -> Option<Self> {
        let negative = amount_str.starts_with('-');
        let amount_str = amount_str.strip_prefix('-').unwrap_or(amount_str);

        // in this solution, we exclude SignedAmount::MIN, but we don't really care
        let unsigned_amount = Amount::from_fixedpoint_str(amount_str, decimals)?;
        let signed_amount = unsigned_amount.into_signed()?;
        let signed_atoms = if negative {
            -signed_amount.into_atoms()
        } else {
            signed_amount.into_atoms()
        };
        Some(Self::from_atoms(signed_atoms))
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

impl std::ops::Mul<SignedIntType> for SignedAmount {
    type Output = Option<Self>;

    fn mul(self, other: SignedIntType) -> Option<Self> {
        self.val.checked_mul(other).map(|n| SignedAmount { val: n })
    }
}

impl std::ops::Div<SignedIntType> for SignedAmount {
    type Output = Option<SignedAmount>;

    fn div(self, other: SignedIntType) -> Option<SignedAmount> {
        self.val.checked_div(other).map(|n| SignedAmount { val: n })
    }
}

impl std::ops::Rem<SignedIntType> for SignedAmount {
    type Output = Option<Self>;

    fn rem(self, other: SignedIntType) -> Option<Self> {
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

#[cfg(test)]
mod tests {
    use crate::{amount_sum, primitives::amount::UnsignedIntType};

    use super::*;

    #[test]
    fn creation() {
        let x = SignedAmount::from_atoms(555);
        assert_eq!(x, SignedAmount { val: 555 });

        let y = SignedAmount::from_atoms(123);
        assert_eq!(y, SignedAmount { val: 123 });

        let z = SignedAmount::from_atoms(-123);
        assert_eq!(z, SignedAmount { val: -123 });
    }

    #[test]
    fn add_some() {
        assert_eq!(
            SignedAmount { val: 2 } + SignedAmount { val: 2 },
            Some(SignedAmount { val: 4 })
        );

        assert_eq!(
            SignedAmount { val: 2 } + SignedAmount { val: -3 },
            Some(SignedAmount { val: -1 })
        );
    }

    #[test]
    fn sub_some() {
        assert_eq!(
            SignedAmount { val: -4 } - SignedAmount { val: 2 },
            Some(SignedAmount { val: -6 })
        );

        assert_eq!(
            SignedAmount { val: 4 } - SignedAmount { val: 2 },
            Some(SignedAmount { val: 2 })
        );
    }

    #[test]
    fn mul_some() {
        assert_eq!(SignedAmount { val: 3 } * 3, Some(SignedAmount { val: 9 }));

        assert_eq!(SignedAmount { val: -3 } * 3, Some(SignedAmount { val: -9 }));
    }

    #[test]
    fn div_some() {
        assert_eq!(SignedAmount { val: 9 } / 3, Some(SignedAmount { val: 3 }));

        assert_eq!(SignedAmount { val: 9 } / -3, Some(SignedAmount { val: -3 }));
    }

    #[test]
    fn rem_some() {
        assert_eq!(SignedAmount { val: 9 } % 4, Some(SignedAmount { val: 1 }));

        assert_eq!(SignedAmount { val: -9 } % 4, Some(SignedAmount { val: -1 }));
    }

    #[test]
    fn add_overflow() {
        assert_eq!(
            SignedAmount {
                val: SignedIntType::MAX
            } + SignedAmount { val: 1 },
            None
        );
    }

    #[test]
    fn sum_some() {
        let amounts =
            vec![SignedAmount { val: 1 }, SignedAmount { val: -2 }, SignedAmount { val: -3 }];
        assert_eq!(
            amounts.into_iter().sum::<Option<SignedAmount>>(),
            Some(SignedAmount { val: -4 })
        );
    }

    #[test]
    fn sum_overflow() {
        let amounts = vec![
            SignedAmount { val: 1 },
            SignedAmount { val: 2 },
            SignedAmount {
                val: SignedIntType::MAX - 2,
            },
        ];
        assert_eq!(amounts.into_iter().sum::<Option<SignedAmount>>(), None);
    }

    #[test]
    fn sum_empty() {
        assert_eq!(
            vec![].into_iter().sum::<Option<SignedAmount>>(),
            Some(SignedAmount::from_atoms(0))
        )
    }

    #[test]
    fn sub_underflow() {
        assert_eq!(
            SignedAmount {
                val: SignedIntType::MIN
            } - SignedAmount { val: 1 },
            None
        );
    }

    #[test]
    fn mul_overflow() {
        assert_eq!(
            SignedAmount {
                val: SignedIntType::MAX / 2 + 1
            } * 2,
            None
        );
    }

    #[test]
    fn comparison() {
        assert!(SignedAmount { val: 1 } != SignedAmount { val: 2 });
        assert!(SignedAmount { val: 1 } < SignedAmount { val: 2 });
        assert!(SignedAmount { val: 1 } <= SignedAmount { val: 2 });
        assert!(SignedAmount { val: 2 } <= SignedAmount { val: 2 });
        assert!(SignedAmount { val: 2 } == SignedAmount { val: 2 });
        assert!(SignedAmount { val: 2 } >= SignedAmount { val: 2 });
        assert!(SignedAmount { val: 3 } > SignedAmount { val: 2 });

        assert!(SignedAmount { val: -1 } != SignedAmount { val: -2 });
        assert!(SignedAmount { val: -1 } > SignedAmount { val: -2 });
        assert!(SignedAmount { val: -1 } >= SignedAmount { val: -2 });
        assert!(SignedAmount { val: -2 } >= SignedAmount { val: -2 });
        assert!(SignedAmount { val: -2 } == SignedAmount { val: -2 });
        assert!(SignedAmount { val: -2 } <= SignedAmount { val: -2 });
        assert!(SignedAmount { val: -3 } < SignedAmount { val: -2 });

        assert!(SignedAmount { val: -1 } < SignedAmount { val: 2 });
        assert!(SignedAmount { val: 3 } > SignedAmount { val: -2 });
    }

    #[test]
    fn variadic_sum() {
        assert_eq!(
            amount_sum!(SignedAmount::from_atoms(1), SignedAmount::from_atoms(2)),
            Some(SignedAmount::from_atoms(3))
        );

        assert_eq!(
            amount_sum!(
                SignedAmount::from_atoms(1),
                SignedAmount::from_atoms(2),
                SignedAmount::from_atoms(3)
            ),
            Some(SignedAmount::from_atoms(6))
        );

        assert_eq!(
            amount_sum!(
                SignedAmount::from_atoms(1),
                SignedAmount::from_atoms(2),
                SignedAmount::from_atoms(3),
                SignedAmount::from_atoms(4)
            ),
            Some(SignedAmount::from_atoms(10))
        );

        assert_eq!(
            amount_sum!(
                SignedAmount::from_atoms(SignedIntType::MAX),
                SignedAmount::from_atoms(0)
            ),
            Some(SignedAmount::from_atoms(SignedIntType::MAX))
        );

        assert_eq!(
            amount_sum!(
                SignedAmount::from_atoms(SignedIntType::MAX),
                SignedAmount::from_atoms(1)
            ),
            None
        );

        assert_eq!(
            amount_sum!(
                SignedAmount::from_atoms(SignedIntType::MAX - 1),
                SignedAmount::from_atoms(1),
                SignedAmount::from_atoms(1)
            ),
            None
        );
    }

    #[test]
    fn unsigned_conversion_signed_arbitrary() {
        let amount = SignedAmount::from_atoms(10);
        let unsigned_amount_inner = 10 as UnsignedIntType;
        assert_eq!(
            amount.into_unsigned().unwrap(),
            Amount::from_atoms(unsigned_amount_inner)
        )
    }

    #[test]
    fn unsigned_conversion_signed_max() {
        let amount = SignedAmount::MAX;
        let unsigned_amount_inner = SignedIntType::MAX as UnsignedIntType;
        assert_eq!(
            amount.into_unsigned().unwrap(),
            Amount::from_atoms(unsigned_amount_inner)
        )
    }

    #[test]
    fn unsigned_conversion_signed_negative() {
        let amount = SignedAmount::from_atoms(-10);
        assert!(amount.into_unsigned().is_none())
    }

    #[rustfmt::skip]
    #[test]
    fn from_fixedpoint_8_decimals() {
        assert_eq!(SignedAmount::from_fixedpoint_str("987654321", 8).unwrap(), SignedAmount { val: 98765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("87654321", 8).unwrap(), SignedAmount { val: 8765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("7654321", 8).unwrap(), SignedAmount { val: 765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("654321", 8).unwrap(), SignedAmount { val: 65432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("54321", 8).unwrap(), SignedAmount { val: 5432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("4321", 8).unwrap(), SignedAmount { val: 432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("321", 8).unwrap(), SignedAmount { val: 32100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21", 8).unwrap(), SignedAmount { val: 2100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("1", 8).unwrap(), SignedAmount { val: 100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("1.2", 8).unwrap(), SignedAmount { val: 120000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("1.23", 8).unwrap(), SignedAmount { val: 123000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("1.234", 8).unwrap(), SignedAmount { val: 123400000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("1.2345", 8).unwrap(), SignedAmount { val: 123450000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("1.23456", 8).unwrap(), SignedAmount { val: 123456000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("1.234567", 8).unwrap(), SignedAmount { val: 123456700 });
        assert_eq!(SignedAmount::from_fixedpoint_str("1.2345678", 8).unwrap(), SignedAmount { val: 123456780 });
        assert_eq!(SignedAmount::from_fixedpoint_str("1.23456789", 8).unwrap(), SignedAmount { val: 123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21.23456789", 8).unwrap(), SignedAmount { val: 2123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("321.23456789", 8).unwrap(), SignedAmount { val: 32123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("4321.23456789", 8).unwrap(), SignedAmount { val: 432123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("54321.23456789", 8).unwrap(), SignedAmount { val: 5432123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("654321.23456789", 8).unwrap(), SignedAmount { val: 65432123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("7654321.23456789", 8).unwrap(), SignedAmount { val: 765432123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("87654321.23456789", 8).unwrap(), SignedAmount { val: 8765432123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("987654321.23456789", 8).unwrap(), SignedAmount { val: 98765432123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("1987654321.23456789", 8).unwrap(), SignedAmount { val: 198765432123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.23456789", 8).unwrap(), SignedAmount { val: 2198765432123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.2345678", 8).unwrap(), SignedAmount { val: 2198765432123456780 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.234567", 8).unwrap(), SignedAmount { val: 2198765432123456700 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.23456", 8).unwrap(), SignedAmount { val: 2198765432123456000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.2345", 8).unwrap(), SignedAmount { val: 2198765432123450000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.234", 8).unwrap(), SignedAmount { val: 2198765432123400000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.23", 8).unwrap(), SignedAmount { val: 2198765432123000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.2", 8).unwrap(), SignedAmount { val: 2198765432120000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.", 8).unwrap(), SignedAmount { val: 2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.0", 8).unwrap(), SignedAmount { val: 2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.00", 8).unwrap(), SignedAmount { val: 2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.000", 8).unwrap(), SignedAmount { val: 2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.0000", 8).unwrap(), SignedAmount { val: 2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.00000", 8).unwrap(), SignedAmount { val: 2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.000000", 8).unwrap(), SignedAmount { val: 2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.0000000", 8).unwrap(), SignedAmount { val: 2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.00000000", 8).unwrap(), SignedAmount { val: 2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str(".2", 8).unwrap(), SignedAmount { val: 20000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str(".23", 8).unwrap(), SignedAmount { val: 23000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str(".234", 8).unwrap(), SignedAmount { val: 23400000 });
        assert_eq!(SignedAmount::from_fixedpoint_str(".2345", 8).unwrap(), SignedAmount { val: 23450000 });
        assert_eq!(SignedAmount::from_fixedpoint_str(".23456", 8).unwrap(), SignedAmount { val: 23456000 });
        assert_eq!(SignedAmount::from_fixedpoint_str(".234567", 8).unwrap(), SignedAmount { val: 23456700 });
        assert_eq!(SignedAmount::from_fixedpoint_str(".2345678", 8).unwrap(), SignedAmount { val: 23456780 });
        assert_eq!(SignedAmount::from_fixedpoint_str(".23456789", 8).unwrap(), SignedAmount { val: 23456789 });
        assert!(SignedAmount::from_fixedpoint_str("", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str(" ", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.000000000", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.234567891", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1..234567891", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.234567891,", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.23a4567891,", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.23-4567891", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.23e4567891", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("--21987654321", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-219876-54321", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321-", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str(".", 8).is_none());
    }

    #[rustfmt::skip]
    #[test]
    fn from_fixedpoint_8_decimals_negative() {
        assert_eq!(SignedAmount::from_fixedpoint_str("-987654321", 8).unwrap(), SignedAmount { val: -98765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-87654321", 8).unwrap(), SignedAmount { val: -8765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-7654321", 8).unwrap(), SignedAmount { val: -765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-654321", 8).unwrap(), SignedAmount { val: -65432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-54321", 8).unwrap(), SignedAmount { val: -5432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-4321", 8).unwrap(), SignedAmount { val: -432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-321", 8).unwrap(), SignedAmount { val: -32100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21", 8).unwrap(), SignedAmount { val: -2100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-1", 8).unwrap(), SignedAmount { val: -100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-1.2", 8).unwrap(), SignedAmount { val: -120000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-1.23", 8).unwrap(), SignedAmount { val: -123000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-1.234", 8).unwrap(), SignedAmount { val: -123400000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-1.2345", 8).unwrap(), SignedAmount { val: -123450000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-1.23456", 8).unwrap(), SignedAmount { val: -123456000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-1.234567", 8).unwrap(), SignedAmount { val: -123456700 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-1.2345678", 8).unwrap(), SignedAmount { val: -123456780 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-1.23456789", 8).unwrap(), SignedAmount { val: -123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21.23456789", 8).unwrap(), SignedAmount { val: -2123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-321.23456789", 8).unwrap(), SignedAmount { val: -32123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-4321.23456789", 8).unwrap(), SignedAmount { val: -432123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-54321.23456789", 8).unwrap(), SignedAmount { val: -5432123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-654321.23456789", 8).unwrap(), SignedAmount { val: -65432123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-7654321.23456789", 8).unwrap(), SignedAmount { val: -765432123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-87654321.23456789", 8).unwrap(), SignedAmount { val: -8765432123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-987654321.23456789", 8).unwrap(), SignedAmount { val: -98765432123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-1987654321.23456789", 8).unwrap(), SignedAmount { val: -198765432123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.23456789", 8).unwrap(), SignedAmount { val: -2198765432123456789 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.2345678", 8).unwrap(), SignedAmount { val: -2198765432123456780 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.234567", 8).unwrap(), SignedAmount { val: -2198765432123456700 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.23456", 8).unwrap(), SignedAmount { val: -2198765432123456000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.2345", 8).unwrap(), SignedAmount { val: -2198765432123450000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.234", 8).unwrap(), SignedAmount { val: -2198765432123400000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.23", 8).unwrap(), SignedAmount { val: -2198765432123000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.2", 8).unwrap(), SignedAmount { val: -2198765432120000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.", 8).unwrap(), SignedAmount { val: -2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.0", 8).unwrap(), SignedAmount { val: -2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.00", 8).unwrap(), SignedAmount { val: -2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.000", 8).unwrap(), SignedAmount { val: -2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.0000", 8).unwrap(), SignedAmount { val: -2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.00000", 8).unwrap(), SignedAmount { val: -2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.000000", 8).unwrap(), SignedAmount { val: -2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.0000000", 8).unwrap(), SignedAmount { val: -2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.00000000", 8).unwrap(), SignedAmount { val: -2198765432100000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-.2", 8).unwrap(), SignedAmount { val: -20000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-.23", 8).unwrap(), SignedAmount { val: -23000000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-.234", 8).unwrap(), SignedAmount { val: -23400000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-.2345", 8).unwrap(), SignedAmount { val: -23450000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-.23456", 8).unwrap(), SignedAmount { val: -23456000 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-.234567", 8).unwrap(), SignedAmount { val: -23456700 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-.2345678", 8).unwrap(), SignedAmount { val: -23456780 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-.23456789", 8).unwrap(), SignedAmount { val: -23456789 });
        assert!(SignedAmount::from_fixedpoint_str("-", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("- ", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.000000000", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.234567891", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1..234567891", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.234567891,", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.23a4567891,", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.23-4567891", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.23e4567891", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("--21987654321", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-219876-54321", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321-", 8).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-.", 8).is_none());
    }

    #[rustfmt::skip]
    #[test]
    fn from_fixedpoint_0_decimals() {
        assert_eq!(SignedAmount::from_fixedpoint_str("987654321", 0).unwrap(), SignedAmount { val: 987654321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("87654321", 0).unwrap(), SignedAmount { val: 87654321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("7654321", 0).unwrap(), SignedAmount { val: 7654321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("654321", 0).unwrap(), SignedAmount { val: 654321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("54321", 0).unwrap(), SignedAmount { val: 54321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("4321", 0).unwrap(), SignedAmount { val: 4321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("321", 0).unwrap(), SignedAmount { val: 321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21", 0).unwrap(), SignedAmount { val: 21 });
        assert_eq!(SignedAmount::from_fixedpoint_str("1", 0).unwrap(), SignedAmount { val: 1 });
        assert_eq!(SignedAmount::from_fixedpoint_str("987654321.", 0).unwrap(), SignedAmount { val: 987654321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("87654321.", 0).unwrap(), SignedAmount { val: 87654321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("7654321.", 0).unwrap(), SignedAmount { val: 7654321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("654321.", 0).unwrap(), SignedAmount { val: 654321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("54321.", 0).unwrap(), SignedAmount { val: 54321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("4321.", 0).unwrap(), SignedAmount { val: 4321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("321.", 0).unwrap(), SignedAmount { val: 321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21.", 0).unwrap(), SignedAmount { val: 21 });
        assert_eq!(SignedAmount::from_fixedpoint_str("1.", 0).unwrap(), SignedAmount { val: 1 });
        assert!(SignedAmount::from_fixedpoint_str("1.2", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.23", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.234", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.2345", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.23456", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.234567", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.2345678", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("4321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("54321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("654321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("7654321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("87654321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("987654321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1987654321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.2345678", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.234567", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.23456", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.2345", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.234", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.23", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.2", 0).is_none());
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.", 0).unwrap(), SignedAmount { val: 21987654321 });
        assert!(SignedAmount::from_fixedpoint_str("21987654321.0", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.00", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.000", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.0000", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.00000", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.000000", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.0000000", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.00000000", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str(" ", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.000000000", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.234567891", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1..234567891", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.234567891,", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.23a4567891,", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.23-4567891", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.23e4567891", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("--987654321", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-987654321-", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-987654321-", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-98765-4321", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str(".", 0).is_none());
    }

    #[rustfmt::skip]
    #[test]
    fn from_fixedpoint_0_decimals_negative() {
        assert_eq!(SignedAmount::from_fixedpoint_str("-987654321", 0).unwrap(), SignedAmount { val: -987654321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-87654321", 0).unwrap(), SignedAmount { val: -87654321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-7654321", 0).unwrap(), SignedAmount { val: -7654321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-654321", 0).unwrap(), SignedAmount { val: -654321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-54321", 0).unwrap(), SignedAmount { val: -54321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-4321", 0).unwrap(), SignedAmount { val: -4321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-321", 0).unwrap(), SignedAmount { val: -321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21", 0).unwrap(), SignedAmount { val: -21 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-1", 0).unwrap(), SignedAmount { val: -1 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-987654321.", 0).unwrap(), SignedAmount { val: -987654321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-87654321.", 0).unwrap(), SignedAmount { val: -87654321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-7654321.", 0).unwrap(), SignedAmount { val: -7654321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-654321.", 0).unwrap(), SignedAmount { val: -654321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-54321.", 0).unwrap(), SignedAmount { val: -54321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-4321.", 0).unwrap(), SignedAmount { val: -4321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-321.", 0).unwrap(), SignedAmount { val: -321 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21.", 0).unwrap(), SignedAmount { val: -21 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-1.", 0).unwrap(), SignedAmount { val: -1 });
        assert!(SignedAmount::from_fixedpoint_str("-1.2", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.23", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.234", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.2345", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.23456", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.234567", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.2345678", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-4321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-54321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-654321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-7654321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-87654321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-987654321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1987654321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.23456789", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.2345678", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.234567", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.23456", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.2345", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.234", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.23", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.2", 0).is_none());
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.", 0).unwrap(), SignedAmount { val: -21987654321 });
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.0", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.00", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.000", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.0000", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.00000", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.000000", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.0000000", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.00000000", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("- ", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.000000000", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.234567891", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1..234567891", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.234567891,", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.23a4567891,", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.23-4567891", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.23e4567891", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("--987654321", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-987654321-", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-987654321-", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-98765-4321", 0).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-.", 0).is_none());
    }

    #[rustfmt::skip]
    #[test]
    fn from_fixedpoint_1_decimal() {
        assert_eq!(SignedAmount::from_fixedpoint_str("987654321", 1).unwrap(), SignedAmount { val: 9876543210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("87654321", 1).unwrap(), SignedAmount { val: 876543210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("7654321", 1).unwrap(), SignedAmount { val: 76543210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("654321", 1).unwrap(), SignedAmount { val: 6543210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("54321", 1).unwrap(), SignedAmount { val: 543210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("4321", 1).unwrap(), SignedAmount { val: 43210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("321", 1).unwrap(), SignedAmount { val: 3210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21", 1).unwrap(), SignedAmount { val: 210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("1", 1).unwrap(), SignedAmount { val: 10 });
        assert_eq!(SignedAmount::from_fixedpoint_str("1.2", 1).unwrap(), SignedAmount { val: 12 });
        assert_eq!(SignedAmount::from_fixedpoint_str(".2", 1).unwrap(), SignedAmount { val: 2 });
        assert!(SignedAmount::from_fixedpoint_str("1.23", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.234", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.2345", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.23456", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.234567", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.2345678", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("4321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("54321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("654321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("7654321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("87654321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("987654321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1987654321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.2345678", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.234567", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.23456", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.2345", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.234", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.23", 1).is_none());
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.2", 1).unwrap(), SignedAmount { val: 219876543212 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.", 1).unwrap(), SignedAmount { val: 219876543210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("21987654321.0", 1).unwrap(), SignedAmount { val: 219876543210 });
        assert!(SignedAmount::from_fixedpoint_str("21987654321.00", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.000", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.0000", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.00000", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.000000", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.0000000", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.00000000", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str(" ", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("21987654321.000000000", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.234567891", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1..234567891", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.234567891,", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.23a4567891,", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.23-4567891", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("1.23e4567891", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("--21987654321.0", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("--21987654321.0", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987-654321.0", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.0-", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str(".", 1).is_none());
    }

    #[rustfmt::skip]
    #[test]
    fn from_fixedpoint_1_decimal_negative() {
        assert_eq!(SignedAmount::from_fixedpoint_str("-987654321", 1).unwrap(), SignedAmount { val: -9876543210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-87654321", 1).unwrap(), SignedAmount { val: -876543210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-7654321", 1).unwrap(), SignedAmount { val: -76543210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-654321", 1).unwrap(), SignedAmount { val: -6543210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-54321", 1).unwrap(), SignedAmount { val: -543210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-4321", 1).unwrap(), SignedAmount { val: -43210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-321", 1).unwrap(), SignedAmount { val: -3210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21", 1).unwrap(), SignedAmount { val: -210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-1", 1).unwrap(), SignedAmount { val: -10 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-1.2", 1).unwrap(), SignedAmount { val: -12 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-.2", 1).unwrap(), SignedAmount { val: -2 });
        assert!(SignedAmount::from_fixedpoint_str("-1.23", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.234", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.2345", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.23456", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.234567", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.2345678", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-4321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-54321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-654321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-7654321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-87654321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-987654321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1987654321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.23456789", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.2345678", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.234567", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.23456", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.2345", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.234", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.23", 1).is_none());
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.2", 1).unwrap(), SignedAmount { val: -219876543212 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.", 1).unwrap(), SignedAmount { val: -219876543210 });
        assert_eq!(SignedAmount::from_fixedpoint_str("-21987654321.0", 1).unwrap(), SignedAmount { val: -219876543210 });
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.00", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.000", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.0000", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.00000", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.000000", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.0000000", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.00000000", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("- ", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.000000000", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.234567891", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1..234567891", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.234567891,", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.23a4567891,", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.23-4567891", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-1.23e4567891", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("--21987654321.0", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("--21987654321.0", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987-654321.0", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-21987654321.0-", 1).is_none());
        assert!(SignedAmount::from_fixedpoint_str("-.", 1).is_none());
    }

    #[rustfmt::skip]
    #[test]
    fn to_fixedpoint_8_decimals() {
        assert_eq!(SignedAmount { val: 0 }.into_fixedpoint_str(8), "0");
        assert_eq!(SignedAmount { val: 1 }.into_fixedpoint_str(8), "0.00000001");
        assert_eq!(SignedAmount { val: 12 }.into_fixedpoint_str(8), "0.00000012");
        assert_eq!(SignedAmount { val: 123 }.into_fixedpoint_str(8), "0.00000123");
        assert_eq!(SignedAmount { val: 1234 }.into_fixedpoint_str(8), "0.00001234");
        assert_eq!(SignedAmount { val: 12345 }.into_fixedpoint_str(8), "0.00012345");
        assert_eq!(SignedAmount { val: 123456 }.into_fixedpoint_str(8), "0.00123456");
        assert_eq!(SignedAmount { val: 1234567 }.into_fixedpoint_str(8), "0.01234567");
        assert_eq!(SignedAmount { val: 12345678 }.into_fixedpoint_str(8), "0.12345678");
        assert_eq!(SignedAmount { val: 112345678 }.into_fixedpoint_str(8), "1.12345678");
        assert_eq!(SignedAmount { val: 2112345678 }.into_fixedpoint_str(8), "21.12345678");
        assert_eq!(SignedAmount { val: 32112345678 }.into_fixedpoint_str(8), "321.12345678");
        assert_eq!(SignedAmount { val: 432112345678 }.into_fixedpoint_str(8), "4321.12345678");
        assert_eq!(SignedAmount { val: 5432112345678 }.into_fixedpoint_str(8), "54321.12345678");
        assert_eq!(SignedAmount { val: 65432112345678 }.into_fixedpoint_str(8), "654321.12345678");
        assert_eq!(SignedAmount { val: 765432112345678 }.into_fixedpoint_str(8), "7654321.12345678");
        assert_eq!(SignedAmount { val: 8765432112345678 }.into_fixedpoint_str(8), "87654321.12345678");
        assert_eq!(SignedAmount { val: 98765432112345678 }.into_fixedpoint_str(8), "987654321.12345678");
        assert_eq!(SignedAmount { val: 10 }.into_fixedpoint_str(8), "0.0000001");
        assert_eq!(SignedAmount { val: 120 }.into_fixedpoint_str(8), "0.0000012");
        assert_eq!(SignedAmount { val: 1230 }.into_fixedpoint_str(8), "0.0000123");
        assert_eq!(SignedAmount { val: 12340 }.into_fixedpoint_str(8), "0.0001234");
        assert_eq!(SignedAmount { val: 123450 }.into_fixedpoint_str(8), "0.0012345");
        assert_eq!(SignedAmount { val: 1234560 }.into_fixedpoint_str(8), "0.0123456");
        assert_eq!(SignedAmount { val: 12345670 }.into_fixedpoint_str(8), "0.1234567");
        assert_eq!(SignedAmount { val: 123456780 }.into_fixedpoint_str(8), "1.2345678");
        assert_eq!(SignedAmount { val: 1123456780 }.into_fixedpoint_str(8), "11.2345678");
        assert_eq!(SignedAmount { val: 100 }.into_fixedpoint_str(8), "0.000001");
        assert_eq!(SignedAmount { val: 1200 }.into_fixedpoint_str(8), "0.000012");
        assert_eq!(SignedAmount { val: 12300 }.into_fixedpoint_str(8), "0.000123");
        assert_eq!(SignedAmount { val: 123400 }.into_fixedpoint_str(8), "0.001234");
        assert_eq!(SignedAmount { val: 1234500 }.into_fixedpoint_str(8), "0.012345");
        assert_eq!(SignedAmount { val: 12345600 }.into_fixedpoint_str(8), "0.123456");
        assert_eq!(SignedAmount { val: 123456700 }.into_fixedpoint_str(8), "1.234567");
        assert_eq!(SignedAmount { val: 1234567800 }.into_fixedpoint_str(8), "12.345678");
        assert_eq!(SignedAmount { val: 11234567800 }.into_fixedpoint_str(8), "112.345678");
    }

    #[rustfmt::skip]
    #[test]
    fn to_fixedpoint_8_decimals_negative() {
        assert_eq!(SignedAmount { val: -0 }.into_fixedpoint_str(8), "0");
        assert_eq!(SignedAmount { val: -1 }.into_fixedpoint_str(8), "-0.00000001");
        assert_eq!(SignedAmount { val: -12 }.into_fixedpoint_str(8), "-0.00000012");
        assert_eq!(SignedAmount { val: -123 }.into_fixedpoint_str(8), "-0.00000123");
        assert_eq!(SignedAmount { val: -1234 }.into_fixedpoint_str(8), "-0.00001234");
        assert_eq!(SignedAmount { val: -12345 }.into_fixedpoint_str(8), "-0.00012345");
        assert_eq!(SignedAmount { val: -123456 }.into_fixedpoint_str(8), "-0.00123456");
        assert_eq!(SignedAmount { val: -1234567 }.into_fixedpoint_str(8), "-0.01234567");
        assert_eq!(SignedAmount { val: -12345678 }.into_fixedpoint_str(8), "-0.12345678");
        assert_eq!(SignedAmount { val: -112345678 }.into_fixedpoint_str(8), "-1.12345678");
        assert_eq!(SignedAmount { val: -2112345678 }.into_fixedpoint_str(8), "-21.12345678");
        assert_eq!(SignedAmount { val: -32112345678 }.into_fixedpoint_str(8), "-321.12345678");
        assert_eq!(SignedAmount { val: -432112345678 }.into_fixedpoint_str(8), "-4321.12345678");
        assert_eq!(SignedAmount { val: -5432112345678 }.into_fixedpoint_str(8), "-54321.12345678");
        assert_eq!(SignedAmount { val: -65432112345678 }.into_fixedpoint_str(8), "-654321.12345678");
        assert_eq!(SignedAmount { val: -765432112345678 }.into_fixedpoint_str(8), "-7654321.12345678");
        assert_eq!(SignedAmount { val: -8765432112345678 }.into_fixedpoint_str(8), "-87654321.12345678");
        assert_eq!(SignedAmount { val: -98765432112345678 }.into_fixedpoint_str(8), "-987654321.12345678");
        assert_eq!(SignedAmount { val: -10 }.into_fixedpoint_str(8), "-0.0000001");
        assert_eq!(SignedAmount { val: -120 }.into_fixedpoint_str(8), "-0.0000012");
        assert_eq!(SignedAmount { val: -1230 }.into_fixedpoint_str(8), "-0.0000123");
        assert_eq!(SignedAmount { val: -12340 }.into_fixedpoint_str(8), "-0.0001234");
        assert_eq!(SignedAmount { val: -123450 }.into_fixedpoint_str(8), "-0.0012345");
        assert_eq!(SignedAmount { val: -1234560 }.into_fixedpoint_str(8), "-0.0123456");
        assert_eq!(SignedAmount { val: -12345670 }.into_fixedpoint_str(8), "-0.1234567");
        assert_eq!(SignedAmount { val: -123456780 }.into_fixedpoint_str(8), "-1.2345678");
        assert_eq!(SignedAmount { val: -1123456780 }.into_fixedpoint_str(8), "-11.2345678");
        assert_eq!(SignedAmount { val: -100 }.into_fixedpoint_str(8), "-0.000001");
        assert_eq!(SignedAmount { val: -1200 }.into_fixedpoint_str(8), "-0.000012");
        assert_eq!(SignedAmount { val: -12300 }.into_fixedpoint_str(8), "-0.000123");
        assert_eq!(SignedAmount { val: -123400 }.into_fixedpoint_str(8), "-0.001234");
        assert_eq!(SignedAmount { val: -1234500 }.into_fixedpoint_str(8), "-0.012345");
        assert_eq!(SignedAmount { val: -12345600 }.into_fixedpoint_str(8), "-0.123456");
        assert_eq!(SignedAmount { val: -123456700 }.into_fixedpoint_str(8), "-1.234567");
        assert_eq!(SignedAmount { val: -1234567800 }.into_fixedpoint_str(8), "-12.345678");
        assert_eq!(SignedAmount { val: -11234567800 }.into_fixedpoint_str(8), "-112.345678");
    }

    #[rustfmt::skip]
    #[test]
    fn to_fixedpoint_0_decimals() {
        assert_eq!(SignedAmount { val: 1 }.into_fixedpoint_str(0), "1");
        assert_eq!(SignedAmount { val: 12 }.into_fixedpoint_str(0), "12");
        assert_eq!(SignedAmount { val: 123 }.into_fixedpoint_str(0), "123");
        assert_eq!(SignedAmount { val: 1234 }.into_fixedpoint_str(0), "1234");
        assert_eq!(SignedAmount { val: 12345 }.into_fixedpoint_str(0), "12345");
        assert_eq!(SignedAmount { val: 123456 }.into_fixedpoint_str(0), "123456");
        assert_eq!(SignedAmount { val: 1234567 }.into_fixedpoint_str(0), "1234567");
        assert_eq!(SignedAmount { val: 12345678 }.into_fixedpoint_str(0), "12345678");
        assert_eq!(SignedAmount { val: 123456789 }.into_fixedpoint_str(0), "123456789");
        assert_eq!(SignedAmount { val: 1234567890 }.into_fixedpoint_str(0), "1234567890");
        assert_eq!(SignedAmount { val: 12345678901 }.into_fixedpoint_str(0), "12345678901");
        assert_eq!(SignedAmount { val: 123456789012 }.into_fixedpoint_str(0), "123456789012");
        assert_eq!(SignedAmount { val: 1234567890123 }.into_fixedpoint_str(0), "1234567890123");
        assert_eq!(SignedAmount { val: 10 }.into_fixedpoint_str(0), "10");
        assert_eq!(SignedAmount { val: 120 }.into_fixedpoint_str(0), "120");
        assert_eq!(SignedAmount { val: 1230 }.into_fixedpoint_str(0), "1230");
        assert_eq!(SignedAmount { val: 12340 }.into_fixedpoint_str(0), "12340");
        assert_eq!(SignedAmount { val: 123450 }.into_fixedpoint_str(0), "123450");
        assert_eq!(SignedAmount { val: 1234560 }.into_fixedpoint_str(0), "1234560");
        assert_eq!(SignedAmount { val: 12345670 }.into_fixedpoint_str(0), "12345670");
        assert_eq!(SignedAmount { val: 123456780 }.into_fixedpoint_str(0), "123456780");
        assert_eq!(SignedAmount { val: 1234567890 }.into_fixedpoint_str(0), "1234567890");
        assert_eq!(SignedAmount { val: 12345678900 }.into_fixedpoint_str(0), "12345678900");
        assert_eq!(SignedAmount { val: 123456789010 }.into_fixedpoint_str(0), "123456789010");
        assert_eq!(SignedAmount { val: 1234567890120 }.into_fixedpoint_str(0), "1234567890120");
        assert_eq!(SignedAmount { val: 12345678901230 }.into_fixedpoint_str(0), "12345678901230");
        assert_eq!(SignedAmount { val: 100 }.into_fixedpoint_str(0), "100");
        assert_eq!(SignedAmount { val: 1200 }.into_fixedpoint_str(0), "1200");
        assert_eq!(SignedAmount { val: 12300 }.into_fixedpoint_str(0), "12300");
        assert_eq!(SignedAmount { val: 123400 }.into_fixedpoint_str(0), "123400");
        assert_eq!(SignedAmount { val: 1234500 }.into_fixedpoint_str(0), "1234500");
        assert_eq!(SignedAmount { val: 12345600 }.into_fixedpoint_str(0), "12345600");
        assert_eq!(SignedAmount { val: 123456700 }.into_fixedpoint_str(0), "123456700");
        assert_eq!(SignedAmount { val: 1234567800 }.into_fixedpoint_str(0), "1234567800");
        assert_eq!(SignedAmount { val: 12345678900 }.into_fixedpoint_str(0), "12345678900");
        assert_eq!(SignedAmount { val: 123456789000 }.into_fixedpoint_str(0), "123456789000");
        assert_eq!(SignedAmount { val: 1234567890100 }.into_fixedpoint_str(0), "1234567890100");
        assert_eq!(SignedAmount { val: 12345678901200 }.into_fixedpoint_str(0), "12345678901200");
        assert_eq!(SignedAmount { val: 123456789012300 }.into_fixedpoint_str(0), "123456789012300");

    }

    #[rustfmt::skip]
    #[test]
    fn to_fixedpoint_0_decimals_negative() {
        assert_eq!(SignedAmount { val: -1 }.into_fixedpoint_str(0), "-1");
        assert_eq!(SignedAmount { val: -12 }.into_fixedpoint_str(0), "-12");
        assert_eq!(SignedAmount { val: -123 }.into_fixedpoint_str(0), "-123");
        assert_eq!(SignedAmount { val: -1234 }.into_fixedpoint_str(0), "-1234");
        assert_eq!(SignedAmount { val: -12345 }.into_fixedpoint_str(0), "-12345");
        assert_eq!(SignedAmount { val: -123456 }.into_fixedpoint_str(0), "-123456");
        assert_eq!(SignedAmount { val: -1234567 }.into_fixedpoint_str(0), "-1234567");
        assert_eq!(SignedAmount { val: -12345678 }.into_fixedpoint_str(0), "-12345678");
        assert_eq!(SignedAmount { val: -123456789 }.into_fixedpoint_str(0), "-123456789");
        assert_eq!(SignedAmount { val: -1234567890 }.into_fixedpoint_str(0), "-1234567890");
        assert_eq!(SignedAmount { val: -12345678901 }.into_fixedpoint_str(0), "-12345678901");
        assert_eq!(SignedAmount { val: -123456789012 }.into_fixedpoint_str(0), "-123456789012");
        assert_eq!(SignedAmount { val: -1234567890123 }.into_fixedpoint_str(0), "-1234567890123");
        assert_eq!(SignedAmount { val: -10 }.into_fixedpoint_str(0), "-10");
        assert_eq!(SignedAmount { val: -120 }.into_fixedpoint_str(0), "-120");
        assert_eq!(SignedAmount { val: -1230 }.into_fixedpoint_str(0), "-1230");
        assert_eq!(SignedAmount { val: -12340 }.into_fixedpoint_str(0), "-12340");
        assert_eq!(SignedAmount { val: -123450 }.into_fixedpoint_str(0), "-123450");
        assert_eq!(SignedAmount { val: -1234560 }.into_fixedpoint_str(0), "-1234560");
        assert_eq!(SignedAmount { val: -12345670 }.into_fixedpoint_str(0), "-12345670");
        assert_eq!(SignedAmount { val: -123456780 }.into_fixedpoint_str(0), "-123456780");
        assert_eq!(SignedAmount { val: -1234567890 }.into_fixedpoint_str(0), "-1234567890");
        assert_eq!(SignedAmount { val: -12345678900 }.into_fixedpoint_str(0), "-12345678900");
        assert_eq!(SignedAmount { val: -123456789010 }.into_fixedpoint_str(0), "-123456789010");
        assert_eq!(SignedAmount { val: -1234567890120 }.into_fixedpoint_str(0), "-1234567890120");
        assert_eq!(SignedAmount { val: -12345678901230 }.into_fixedpoint_str(0), "-12345678901230");
        assert_eq!(SignedAmount { val: -100 }.into_fixedpoint_str(0), "-100");
        assert_eq!(SignedAmount { val: -1200 }.into_fixedpoint_str(0), "-1200");
        assert_eq!(SignedAmount { val: -12300 }.into_fixedpoint_str(0), "-12300");
        assert_eq!(SignedAmount { val: -123400 }.into_fixedpoint_str(0), "-123400");
        assert_eq!(SignedAmount { val: -1234500 }.into_fixedpoint_str(0), "-1234500");
        assert_eq!(SignedAmount { val: -12345600 }.into_fixedpoint_str(0), "-12345600");
        assert_eq!(SignedAmount { val: -123456700 }.into_fixedpoint_str(0), "-123456700");
        assert_eq!(SignedAmount { val: -1234567800 }.into_fixedpoint_str(0), "-1234567800");
        assert_eq!(SignedAmount { val: -12345678900 }.into_fixedpoint_str(0), "-12345678900");
        assert_eq!(SignedAmount { val: -123456789000 }.into_fixedpoint_str(0), "-123456789000");
        assert_eq!(SignedAmount { val: -1234567890100 }.into_fixedpoint_str(0), "-1234567890100");
        assert_eq!(SignedAmount { val: -12345678901200 }.into_fixedpoint_str(0), "-12345678901200");
        assert_eq!(SignedAmount { val: -123456789012300 }.into_fixedpoint_str(0), "-123456789012300");

    }

    #[rustfmt::skip]
    #[test]
    fn to_fixedpoint_1_decimal() {
        assert_eq!(SignedAmount { val: 1 }.into_fixedpoint_str(1), "0.1");
        assert_eq!(SignedAmount { val: 12 }.into_fixedpoint_str(1), "1.2");
        assert_eq!(SignedAmount { val: 123 }.into_fixedpoint_str(1), "12.3");
        assert_eq!(SignedAmount { val: 1234 }.into_fixedpoint_str(1), "123.4");
        assert_eq!(SignedAmount { val: 12345 }.into_fixedpoint_str(1), "1234.5");
        assert_eq!(SignedAmount { val: 123456 }.into_fixedpoint_str(1), "12345.6");
        assert_eq!(SignedAmount { val: 1234567 }.into_fixedpoint_str(1), "123456.7");
        assert_eq!(SignedAmount { val: 12345678 }.into_fixedpoint_str(1), "1234567.8");
        assert_eq!(SignedAmount { val: 123456789 }.into_fixedpoint_str(1), "12345678.9");
        assert_eq!(SignedAmount { val: 1234567890 }.into_fixedpoint_str(1), "123456789");
        assert_eq!(SignedAmount { val: 12345678901 }.into_fixedpoint_str(1), "1234567890.1");
        assert_eq!(SignedAmount { val: 123456789012 }.into_fixedpoint_str(1), "12345678901.2");
        assert_eq!(SignedAmount { val: 1234567890123 }.into_fixedpoint_str(1), "123456789012.3");
        assert_eq!(SignedAmount { val: 10 }.into_fixedpoint_str(1), "1");
        assert_eq!(SignedAmount { val: 120 }.into_fixedpoint_str(1), "12");
        assert_eq!(SignedAmount { val: 1230 }.into_fixedpoint_str(1), "123");
        assert_eq!(SignedAmount { val: 12340 }.into_fixedpoint_str(1), "1234");
        assert_eq!(SignedAmount { val: 123450 }.into_fixedpoint_str(1), "12345");
        assert_eq!(SignedAmount { val: 1234560 }.into_fixedpoint_str(1), "123456");
        assert_eq!(SignedAmount { val: 12345670 }.into_fixedpoint_str(1), "1234567");
        assert_eq!(SignedAmount { val: 123456780 }.into_fixedpoint_str(1), "12345678");
        assert_eq!(SignedAmount { val: 1234567890 }.into_fixedpoint_str(1), "123456789");
        assert_eq!(SignedAmount { val: 12345678900 }.into_fixedpoint_str(1), "1234567890");
        assert_eq!(SignedAmount { val: 123456789010 }.into_fixedpoint_str(1), "12345678901");
        assert_eq!(SignedAmount { val: 1234567890120 }.into_fixedpoint_str(1), "123456789012");
        assert_eq!(SignedAmount { val: 12345678901230 }.into_fixedpoint_str(1), "1234567890123");
        assert_eq!(SignedAmount { val: 100 }.into_fixedpoint_str(1), "10");
        assert_eq!(SignedAmount { val: 1200 }.into_fixedpoint_str(1), "120");
        assert_eq!(SignedAmount { val: 12300 }.into_fixedpoint_str(1), "1230");
        assert_eq!(SignedAmount { val: 123400 }.into_fixedpoint_str(1), "12340");
        assert_eq!(SignedAmount { val: 1234500 }.into_fixedpoint_str(1), "123450");
        assert_eq!(SignedAmount { val: 12345600 }.into_fixedpoint_str(1), "1234560");
        assert_eq!(SignedAmount { val: 123456700 }.into_fixedpoint_str(1), "12345670");
        assert_eq!(SignedAmount { val: 1234567800 }.into_fixedpoint_str(1), "123456780");
        assert_eq!(SignedAmount { val: 12345678900 }.into_fixedpoint_str(1), "1234567890");
        assert_eq!(SignedAmount { val: 123456789000 }.into_fixedpoint_str(1), "12345678900");
        assert_eq!(SignedAmount { val: 1234567890100 }.into_fixedpoint_str(1), "123456789010");
        assert_eq!(SignedAmount { val: 12345678901200 }.into_fixedpoint_str(1), "1234567890120");
        assert_eq!(SignedAmount { val: 123456789012300 }.into_fixedpoint_str(1), "12345678901230");
    }

    #[rustfmt::skip]
    #[test]
    fn to_fixedpoint_1_decimal_negative() {
        assert_eq!(SignedAmount { val: -1 }.into_fixedpoint_str(1), "-0.1");
        assert_eq!(SignedAmount { val: -12 }.into_fixedpoint_str(1), "-1.2");
        assert_eq!(SignedAmount { val: -123 }.into_fixedpoint_str(1), "-12.3");
        assert_eq!(SignedAmount { val: -1234 }.into_fixedpoint_str(1), "-123.4");
        assert_eq!(SignedAmount { val: -12345 }.into_fixedpoint_str(1), "-1234.5");
        assert_eq!(SignedAmount { val: -123456 }.into_fixedpoint_str(1), "-12345.6");
        assert_eq!(SignedAmount { val: -1234567 }.into_fixedpoint_str(1), "-123456.7");
        assert_eq!(SignedAmount { val: -12345678 }.into_fixedpoint_str(1), "-1234567.8");
        assert_eq!(SignedAmount { val: -123456789 }.into_fixedpoint_str(1), "-12345678.9");
        assert_eq!(SignedAmount { val: -1234567890 }.into_fixedpoint_str(1), "-123456789");
        assert_eq!(SignedAmount { val: -12345678901 }.into_fixedpoint_str(1), "-1234567890.1");
        assert_eq!(SignedAmount { val: -123456789012 }.into_fixedpoint_str(1), "-12345678901.2");
        assert_eq!(SignedAmount { val: -1234567890123 }.into_fixedpoint_str(1), "-123456789012.3");
        assert_eq!(SignedAmount { val: -10 }.into_fixedpoint_str(1), "-1");
        assert_eq!(SignedAmount { val: -120 }.into_fixedpoint_str(1), "-12");
        assert_eq!(SignedAmount { val: -1230 }.into_fixedpoint_str(1), "-123");
        assert_eq!(SignedAmount { val: -12340 }.into_fixedpoint_str(1), "-1234");
        assert_eq!(SignedAmount { val: -123450 }.into_fixedpoint_str(1), "-12345");
        assert_eq!(SignedAmount { val: -1234560 }.into_fixedpoint_str(1), "-123456");
        assert_eq!(SignedAmount { val: -12345670 }.into_fixedpoint_str(1), "-1234567");
        assert_eq!(SignedAmount { val: -123456780 }.into_fixedpoint_str(1), "-12345678");
        assert_eq!(SignedAmount { val: -1234567890 }.into_fixedpoint_str(1), "-123456789");
        assert_eq!(SignedAmount { val: -12345678900 }.into_fixedpoint_str(1), "-1234567890");
        assert_eq!(SignedAmount { val: -123456789010 }.into_fixedpoint_str(1), "-12345678901");
        assert_eq!(SignedAmount { val: -1234567890120 }.into_fixedpoint_str(1), "-123456789012");
        assert_eq!(SignedAmount { val: -12345678901230 }.into_fixedpoint_str(1), "-1234567890123");
        assert_eq!(SignedAmount { val: -100 }.into_fixedpoint_str(1), "-10");
        assert_eq!(SignedAmount { val: -1200 }.into_fixedpoint_str(1), "-120");
        assert_eq!(SignedAmount { val: -12300 }.into_fixedpoint_str(1), "-1230");
        assert_eq!(SignedAmount { val: -123400 }.into_fixedpoint_str(1), "-12340");
        assert_eq!(SignedAmount { val: -1234500 }.into_fixedpoint_str(1), "-123450");
        assert_eq!(SignedAmount { val: -12345600 }.into_fixedpoint_str(1), "-1234560");
        assert_eq!(SignedAmount { val: -123456700 }.into_fixedpoint_str(1), "-12345670");
        assert_eq!(SignedAmount { val: -1234567800 }.into_fixedpoint_str(1), "-123456780");
        assert_eq!(SignedAmount { val: -12345678900 }.into_fixedpoint_str(1), "-1234567890");
        assert_eq!(SignedAmount { val: -123456789000 }.into_fixedpoint_str(1), "-12345678900");
        assert_eq!(SignedAmount { val: -1234567890100 }.into_fixedpoint_str(1), "-123456789010");
        assert_eq!(SignedAmount { val: -12345678901200 }.into_fixedpoint_str(1), "-1234567890120");
        assert_eq!(SignedAmount { val: -123456789012300 }.into_fixedpoint_str(1), "-12345678901230");
    }
}
