#![allow(clippy::eq_op)]

use serialization::{Decode, Encode};
use std::iter::Sum;

// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach

// use only unsigned types
// if you need a signed amount, we should create a separate type for it and implement proper conversion
pub type IntType = u128;

/// An unsigned fixed-point type for amounts
/// The smallest unit of count is called an atom
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct Amount {
    #[codec(compact)]
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

impl Amount {
    pub fn from_atoms(v: IntType) -> Self {
        Amount { val: v }
    }

    pub fn into_atoms(&self) -> IntType {
        self.val
    }

    pub fn into_fixedpoint_str(self, decimals: u8) -> String {
        let amount_str = self.val.to_string();
        let decimals = decimals as usize;
        if amount_str.len() <= decimals {
            let zeros = "0".repeat(decimals - amount_str.len());
            let result = "0.".to_owned() + &zeros + &amount_str;

            remove_right_most_zeros_and_decimal_point(result)
        } else {
            let ten: IntType = 10;
            let unit = ten.pow(decimals as u32);
            let whole = self.val / unit;
            let fraction = self.val % unit;
            let result = format!("{whole}.{fraction:00$}", decimals as usize);

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
        if !amount_str.chars().all(|c| char::is_numeric(c) || c == '.') {
            return None;
        }

        if amount_str.matches('.').count() > 1 {
            // only 1 decimal point allowed
            None
        } else if amount_str.matches('.').count() == 0 {
            // if there is no decimal point, then just add N zeros to the right and we're done
            let zeros = "0".repeat(decimals);
            let amount_str = amount_str + &zeros;

            amount_str.parse::<IntType>().ok().map(|v| Amount { val: v })
        } else {
            // if there's 1 decomal point, split, join the numbers, then add zeros to the right
            let amount_split = amount_str.split('.').collect::<Vec<&str>>();
            debug_assert!(amount_split.len() == 2); // we already checked we have 1 decimal exactly
            if amount_split[1].len() > decimals {
                // there cannot be more decimals than the assumed amount
                return None;
            }
            let zeros = "0".repeat(decimals - amount_split[1].len());
            let atoms_str = amount_split[0].to_owned() + amount_split[1] + &zeros;
            let atoms_str = atoms_str.trim_start_matches('0');

            atoms_str.parse::<IntType>().ok().map(|v| Amount { val: v })
        }
    }
}

impl std::ops::Add for Amount {
    type Output = Option<Self>;

    fn add(self, other: Self) -> Option<Self> {
        self.val.checked_add(other.val).map(|n| Amount { val: n })
    }
}

impl std::ops::Sub for Amount {
    type Output = Option<Self>;

    fn sub(self, other: Self) -> Option<Self> {
        self.val.checked_sub(other.val).map(|n| Amount { val: n })
    }
}

impl std::ops::Mul<IntType> for Amount {
    type Output = Option<Self>;

    fn mul(self, other: IntType) -> Option<Self> {
        self.val.checked_mul(other).map(|n| Amount { val: n })
    }
}

impl std::ops::Div<IntType> for Amount {
    type Output = Option<Amount>;

    fn div(self, other: IntType) -> Option<Amount> {
        self.val.checked_div(other).map(|n| Amount { val: n })
    }
}

impl std::ops::Rem<IntType> for Amount {
    type Output = Option<Self>;

    fn rem(self, other: IntType) -> Option<Self> {
        self.val.checked_rem(other).map(|n| Amount { val: n })
    }
}

impl std::ops::BitAnd for Amount {
    type Output = Self;

    fn bitand(self, other: Self) -> Self {
        Amount {
            val: self.val.bitand(other.val),
        }
    }
}

impl std::ops::BitAndAssign for Amount {
    fn bitand_assign(&mut self, other: Self) {
        self.val.bitand_assign(other.val)
    }
}

impl std::ops::BitOr for Amount {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Amount {
            val: self.val.bitor(other.val),
        }
    }
}

impl std::ops::BitOrAssign for Amount {
    fn bitor_assign(&mut self, other: Self) {
        self.val.bitor_assign(other.val)
    }
}

impl std::ops::BitXor for Amount {
    type Output = Self;

    fn bitxor(self, other: Self) -> Self {
        Amount {
            val: self.val.bitxor(other.val),
        }
    }
}

impl std::ops::BitXorAssign for Amount {
    fn bitxor_assign(&mut self, other: Self) {
        self.val.bitxor_assign(other.val)
    }
}

impl std::ops::Not for Amount {
    type Output = Self;

    fn not(self) -> Self {
        Amount {
            val: self.val.not(),
        }
    }
}

impl std::ops::Shl<u32> for Amount {
    type Output = Option<Self>;

    fn shl(self, other: u32) -> Option<Self> {
        self.val.checked_shl(other).map(|v| Amount { val: v })
    }
}

impl std::ops::Shr<u32> for Amount {
    type Output = Option<Self>;

    fn shr(self, other: u32) -> Option<Self> {
        self.val.checked_shr(other).map(|v| Amount { val: v })
    }
}

impl Sum<Amount> for Option<Amount> {
    fn sum<I>(mut iter: I) -> Self
    where
        I: Iterator<Item = Amount>,
    {
        iter.try_fold(Amount::from_atoms(0), std::ops::Add::add)
    }
}

#[macro_export]
macro_rules! amount_sum {
    ($($args:expr),+) => {{
        let result = Some(Amount::from_atoms(0));
        $(
            let result = match result {
                Some(v) => v + $args,
                None => None,
            };
        )*
        result
    }}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation() {
        let x = Amount::from_atoms(555);
        assert_eq!(x, Amount { val: 555 });

        let y = Amount::from_atoms(123);
        assert_eq!(y, Amount { val: 123 });
    }

    #[test]
    fn add_some() {
        assert_eq!(
            Amount { val: 2 } + Amount { val: 2 },
            Some(Amount { val: 4 })
        );
    }

    #[test]
    fn sub_some() {
        assert_eq!(
            Amount { val: 4 } - Amount { val: 2 },
            Some(Amount { val: 2 })
        );
    }

    #[test]
    fn mul_some() {
        assert_eq!(Amount { val: 3 } * 3, Some(Amount { val: 9 }));
    }

    #[test]
    fn div_some() {
        assert_eq!(Amount { val: 9 } / 3, Some(Amount { val: 3 }));
    }

    #[test]
    fn rem_some() {
        assert_eq!(Amount { val: 9 } % 4, Some(Amount { val: 1 }));
    }

    #[test]
    fn add_overflow() {
        assert_eq!(Amount { val: IntType::MAX } + Amount { val: 1 }, None);
    }

    #[test]
    fn sub_underflow() {
        assert_eq!(Amount { val: IntType::MIN } - Amount { val: 1 }, None);
    }

    #[test]
    fn mul_overflow() {
        assert_eq!(
            Amount {
                val: IntType::MAX / 2 + 1
            } * 2,
            None
        );
    }

    #[test]
    fn comparison() {
        assert!(Amount { val: 1 } != Amount { val: 2 });
        assert!(Amount { val: 1 } < Amount { val: 2 });
        assert!(Amount { val: 1 } <= Amount { val: 2 });
        assert!(Amount { val: 2 } <= Amount { val: 2 });
        assert!(Amount { val: 2 } == Amount { val: 2 });
        assert!(Amount { val: 2 } >= Amount { val: 2 });
        assert!(Amount { val: 3 } > Amount { val: 2 });
    }

    #[test]
    fn bit_ops() {
        let x = Amount { val: 5 };
        let y = Amount { val: 1 };
        let z = Amount { val: 2 };
        let zero: IntType = 0;
        assert_eq!(x | y, Amount { val: 5 });
        assert_eq!(x & z, Amount { val: 0 });
        assert_eq!(x ^ y, Amount { val: 4 });
        assert!(!zero == IntType::MAX);
    }

    #[test]
    fn bit_ops_assign() {
        let mut x = Amount { val: 5 };

        x ^= Amount { val: 1 };
        assert_eq!(x, Amount { val: 4 });

        x |= Amount { val: 2 };
        assert_eq!(x, Amount { val: 6 });

        x &= Amount { val: 5 };
        assert_eq!(x, Amount { val: 4 });
    }

    #[test]
    fn bit_shifts() {
        let x = Amount { val: 1 };
        assert_eq!(x << 1, Some(Amount { val: 2 }));
        assert_eq!(x << 2, Some(Amount { val: 4 }));
        assert_eq!(x << 4, Some(Amount { val: 16 }));
        assert_eq!(x << 6, Some(Amount { val: 64 }));

        let y = Amount { val: 128 };
        assert_eq!(y >> 1, Some(Amount { val: 64 }));
        assert_eq!(y >> 2, Some(Amount { val: 32 }));
        assert_eq!(y >> 4, Some(Amount { val: 8 }));
        assert_eq!(y >> 6, Some(Amount { val: 2 }));
    }

    #[test]
    fn variadic_sum() {
        assert_eq!(
            amount_sum!(Amount::from_atoms(1), Amount::from_atoms(2)),
            Some(Amount::from_atoms(3))
        );

        assert_eq!(
            amount_sum!(
                Amount::from_atoms(1),
                Amount::from_atoms(2),
                Amount::from_atoms(3)
            ),
            Some(Amount::from_atoms(6))
        );

        assert_eq!(
            amount_sum!(
                Amount::from_atoms(1),
                Amount::from_atoms(2),
                Amount::from_atoms(3),
                Amount::from_atoms(4)
            ),
            Some(Amount::from_atoms(10))
        );

        assert_eq!(
            amount_sum!(Amount::from_atoms(IntType::MAX)),
            Some(Amount::from_atoms(IntType::MAX))
        );

        assert_eq!(
            amount_sum!(Amount::from_atoms(IntType::MAX), Amount::from_atoms(1)),
            None
        );

        assert_eq!(
            amount_sum!(
                Amount::from_atoms(IntType::MAX - 1),
                Amount::from_atoms(1),
                Amount::from_atoms(1)
            ),
            None
        );
    }

    #[rustfmt::skip]
    #[test]
    fn from_fixedpoint_8_decimals() {
        assert_eq!(Amount::from_fixedpoint_str("987654321", 8).unwrap(), Amount { val: 98765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("87654321", 8).unwrap(), Amount { val: 8765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("7654321", 8).unwrap(), Amount { val: 765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("654321", 8).unwrap(), Amount { val: 65432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("54321", 8).unwrap(), Amount { val: 5432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("4321", 8).unwrap(), Amount { val: 432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("321", 8).unwrap(), Amount { val: 32100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21", 8).unwrap(), Amount { val: 2100000000 });
        assert_eq!(Amount::from_fixedpoint_str("1", 8).unwrap(), Amount { val: 100000000 });
        assert_eq!(Amount::from_fixedpoint_str("1.2", 8).unwrap(), Amount { val: 120000000 });
        assert_eq!(Amount::from_fixedpoint_str("1.23", 8).unwrap(), Amount { val: 123000000 });
        assert_eq!(Amount::from_fixedpoint_str("1.234", 8).unwrap(), Amount { val: 123400000 });
        assert_eq!(Amount::from_fixedpoint_str("1.2345", 8).unwrap(), Amount { val: 123450000 });
        assert_eq!(Amount::from_fixedpoint_str("1.23456", 8).unwrap(), Amount { val: 123456000 });
        assert_eq!(Amount::from_fixedpoint_str("1.234567", 8).unwrap(), Amount { val: 123456700 });
        assert_eq!(Amount::from_fixedpoint_str("1.2345678", 8).unwrap(), Amount { val: 123456780 });
        assert_eq!(Amount::from_fixedpoint_str("1.23456789", 8).unwrap(), Amount { val: 123456789 });
        assert_eq!(Amount::from_fixedpoint_str("21.23456789", 8).unwrap(), Amount { val: 2123456789 });
        assert_eq!(Amount::from_fixedpoint_str("321.23456789", 8).unwrap(), Amount { val: 32123456789 });
        assert_eq!(Amount::from_fixedpoint_str("4321.23456789", 8).unwrap(), Amount { val: 432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("54321.23456789", 8).unwrap(), Amount { val: 5432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("654321.23456789", 8).unwrap(), Amount { val: 65432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("7654321.23456789", 8).unwrap(), Amount { val: 765432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("87654321.23456789", 8).unwrap(), Amount { val: 8765432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("987654321.23456789", 8).unwrap(), Amount { val: 98765432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("1987654321.23456789", 8).unwrap(), Amount { val: 198765432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.23456789", 8).unwrap(), Amount { val: 2198765432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.2345678", 8).unwrap(), Amount { val: 2198765432123456780 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.234567", 8).unwrap(), Amount { val: 2198765432123456700 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.23456", 8).unwrap(), Amount { val: 2198765432123456000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.2345", 8).unwrap(), Amount { val: 2198765432123450000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.234", 8).unwrap(), Amount { val: 2198765432123400000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.23", 8).unwrap(), Amount { val: 2198765432123000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.2", 8).unwrap(), Amount { val: 2198765432120000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.", 8).unwrap(), Amount { val: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.0", 8).unwrap(), Amount { val: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.00", 8).unwrap(), Amount { val: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.000", 8).unwrap(), Amount { val: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.0000", 8).unwrap(), Amount { val: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.00000", 8).unwrap(), Amount { val: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.000000", 8).unwrap(), Amount { val: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.0000000", 8).unwrap(), Amount { val: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.00000000", 8).unwrap(), Amount { val: 2198765432100000000 });
        assert!(Amount::from_fixedpoint_str("", 8).is_none());
        assert!(Amount::from_fixedpoint_str(" ", 8).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.000000000", 8).is_none());
        assert!(Amount::from_fixedpoint_str("1.234567891", 8).is_none());
        assert!(Amount::from_fixedpoint_str("1..234567891", 8).is_none());
        assert!(Amount::from_fixedpoint_str("1.234567891,", 8).is_none());
        assert!(Amount::from_fixedpoint_str("1.23a4567891,", 8).is_none());
        assert!(Amount::from_fixedpoint_str("1.23-4567891", 8).is_none());
        assert!(Amount::from_fixedpoint_str("1.23e4567891", 8).is_none());

        assert!(Amount::from_fixedpoint_str("-", 8).is_none());
        assert!(Amount::from_fixedpoint_str("-21987654321.0", 8).is_none());
        assert!(Amount::from_fixedpoint_str("-21987654321.00000000", 8).is_none());
        assert!(Amount::from_fixedpoint_str("-1.234567891", 8).is_none());
        assert!(Amount::from_fixedpoint_str("-1..234567891", 8).is_none());
        assert!(Amount::from_fixedpoint_str("-1.234567891,", 8).is_none());
        assert!(Amount::from_fixedpoint_str("-1.23a4567891,", 8).is_none());
        assert!(Amount::from_fixedpoint_str("-1.23-4567891", 8).is_none());
        assert!(Amount::from_fixedpoint_str("-1.23e4567891", 8).is_none());
    }

    #[rustfmt::skip]
    #[test]
    fn from_fixedpoint_0_decimals() {
        assert_eq!(Amount::from_fixedpoint_str("987654321", 0).unwrap(), Amount { val: 987654321 });
        assert_eq!(Amount::from_fixedpoint_str("87654321", 0).unwrap(), Amount { val: 87654321 });
        assert_eq!(Amount::from_fixedpoint_str("7654321", 0).unwrap(), Amount { val: 7654321 });
        assert_eq!(Amount::from_fixedpoint_str("654321", 0).unwrap(), Amount { val: 654321 });
        assert_eq!(Amount::from_fixedpoint_str("54321", 0).unwrap(), Amount { val: 54321 });
        assert_eq!(Amount::from_fixedpoint_str("4321", 0).unwrap(), Amount { val: 4321 });
        assert_eq!(Amount::from_fixedpoint_str("321", 0).unwrap(), Amount { val: 321 });
        assert_eq!(Amount::from_fixedpoint_str("21", 0).unwrap(), Amount { val: 21 });
        assert_eq!(Amount::from_fixedpoint_str("1", 0).unwrap(), Amount { val: 1 });
        assert_eq!(Amount::from_fixedpoint_str("987654321.", 0).unwrap(), Amount { val: 987654321 });
        assert_eq!(Amount::from_fixedpoint_str("87654321.", 0).unwrap(), Amount { val: 87654321 });
        assert_eq!(Amount::from_fixedpoint_str("7654321.", 0).unwrap(), Amount { val: 7654321 });
        assert_eq!(Amount::from_fixedpoint_str("654321.", 0).unwrap(), Amount { val: 654321 });
        assert_eq!(Amount::from_fixedpoint_str("54321.", 0).unwrap(), Amount { val: 54321 });
        assert_eq!(Amount::from_fixedpoint_str("4321.", 0).unwrap(), Amount { val: 4321 });
        assert_eq!(Amount::from_fixedpoint_str("321.", 0).unwrap(), Amount { val: 321 });
        assert_eq!(Amount::from_fixedpoint_str("21.", 0).unwrap(), Amount { val: 21 });
        assert_eq!(Amount::from_fixedpoint_str("1.", 0).unwrap(), Amount { val: 1 });
        assert!(Amount::from_fixedpoint_str("1.2", 0).is_none());
        assert!(Amount::from_fixedpoint_str("1.23", 0).is_none());
        assert!(Amount::from_fixedpoint_str("1.234", 0).is_none());
        assert!(Amount::from_fixedpoint_str("1.2345", 0).is_none());
        assert!(Amount::from_fixedpoint_str("1.23456", 0).is_none());
        assert!(Amount::from_fixedpoint_str("1.234567", 0).is_none());
        assert!(Amount::from_fixedpoint_str("1.2345678", 0).is_none());
        assert!(Amount::from_fixedpoint_str("1.23456789", 0).is_none());
        assert!(Amount::from_fixedpoint_str("21.23456789", 0).is_none());
        assert!(Amount::from_fixedpoint_str("321.23456789", 0).is_none());
        assert!(Amount::from_fixedpoint_str("4321.23456789", 0).is_none());
        assert!(Amount::from_fixedpoint_str("54321.23456789", 0).is_none());
        assert!(Amount::from_fixedpoint_str("654321.23456789", 0).is_none());
        assert!(Amount::from_fixedpoint_str("7654321.23456789", 0).is_none());
        assert!(Amount::from_fixedpoint_str("87654321.23456789", 0).is_none());
        assert!(Amount::from_fixedpoint_str("987654321.23456789", 0).is_none());
        assert!(Amount::from_fixedpoint_str("1987654321.23456789", 0).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.23456789", 0).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.2345678", 0).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.234567", 0).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.23456", 0).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.2345", 0).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.234", 0).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.23", 0).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.2", 0).is_none());
        assert_eq!(Amount::from_fixedpoint_str("21987654321.", 0).unwrap(), Amount { val: 21987654321 });
        assert!(Amount::from_fixedpoint_str("21987654321.0", 0).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.00", 0).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.000", 0).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.0000", 0).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.00000", 0).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.000000", 0).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.0000000", 0).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.00000000", 0).is_none());
        assert!(Amount::from_fixedpoint_str("", 0).is_none());
        assert!(Amount::from_fixedpoint_str(" ", 0).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.000000000", 0).is_none());
        assert!(Amount::from_fixedpoint_str("1.234567891", 0).is_none());
        assert!(Amount::from_fixedpoint_str("1..234567891", 0).is_none());
        assert!(Amount::from_fixedpoint_str("1.234567891,", 0).is_none());
        assert!(Amount::from_fixedpoint_str("1.23a4567891,", 0).is_none());
        assert!(Amount::from_fixedpoint_str("1.23-4567891", 0).is_none());
        assert!(Amount::from_fixedpoint_str("1.23e4567891", 0).is_none());

        assert!(Amount::from_fixedpoint_str("-987654321", 0).is_none());
        assert!(Amount::from_fixedpoint_str("-87654321", 0).is_none());
        assert!(Amount::from_fixedpoint_str("-7654321", 0).is_none());
        assert!(Amount::from_fixedpoint_str("-654321", 0).is_none());
        assert!(Amount::from_fixedpoint_str("-54321", 0).is_none());
        assert!(Amount::from_fixedpoint_str("-4321", 0).is_none());
        assert!(Amount::from_fixedpoint_str("-321", 0).is_none());
        assert!(Amount::from_fixedpoint_str("-21", 0).is_none());
        assert!(Amount::from_fixedpoint_str("-1", 0).is_none());
    }

    #[rustfmt::skip]
    #[test]
    fn from_fixedpoint_1_decimal() {
        assert_eq!(Amount::from_fixedpoint_str("987654321", 1).unwrap(), Amount { val: 9876543210 });
        assert_eq!(Amount::from_fixedpoint_str("87654321", 1).unwrap(), Amount { val: 876543210 });
        assert_eq!(Amount::from_fixedpoint_str("7654321", 1).unwrap(), Amount { val: 76543210 });
        assert_eq!(Amount::from_fixedpoint_str("654321", 1).unwrap(), Amount { val: 6543210 });
        assert_eq!(Amount::from_fixedpoint_str("54321", 1).unwrap(), Amount { val: 543210 });
        assert_eq!(Amount::from_fixedpoint_str("4321", 1).unwrap(), Amount { val: 43210 });
        assert_eq!(Amount::from_fixedpoint_str("321", 1).unwrap(), Amount { val: 3210 });
        assert_eq!(Amount::from_fixedpoint_str("21", 1).unwrap(), Amount { val: 210 });
        assert_eq!(Amount::from_fixedpoint_str("1", 1).unwrap(), Amount { val: 10 });
        assert_eq!(Amount::from_fixedpoint_str("1.2", 1).unwrap(), Amount { val: 12 });
        assert!(Amount::from_fixedpoint_str("1.23", 1).is_none());
        assert!(Amount::from_fixedpoint_str("1.234", 1).is_none());
        assert!(Amount::from_fixedpoint_str("1.2345", 1).is_none());
        assert!(Amount::from_fixedpoint_str("1.23456", 1).is_none());
        assert!(Amount::from_fixedpoint_str("1.234567", 1).is_none());
        assert!(Amount::from_fixedpoint_str("1.2345678", 1).is_none());
        assert!(Amount::from_fixedpoint_str("1.23456789", 1).is_none());
        assert!(Amount::from_fixedpoint_str("21.23456789", 1).is_none());
        assert!(Amount::from_fixedpoint_str("321.23456789", 1).is_none());
        assert!(Amount::from_fixedpoint_str("4321.23456789", 1).is_none());
        assert!(Amount::from_fixedpoint_str("54321.23456789", 1).is_none());
        assert!(Amount::from_fixedpoint_str("654321.23456789", 1).is_none());
        assert!(Amount::from_fixedpoint_str("7654321.23456789", 1).is_none());
        assert!(Amount::from_fixedpoint_str("87654321.23456789", 1).is_none());
        assert!(Amount::from_fixedpoint_str("987654321.23456789", 1).is_none());
        assert!(Amount::from_fixedpoint_str("1987654321.23456789", 1).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.23456789", 1).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.2345678", 1).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.234567", 1).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.23456", 1).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.2345", 1).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.234", 1).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.23", 1).is_none());
        assert_eq!(Amount::from_fixedpoint_str("21987654321.2", 1).unwrap(), Amount { val: 219876543212 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.", 1).unwrap(), Amount { val: 219876543210 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.0", 1).unwrap(), Amount { val: 219876543210 });
        assert!(Amount::from_fixedpoint_str("21987654321.00", 1).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.000", 1).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.0000", 1).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.00000", 1).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.000000", 1).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.0000000", 1).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.00000000", 1).is_none());
        assert!(Amount::from_fixedpoint_str("", 1).is_none());
        assert!(Amount::from_fixedpoint_str(" ", 1).is_none());
        assert!(Amount::from_fixedpoint_str("21987654321.000000000", 1).is_none());
        assert!(Amount::from_fixedpoint_str("1.234567891", 1).is_none());
        assert!(Amount::from_fixedpoint_str("1..234567891", 1).is_none());
        assert!(Amount::from_fixedpoint_str("1.234567891,", 1).is_none());
        assert!(Amount::from_fixedpoint_str("1.23a4567891,", 1).is_none());
        assert!(Amount::from_fixedpoint_str("1.23-4567891", 1).is_none());
        assert!(Amount::from_fixedpoint_str("1.23e4567891", 1).is_none());

        assert!(Amount::from_fixedpoint_str("-987654321", 1).is_none());
        assert!(Amount::from_fixedpoint_str("-87654321", 1).is_none());
        assert!(Amount::from_fixedpoint_str("-7654321", 1).is_none());
        assert!(Amount::from_fixedpoint_str("-654321", 1).is_none());
        assert!(Amount::from_fixedpoint_str("-54321", 1).is_none());
        assert!(Amount::from_fixedpoint_str("-4321", 1).is_none());
        assert!(Amount::from_fixedpoint_str("-321", 1).is_none());
        assert!(Amount::from_fixedpoint_str("-21", 1).is_none());
        assert!(Amount::from_fixedpoint_str("-1", 1).is_none());
        assert!(Amount::from_fixedpoint_str("-1.2", 1).is_none());
    }

    #[rustfmt::skip]
    #[test]
    fn to_fixedpoint_8_decimals() {
        assert_eq!(Amount { val: 0 }.into_fixedpoint_str(8), "0");
        assert_eq!(Amount { val: 1 }.into_fixedpoint_str(8), "0.00000001");
        assert_eq!(Amount { val: 12 }.into_fixedpoint_str(8), "0.00000012");
        assert_eq!(Amount { val: 123 }.into_fixedpoint_str(8), "0.00000123");
        assert_eq!(Amount { val: 1234 }.into_fixedpoint_str(8), "0.00001234");
        assert_eq!(Amount { val: 12345 }.into_fixedpoint_str(8), "0.00012345");
        assert_eq!(Amount { val: 123456 }.into_fixedpoint_str(8), "0.00123456");
        assert_eq!(Amount { val: 1234567 }.into_fixedpoint_str(8), "0.01234567");
        assert_eq!(Amount { val: 12345678 }.into_fixedpoint_str(8), "0.12345678");
        assert_eq!(Amount { val: 112345678 }.into_fixedpoint_str(8), "1.12345678");
        assert_eq!(Amount { val: 2112345678 }.into_fixedpoint_str(8), "21.12345678");
        assert_eq!(Amount { val: 32112345678 }.into_fixedpoint_str(8), "321.12345678");
        assert_eq!(Amount { val: 432112345678 }.into_fixedpoint_str(8), "4321.12345678");
        assert_eq!(Amount { val: 5432112345678 }.into_fixedpoint_str(8), "54321.12345678");
        assert_eq!(Amount { val: 65432112345678 }.into_fixedpoint_str(8), "654321.12345678");
        assert_eq!(Amount { val: 765432112345678 }.into_fixedpoint_str(8), "7654321.12345678");
        assert_eq!(Amount { val: 8765432112345678 }.into_fixedpoint_str(8), "87654321.12345678");
        assert_eq!(Amount { val: 98765432112345678 }.into_fixedpoint_str(8), "987654321.12345678");
        assert_eq!(Amount { val: 10 }.into_fixedpoint_str(8), "0.0000001");
        assert_eq!(Amount { val: 120 }.into_fixedpoint_str(8), "0.0000012");
        assert_eq!(Amount { val: 1230 }.into_fixedpoint_str(8), "0.0000123");
        assert_eq!(Amount { val: 12340 }.into_fixedpoint_str(8), "0.0001234");
        assert_eq!(Amount { val: 123450 }.into_fixedpoint_str(8), "0.0012345");
        assert_eq!(Amount { val: 1234560 }.into_fixedpoint_str(8), "0.0123456");
        assert_eq!(Amount { val: 12345670 }.into_fixedpoint_str(8), "0.1234567");
        assert_eq!(Amount { val: 123456780 }.into_fixedpoint_str(8), "1.2345678");
        assert_eq!(Amount { val: 1123456780 }.into_fixedpoint_str(8), "11.2345678");
        assert_eq!(Amount { val: 100 }.into_fixedpoint_str(8), "0.000001");
        assert_eq!(Amount { val: 1200 }.into_fixedpoint_str(8), "0.000012");
        assert_eq!(Amount { val: 12300 }.into_fixedpoint_str(8), "0.000123");
        assert_eq!(Amount { val: 123400 }.into_fixedpoint_str(8), "0.001234");
        assert_eq!(Amount { val: 1234500 }.into_fixedpoint_str(8), "0.012345");
        assert_eq!(Amount { val: 12345600 }.into_fixedpoint_str(8), "0.123456");
        assert_eq!(Amount { val: 123456700 }.into_fixedpoint_str(8), "1.234567");
        assert_eq!(Amount { val: 1234567800 }.into_fixedpoint_str(8), "12.345678");
        assert_eq!(Amount { val: 11234567800 }.into_fixedpoint_str(8), "112.345678");
    }

    #[rustfmt::skip]
    #[test]
    fn to_fixedpoint_0_decimals() {
        assert_eq!(Amount { val: 1 }.into_fixedpoint_str(0), "1");
        assert_eq!(Amount { val: 12 }.into_fixedpoint_str(0), "12");
        assert_eq!(Amount { val: 123 }.into_fixedpoint_str(0), "123");
        assert_eq!(Amount { val: 1234 }.into_fixedpoint_str(0), "1234");
        assert_eq!(Amount { val: 12345 }.into_fixedpoint_str(0), "12345");
        assert_eq!(Amount { val: 123456 }.into_fixedpoint_str(0), "123456");
        assert_eq!(Amount { val: 1234567 }.into_fixedpoint_str(0), "1234567");
        assert_eq!(Amount { val: 12345678 }.into_fixedpoint_str(0), "12345678");
        assert_eq!(Amount { val: 123456789 }.into_fixedpoint_str(0), "123456789");
        assert_eq!(Amount { val: 1234567890 }.into_fixedpoint_str(0), "1234567890");
        assert_eq!(Amount { val: 12345678901 }.into_fixedpoint_str(0), "12345678901");
        assert_eq!(Amount { val: 123456789012 }.into_fixedpoint_str(0), "123456789012");
        assert_eq!(Amount { val: 1234567890123 }.into_fixedpoint_str(0), "1234567890123");
        assert_eq!(Amount { val: 10 }.into_fixedpoint_str(0), "10");
        assert_eq!(Amount { val: 120 }.into_fixedpoint_str(0), "120");
        assert_eq!(Amount { val: 1230 }.into_fixedpoint_str(0), "1230");
        assert_eq!(Amount { val: 12340 }.into_fixedpoint_str(0), "12340");
        assert_eq!(Amount { val: 123450 }.into_fixedpoint_str(0), "123450");
        assert_eq!(Amount { val: 1234560 }.into_fixedpoint_str(0), "1234560");
        assert_eq!(Amount { val: 12345670 }.into_fixedpoint_str(0), "12345670");
        assert_eq!(Amount { val: 123456780 }.into_fixedpoint_str(0), "123456780");
        assert_eq!(Amount { val: 1234567890 }.into_fixedpoint_str(0), "1234567890");
        assert_eq!(Amount { val: 12345678900 }.into_fixedpoint_str(0), "12345678900");
        assert_eq!(Amount { val: 123456789010 }.into_fixedpoint_str(0), "123456789010");
        assert_eq!(Amount { val: 1234567890120 }.into_fixedpoint_str(0), "1234567890120");
        assert_eq!(Amount { val: 12345678901230 }.into_fixedpoint_str(0), "12345678901230");
        assert_eq!(Amount { val: 100 }.into_fixedpoint_str(0), "100");
        assert_eq!(Amount { val: 1200 }.into_fixedpoint_str(0), "1200");
        assert_eq!(Amount { val: 12300 }.into_fixedpoint_str(0), "12300");
        assert_eq!(Amount { val: 123400 }.into_fixedpoint_str(0), "123400");
        assert_eq!(Amount { val: 1234500 }.into_fixedpoint_str(0), "1234500");
        assert_eq!(Amount { val: 12345600 }.into_fixedpoint_str(0), "12345600");
        assert_eq!(Amount { val: 123456700 }.into_fixedpoint_str(0), "123456700");
        assert_eq!(Amount { val: 1234567800 }.into_fixedpoint_str(0), "1234567800");
        assert_eq!(Amount { val: 12345678900 }.into_fixedpoint_str(0), "12345678900");
        assert_eq!(Amount { val: 123456789000 }.into_fixedpoint_str(0), "123456789000");
        assert_eq!(Amount { val: 1234567890100 }.into_fixedpoint_str(0), "1234567890100");
        assert_eq!(Amount { val: 12345678901200 }.into_fixedpoint_str(0), "12345678901200");
        assert_eq!(Amount { val: 123456789012300 }.into_fixedpoint_str(0), "123456789012300");

    }

    #[rustfmt::skip]
    #[test]
    fn to_fixedpoint_1_decimal() {
        assert_eq!(Amount { val: 1 }.into_fixedpoint_str(1), "0.1");
        assert_eq!(Amount { val: 12 }.into_fixedpoint_str(1), "1.2");
        assert_eq!(Amount { val: 123 }.into_fixedpoint_str(1), "12.3");
        assert_eq!(Amount { val: 1234 }.into_fixedpoint_str(1), "123.4");
        assert_eq!(Amount { val: 12345 }.into_fixedpoint_str(1), "1234.5");
        assert_eq!(Amount { val: 123456 }.into_fixedpoint_str(1), "12345.6");
        assert_eq!(Amount { val: 1234567 }.into_fixedpoint_str(1), "123456.7");
        assert_eq!(Amount { val: 12345678 }.into_fixedpoint_str(1), "1234567.8");
        assert_eq!(Amount { val: 123456789 }.into_fixedpoint_str(1), "12345678.9");
        assert_eq!(Amount { val: 1234567890 }.into_fixedpoint_str(1), "123456789");
        assert_eq!(Amount { val: 12345678901 }.into_fixedpoint_str(1), "1234567890.1");
        assert_eq!(Amount { val: 123456789012 }.into_fixedpoint_str(1), "12345678901.2");
        assert_eq!(Amount { val: 1234567890123 }.into_fixedpoint_str(1), "123456789012.3");
        assert_eq!(Amount { val: 10 }.into_fixedpoint_str(1), "1");
        assert_eq!(Amount { val: 120 }.into_fixedpoint_str(1), "12");
        assert_eq!(Amount { val: 1230 }.into_fixedpoint_str(1), "123");
        assert_eq!(Amount { val: 12340 }.into_fixedpoint_str(1), "1234");
        assert_eq!(Amount { val: 123450 }.into_fixedpoint_str(1), "12345");
        assert_eq!(Amount { val: 1234560 }.into_fixedpoint_str(1), "123456");
        assert_eq!(Amount { val: 12345670 }.into_fixedpoint_str(1), "1234567");
        assert_eq!(Amount { val: 123456780 }.into_fixedpoint_str(1), "12345678");
        assert_eq!(Amount { val: 1234567890 }.into_fixedpoint_str(1), "123456789");
        assert_eq!(Amount { val: 12345678900 }.into_fixedpoint_str(1), "1234567890");
        assert_eq!(Amount { val: 123456789010 }.into_fixedpoint_str(1), "12345678901");
        assert_eq!(Amount { val: 1234567890120 }.into_fixedpoint_str(1), "123456789012");
        assert_eq!(Amount { val: 12345678901230 }.into_fixedpoint_str(1), "1234567890123");
        assert_eq!(Amount { val: 100 }.into_fixedpoint_str(1), "10");
        assert_eq!(Amount { val: 1200 }.into_fixedpoint_str(1), "120");
        assert_eq!(Amount { val: 12300 }.into_fixedpoint_str(1), "1230");
        assert_eq!(Amount { val: 123400 }.into_fixedpoint_str(1), "12340");
        assert_eq!(Amount { val: 1234500 }.into_fixedpoint_str(1), "123450");
        assert_eq!(Amount { val: 12345600 }.into_fixedpoint_str(1), "1234560");
        assert_eq!(Amount { val: 123456700 }.into_fixedpoint_str(1), "12345670");
        assert_eq!(Amount { val: 1234567800 }.into_fixedpoint_str(1), "123456780");
        assert_eq!(Amount { val: 12345678900 }.into_fixedpoint_str(1), "1234567890");
        assert_eq!(Amount { val: 123456789000 }.into_fixedpoint_str(1), "12345678900");
        assert_eq!(Amount { val: 1234567890100 }.into_fixedpoint_str(1), "123456789010");
        assert_eq!(Amount { val: 12345678901200 }.into_fixedpoint_str(1), "1234567890120");
        assert_eq!(Amount { val: 123456789012300 }.into_fixedpoint_str(1), "12345678901230");
    }
}
