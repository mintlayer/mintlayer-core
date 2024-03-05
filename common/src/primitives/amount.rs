// Copyright (c) 2021-2023 RBB S.r.l
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

use super::{signed_amount::SignedAmount, DecimalAmount};

pub type UnsignedIntType = u128;

/// An unsigned fixed-point type for amounts
/// The smallest unit of count is called an atom
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
#[must_use]
pub struct Amount {
    #[codec(compact)]
    fixed_point_integer: UnsignedIntType,
}

impl Amount {
    pub const MAX: Self = Self::from_atoms(UnsignedIntType::MAX);
    pub const ZERO: Self = Self::from_atoms(0);

    pub const fn from_atoms(v: UnsignedIntType) -> Self {
        Amount {
            fixed_point_integer: v,
        }
    }

    pub const fn into_atoms(&self) -> UnsignedIntType {
        self.fixed_point_integer
    }

    pub fn from_signed(amount: SignedAmount) -> Option<Self> {
        let signed_atoms = amount.into_atoms();
        let atoms: UnsignedIntType = signed_atoms.try_into().ok()?;
        Some(Self::from_atoms(atoms))
    }

    pub fn into_signed(self) -> Option<SignedAmount> {
        let atoms = self.fixed_point_integer;
        let signed_atoms: super::signed_amount::SignedIntType = atoms.try_into().ok()?;
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
        self.fixed_point_integer.checked_add(other.fixed_point_integer).map(|n| Amount {
            fixed_point_integer: n,
        })
    }
}

impl std::ops::Sub for Amount {
    type Output = Option<Self>;

    fn sub(self, other: Self) -> Option<Self> {
        self.fixed_point_integer.checked_sub(other.fixed_point_integer).map(|n| Amount {
            fixed_point_integer: n,
        })
    }
}

impl std::ops::Mul<UnsignedIntType> for Amount {
    type Output = Option<Self>;

    fn mul(self, other: UnsignedIntType) -> Option<Self> {
        self.fixed_point_integer.checked_mul(other).map(|n| Amount {
            fixed_point_integer: n,
        })
    }
}

impl std::ops::Div<UnsignedIntType> for Amount {
    type Output = Option<Amount>;

    fn div(self, other: UnsignedIntType) -> Option<Amount> {
        self.fixed_point_integer.checked_div(other).map(|n| Amount {
            fixed_point_integer: n,
        })
    }
}

impl std::ops::Rem<UnsignedIntType> for Amount {
    type Output = Option<Self>;

    fn rem(self, other: UnsignedIntType) -> Option<Self> {
        self.fixed_point_integer.checked_rem(other).map(|n| Amount {
            fixed_point_integer: n,
        })
    }
}

impl std::ops::BitAnd for Amount {
    type Output = Self;

    fn bitand(self, other: Self) -> Self {
        Amount {
            fixed_point_integer: self.fixed_point_integer.bitand(other.fixed_point_integer),
        }
    }
}

impl std::ops::BitAndAssign for Amount {
    fn bitand_assign(&mut self, other: Self) {
        self.fixed_point_integer.bitand_assign(other.fixed_point_integer)
    }
}

impl std::ops::BitOr for Amount {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Amount {
            fixed_point_integer: self.fixed_point_integer.bitor(other.fixed_point_integer),
        }
    }
}

impl std::ops::BitOrAssign for Amount {
    fn bitor_assign(&mut self, other: Self) {
        self.fixed_point_integer.bitor_assign(other.fixed_point_integer)
    }
}

impl std::ops::BitXor for Amount {
    type Output = Self;

    fn bitxor(self, other: Self) -> Self {
        Amount {
            fixed_point_integer: self.fixed_point_integer.bitxor(other.fixed_point_integer),
        }
    }
}

impl std::ops::BitXorAssign for Amount {
    fn bitxor_assign(&mut self, other: Self) {
        self.fixed_point_integer.bitxor_assign(other.fixed_point_integer)
    }
}

impl std::ops::Not for Amount {
    type Output = Self;

    fn not(self) -> Self {
        Amount {
            fixed_point_integer: self.fixed_point_integer.not(),
        }
    }
}

impl std::ops::Shl<u32> for Amount {
    type Output = Option<Self>;

    fn shl(self, other: u32) -> Option<Self> {
        self.fixed_point_integer.checked_shl(other).map(|v| Amount {
            fixed_point_integer: v,
        })
    }
}

impl std::ops::Shr<u32> for Amount {
    type Output = Option<Self>;

    fn shr(self, other: u32) -> Option<Self> {
        self.fixed_point_integer.checked_shr(other).map(|v| Amount {
            fixed_point_integer: v,
        })
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
    const HINT: rpc_description::ValueHint = rpc_description::ValueHint::Object(&[(
        "fixed_point_integer",
        &rpc_description::ValueHint::NUMBER,
    )]);
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

#[cfg(test)]
mod tests {
    use crate::primitives::signed_amount::SignedIntType;

    use super::*;

    use crypto::random::Rng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    #[test]
    fn creation() {
        let x = Amount::from_atoms(555);
        assert_eq!(
            x,
            Amount {
                fixed_point_integer: 555
            }
        );

        let y = Amount::from_atoms(123);
        assert_eq!(
            y,
            Amount {
                fixed_point_integer: 123
            }
        );
    }

    #[test]
    fn add_some() {
        assert_eq!(
            Amount {
                fixed_point_integer: 2
            } + Amount {
                fixed_point_integer: 2
            },
            Some(Amount {
                fixed_point_integer: 4
            })
        );
    }

    #[test]
    fn sub_some() {
        assert_eq!(
            Amount {
                fixed_point_integer: 4
            } - Amount {
                fixed_point_integer: 2
            },
            Some(Amount {
                fixed_point_integer: 2
            })
        );
    }

    #[test]
    fn mul_some() {
        assert_eq!(
            Amount {
                fixed_point_integer: 3
            } * 3,
            Some(Amount {
                fixed_point_integer: 9
            })
        );
    }

    #[test]
    fn div_some() {
        assert_eq!(
            Amount {
                fixed_point_integer: 9
            } / 3,
            Some(Amount {
                fixed_point_integer: 3
            })
        );
    }

    #[test]
    fn rem_some() {
        assert_eq!(
            Amount {
                fixed_point_integer: 9
            } % 4,
            Some(Amount {
                fixed_point_integer: 1
            })
        );
    }

    #[test]
    fn add_overflow() {
        assert_eq!(
            Amount {
                fixed_point_integer: UnsignedIntType::MAX
            } + Amount {
                fixed_point_integer: 1
            },
            None
        );
    }

    #[test]
    fn sum_some() {
        let amounts = vec![
            Amount {
                fixed_point_integer: 1,
            },
            Amount {
                fixed_point_integer: 2,
            },
            Amount {
                fixed_point_integer: 3,
            },
        ];
        assert_eq!(
            amounts.into_iter().sum::<Option<Amount>>(),
            Some(Amount {
                fixed_point_integer: 6
            })
        );
    }

    #[test]
    fn sum_overflow() {
        let amounts = vec![
            Amount {
                fixed_point_integer: 1,
            },
            Amount {
                fixed_point_integer: 2,
            },
            Amount {
                fixed_point_integer: UnsignedIntType::MAX - 2,
            },
        ];
        assert_eq!(amounts.into_iter().sum::<Option<Amount>>(), None);
    }

    #[test]
    fn sum_empty() {
        assert_eq!(
            vec![].into_iter().sum::<Option<Amount>>(),
            Some(Amount::from_atoms(0))
        )
    }

    #[test]
    fn sub_underflow() {
        assert_eq!(
            Amount {
                fixed_point_integer: UnsignedIntType::MIN
            } - Amount {
                fixed_point_integer: 1
            },
            None
        );
    }

    #[test]
    fn mul_overflow() {
        assert_eq!(
            Amount {
                fixed_point_integer: UnsignedIntType::MAX / 2 + 1
            } * 2,
            None
        );
    }

    #[test]
    fn comparison() {
        assert!(
            Amount {
                fixed_point_integer: 1
            } != Amount {
                fixed_point_integer: 2
            }
        );
        assert!(
            Amount {
                fixed_point_integer: 1
            } < Amount {
                fixed_point_integer: 2
            }
        );
        assert!(
            Amount {
                fixed_point_integer: 1
            } <= Amount {
                fixed_point_integer: 2
            }
        );
        assert!(
            Amount {
                fixed_point_integer: 2
            } <= Amount {
                fixed_point_integer: 2
            }
        );
        assert!(
            Amount {
                fixed_point_integer: 2
            } == Amount {
                fixed_point_integer: 2
            }
        );
        assert!(
            Amount {
                fixed_point_integer: 2
            } >= Amount {
                fixed_point_integer: 2
            }
        );
        assert!(
            Amount {
                fixed_point_integer: 3
            } > Amount {
                fixed_point_integer: 2
            }
        );
    }

    #[test]
    fn bit_ops() {
        let x = Amount {
            fixed_point_integer: 5,
        };
        let y = Amount {
            fixed_point_integer: 1,
        };
        let z = Amount {
            fixed_point_integer: 2,
        };
        let zero: UnsignedIntType = 0;
        assert_eq!(
            x | y,
            Amount {
                fixed_point_integer: 5
            }
        );
        assert_eq!(
            x & z,
            Amount {
                fixed_point_integer: 0
            }
        );
        assert_eq!(
            x ^ y,
            Amount {
                fixed_point_integer: 4
            }
        );
        assert_eq!(!zero, UnsignedIntType::MAX);
    }

    #[test]
    fn bit_ops_assign() {
        let mut x = Amount {
            fixed_point_integer: 5,
        };

        x ^= Amount {
            fixed_point_integer: 1,
        };
        assert_eq!(
            x,
            Amount {
                fixed_point_integer: 4
            }
        );

        x |= Amount {
            fixed_point_integer: 2,
        };
        assert_eq!(
            x,
            Amount {
                fixed_point_integer: 6
            }
        );

        x &= Amount {
            fixed_point_integer: 5,
        };
        assert_eq!(
            x,
            Amount {
                fixed_point_integer: 4
            }
        );
    }

    #[test]
    fn bit_shifts() {
        let x = Amount {
            fixed_point_integer: 1,
        };
        assert_eq!(
            x << 1,
            Some(Amount {
                fixed_point_integer: 2
            })
        );
        assert_eq!(
            x << 2,
            Some(Amount {
                fixed_point_integer: 4
            })
        );
        assert_eq!(
            x << 4,
            Some(Amount {
                fixed_point_integer: 16
            })
        );
        assert_eq!(
            x << 6,
            Some(Amount {
                fixed_point_integer: 64
            })
        );

        let y = Amount {
            fixed_point_integer: 128,
        };
        assert_eq!(
            y >> 1,
            Some(Amount {
                fixed_point_integer: 64
            })
        );
        assert_eq!(
            y >> 2,
            Some(Amount {
                fixed_point_integer: 32
            })
        );
        assert_eq!(
            y >> 4,
            Some(Amount {
                fixed_point_integer: 8
            })
        );
        assert_eq!(
            y >> 6,
            Some(Amount {
                fixed_point_integer: 2
            })
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn abs_diff_never_fails(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let a = Amount::from_atoms(rng.gen());
        let b = Amount::from_atoms(rng.gen());
        let _ = a.abs_diff(b);
    }

    #[rstest]
    #[case(2, 0, 2)]
    #[case(0, 2, 2)]
    #[case(221, 117, 104)]
    #[case(117, 221, 104)]
    #[case(u128::MAX, 1, u128::MAX-1)]
    #[case(1, u128::MAX, u128::MAX-1)]
    fn abs_diff_check(#[case] a: u128, #[case] b: u128, #[case] result: u128) {
        assert_eq!(
            Amount::from_atoms(a).abs_diff(Amount::from_atoms(b)),
            Amount::from_atoms(result)
        );
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
            amount_sum!(
                Amount::from_atoms(UnsignedIntType::MAX),
                Amount::from_atoms(0)
            ),
            Some(Amount::from_atoms(UnsignedIntType::MAX))
        );

        assert_eq!(
            amount_sum!(
                Amount::from_atoms(UnsignedIntType::MAX),
                Amount::from_atoms(1)
            ),
            None
        );

        assert_eq!(
            amount_sum!(
                Amount::from_atoms(UnsignedIntType::MAX - 1),
                Amount::from_atoms(1),
                Amount::from_atoms(1)
            ),
            None
        );
    }

    #[test]
    fn signed_conversion_arbitrary() {
        let amount = Amount::from_atoms(10);
        let signed_amount_inner = 10 as SignedIntType;
        assert_eq!(
            amount.into_signed().unwrap(),
            SignedAmount::from_atoms(signed_amount_inner)
        )
    }

    #[test]
    fn signed_conversion_max() {
        let amount = Amount::MAX;
        assert!(amount.into_signed().is_none())
    }

    #[test]
    fn signed_conversion_signed_max_before_threshold() {
        let amount = Amount::from_atoms(SignedIntType::MAX as UnsignedIntType);
        let signed_amount_inner = SignedIntType::MAX;
        assert_eq!(
            amount.into_signed().unwrap(),
            SignedAmount::from_atoms(signed_amount_inner)
        )
    }

    #[test]
    fn signed_conversion_signed_max_after_threshold() {
        let amount = Amount::from_atoms(SignedIntType::MAX as UnsignedIntType + 1);
        assert!(amount.into_signed().is_none())
    }

    #[rustfmt::skip]
    #[test]
    fn from_fixedpoint_8_decimals() {
        assert_eq!(Amount::from_fixedpoint_str("987654321", 8).unwrap(), Amount { fixed_point_integer: 98765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("87654321", 8).unwrap(), Amount { fixed_point_integer: 8765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("7654321", 8).unwrap(), Amount { fixed_point_integer: 765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("654321", 8).unwrap(), Amount { fixed_point_integer: 65432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("54321", 8).unwrap(), Amount { fixed_point_integer: 5432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("4321", 8).unwrap(), Amount { fixed_point_integer: 432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("321", 8).unwrap(), Amount { fixed_point_integer: 32100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21", 8).unwrap(), Amount { fixed_point_integer: 2100000000 });
        assert_eq!(Amount::from_fixedpoint_str("1", 8).unwrap(), Amount { fixed_point_integer: 100000000 });
        assert_eq!(Amount::from_fixedpoint_str("1.2", 8).unwrap(), Amount { fixed_point_integer: 120000000 });
        assert_eq!(Amount::from_fixedpoint_str("1.23", 8).unwrap(), Amount { fixed_point_integer: 123000000 });
        assert_eq!(Amount::from_fixedpoint_str("1.234", 8).unwrap(), Amount { fixed_point_integer: 123400000 });
        assert_eq!(Amount::from_fixedpoint_str("1.2345", 8).unwrap(), Amount { fixed_point_integer: 123450000 });
        assert_eq!(Amount::from_fixedpoint_str("1.23456", 8).unwrap(), Amount { fixed_point_integer: 123456000 });
        assert_eq!(Amount::from_fixedpoint_str("1.234567", 8).unwrap(), Amount { fixed_point_integer: 123456700 });
        assert_eq!(Amount::from_fixedpoint_str("1.2345678", 8).unwrap(), Amount { fixed_point_integer: 123456780 });
        assert_eq!(Amount::from_fixedpoint_str("1.23456789", 8).unwrap(), Amount { fixed_point_integer: 123456789 });
        assert_eq!(Amount::from_fixedpoint_str("21.23456789", 8).unwrap(), Amount { fixed_point_integer: 2123456789 });
        assert_eq!(Amount::from_fixedpoint_str("321.23456789", 8).unwrap(), Amount { fixed_point_integer: 32123456789 });
        assert_eq!(Amount::from_fixedpoint_str("4321.23456789", 8).unwrap(), Amount { fixed_point_integer: 432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("54321.23456789", 8).unwrap(), Amount { fixed_point_integer: 5432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("654321.23456789", 8).unwrap(), Amount { fixed_point_integer: 65432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("7654321.23456789", 8).unwrap(), Amount { fixed_point_integer: 765432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("87654321.23456789", 8).unwrap(), Amount { fixed_point_integer: 8765432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("987654321.23456789", 8).unwrap(), Amount { fixed_point_integer: 98765432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("1987654321.23456789", 8).unwrap(), Amount { fixed_point_integer: 198765432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.23456789", 8).unwrap(), Amount { fixed_point_integer: 2198765432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.2345678", 8).unwrap(), Amount { fixed_point_integer: 2198765432123456780 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.234567", 8).unwrap(), Amount { fixed_point_integer: 2198765432123456700 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.23456", 8).unwrap(), Amount { fixed_point_integer: 2198765432123456000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.2345", 8).unwrap(), Amount { fixed_point_integer: 2198765432123450000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.234", 8).unwrap(), Amount { fixed_point_integer: 2198765432123400000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.23", 8).unwrap(), Amount { fixed_point_integer: 2198765432123000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.2", 8).unwrap(), Amount { fixed_point_integer: 2198765432120000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.", 8).unwrap(), Amount { fixed_point_integer: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.0", 8).unwrap(), Amount { fixed_point_integer: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.00", 8).unwrap(), Amount { fixed_point_integer: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.000", 8).unwrap(), Amount { fixed_point_integer: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.0000", 8).unwrap(), Amount { fixed_point_integer: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.00000", 8).unwrap(), Amount { fixed_point_integer: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.000000", 8).unwrap(), Amount { fixed_point_integer: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.0000000", 8).unwrap(), Amount { fixed_point_integer: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.00000000", 8).unwrap(), Amount { fixed_point_integer: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str(".2", 8).unwrap(), Amount { fixed_point_integer: 20000000 });
        assert_eq!(Amount::from_fixedpoint_str(".23", 8).unwrap(), Amount { fixed_point_integer: 23000000 });
        assert_eq!(Amount::from_fixedpoint_str(".234", 8).unwrap(), Amount { fixed_point_integer: 23400000 });
        assert_eq!(Amount::from_fixedpoint_str(".2345", 8).unwrap(), Amount { fixed_point_integer: 23450000 });
        assert_eq!(Amount::from_fixedpoint_str(".23456", 8).unwrap(), Amount { fixed_point_integer: 23456000 });
        assert_eq!(Amount::from_fixedpoint_str(".234567", 8).unwrap(), Amount { fixed_point_integer: 23456700 });
        assert_eq!(Amount::from_fixedpoint_str(".2345678", 8).unwrap(), Amount { fixed_point_integer: 23456780 });
        assert_eq!(Amount::from_fixedpoint_str(".23456789", 8).unwrap(), Amount { fixed_point_integer: 23456789 });
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
        assert_eq!(Amount::from_fixedpoint_str("987654321", 0).unwrap(), Amount { fixed_point_integer: 987654321 });
        assert_eq!(Amount::from_fixedpoint_str("87654321", 0).unwrap(), Amount { fixed_point_integer: 87654321 });
        assert_eq!(Amount::from_fixedpoint_str("7654321", 0).unwrap(), Amount { fixed_point_integer: 7654321 });
        assert_eq!(Amount::from_fixedpoint_str("654321", 0).unwrap(), Amount { fixed_point_integer: 654321 });
        assert_eq!(Amount::from_fixedpoint_str("54321", 0).unwrap(), Amount { fixed_point_integer: 54321 });
        assert_eq!(Amount::from_fixedpoint_str("4321", 0).unwrap(), Amount { fixed_point_integer: 4321 });
        assert_eq!(Amount::from_fixedpoint_str("321", 0).unwrap(), Amount { fixed_point_integer: 321 });
        assert_eq!(Amount::from_fixedpoint_str("21", 0).unwrap(), Amount { fixed_point_integer: 21 });
        assert_eq!(Amount::from_fixedpoint_str("1", 0).unwrap(), Amount { fixed_point_integer: 1 });
        assert_eq!(Amount::from_fixedpoint_str("987654321.", 0).unwrap(), Amount { fixed_point_integer: 987654321 });
        assert_eq!(Amount::from_fixedpoint_str("87654321.", 0).unwrap(), Amount { fixed_point_integer: 87654321 });
        assert_eq!(Amount::from_fixedpoint_str("7654321.", 0).unwrap(), Amount { fixed_point_integer: 7654321 });
        assert_eq!(Amount::from_fixedpoint_str("654321.", 0).unwrap(), Amount { fixed_point_integer: 654321 });
        assert_eq!(Amount::from_fixedpoint_str("54321.", 0).unwrap(), Amount { fixed_point_integer: 54321 });
        assert_eq!(Amount::from_fixedpoint_str("4321.", 0).unwrap(), Amount { fixed_point_integer: 4321 });
        assert_eq!(Amount::from_fixedpoint_str("321.", 0).unwrap(), Amount { fixed_point_integer: 321 });
        assert_eq!(Amount::from_fixedpoint_str("21.", 0).unwrap(), Amount { fixed_point_integer: 21 });
        assert_eq!(Amount::from_fixedpoint_str("1.", 0).unwrap(), Amount { fixed_point_integer: 1 });
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
        assert_eq!(Amount::from_fixedpoint_str("21987654321.", 0).unwrap(), Amount { fixed_point_integer: 21987654321 });
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
        assert_eq!(Amount::from_fixedpoint_str("987654321", 1).unwrap(), Amount { fixed_point_integer: 9876543210 });
        assert_eq!(Amount::from_fixedpoint_str("87654321", 1).unwrap(), Amount { fixed_point_integer: 876543210 });
        assert_eq!(Amount::from_fixedpoint_str("7654321", 1).unwrap(), Amount { fixed_point_integer: 76543210 });
        assert_eq!(Amount::from_fixedpoint_str("654321", 1).unwrap(), Amount { fixed_point_integer: 6543210 });
        assert_eq!(Amount::from_fixedpoint_str("54321", 1).unwrap(), Amount { fixed_point_integer: 543210 });
        assert_eq!(Amount::from_fixedpoint_str("4321", 1).unwrap(), Amount { fixed_point_integer: 43210 });
        assert_eq!(Amount::from_fixedpoint_str("321", 1).unwrap(), Amount { fixed_point_integer: 3210 });
        assert_eq!(Amount::from_fixedpoint_str("21", 1).unwrap(), Amount { fixed_point_integer: 210 });
        assert_eq!(Amount::from_fixedpoint_str("1", 1).unwrap(), Amount { fixed_point_integer: 10 });
        assert_eq!(Amount::from_fixedpoint_str("1.2", 1).unwrap(), Amount { fixed_point_integer: 12 });
        assert_eq!(Amount::from_fixedpoint_str(".2", 1).unwrap(), Amount { fixed_point_integer: 2 });
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
        assert_eq!(Amount::from_fixedpoint_str("21987654321.2", 1).unwrap(), Amount { fixed_point_integer: 219876543212 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.", 1).unwrap(), Amount { fixed_point_integer: 219876543210 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.0", 1).unwrap(), Amount { fixed_point_integer: 219876543210 });
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
        assert_eq!(Amount { fixed_point_integer: 0 }.into_fixedpoint_str(8), "0");
        assert_eq!(Amount { fixed_point_integer: 1 }.into_fixedpoint_str(8), "0.00000001");
        assert_eq!(Amount { fixed_point_integer: 12 }.into_fixedpoint_str(8), "0.00000012");
        assert_eq!(Amount { fixed_point_integer: 123 }.into_fixedpoint_str(8), "0.00000123");
        assert_eq!(Amount { fixed_point_integer: 1234 }.into_fixedpoint_str(8), "0.00001234");
        assert_eq!(Amount { fixed_point_integer: 12345 }.into_fixedpoint_str(8), "0.00012345");
        assert_eq!(Amount { fixed_point_integer: 123456 }.into_fixedpoint_str(8), "0.00123456");
        assert_eq!(Amount { fixed_point_integer: 1234567 }.into_fixedpoint_str(8), "0.01234567");
        assert_eq!(Amount { fixed_point_integer: 12345678 }.into_fixedpoint_str(8), "0.12345678");
        assert_eq!(Amount { fixed_point_integer: 112345678 }.into_fixedpoint_str(8), "1.12345678");
        assert_eq!(Amount { fixed_point_integer: 2112345678 }.into_fixedpoint_str(8), "21.12345678");
        assert_eq!(Amount { fixed_point_integer: 32112345678 }.into_fixedpoint_str(8), "321.12345678");
        assert_eq!(Amount { fixed_point_integer: 432112345678 }.into_fixedpoint_str(8), "4321.12345678");
        assert_eq!(Amount { fixed_point_integer: 5432112345678 }.into_fixedpoint_str(8), "54321.12345678");
        assert_eq!(Amount { fixed_point_integer: 65432112345678 }.into_fixedpoint_str(8), "654321.12345678");
        assert_eq!(Amount { fixed_point_integer: 765432112345678 }.into_fixedpoint_str(8), "7654321.12345678");
        assert_eq!(Amount { fixed_point_integer: 8765432112345678 }.into_fixedpoint_str(8), "87654321.12345678");
        assert_eq!(Amount { fixed_point_integer: 98765432112345678 }.into_fixedpoint_str(8), "987654321.12345678");
        assert_eq!(Amount { fixed_point_integer: 10 }.into_fixedpoint_str(8), "0.0000001");
        assert_eq!(Amount { fixed_point_integer: 120 }.into_fixedpoint_str(8), "0.0000012");
        assert_eq!(Amount { fixed_point_integer: 1230 }.into_fixedpoint_str(8), "0.0000123");
        assert_eq!(Amount { fixed_point_integer: 12340 }.into_fixedpoint_str(8), "0.0001234");
        assert_eq!(Amount { fixed_point_integer: 123450 }.into_fixedpoint_str(8), "0.0012345");
        assert_eq!(Amount { fixed_point_integer: 1234560 }.into_fixedpoint_str(8), "0.0123456");
        assert_eq!(Amount { fixed_point_integer: 12345670 }.into_fixedpoint_str(8), "0.1234567");
        assert_eq!(Amount { fixed_point_integer: 123456780 }.into_fixedpoint_str(8), "1.2345678");
        assert_eq!(Amount { fixed_point_integer: 1123456780 }.into_fixedpoint_str(8), "11.2345678");
        assert_eq!(Amount { fixed_point_integer: 100 }.into_fixedpoint_str(8), "0.000001");
        assert_eq!(Amount { fixed_point_integer: 1200 }.into_fixedpoint_str(8), "0.000012");
        assert_eq!(Amount { fixed_point_integer: 12300 }.into_fixedpoint_str(8), "0.000123");
        assert_eq!(Amount { fixed_point_integer: 123400 }.into_fixedpoint_str(8), "0.001234");
        assert_eq!(Amount { fixed_point_integer: 1234500 }.into_fixedpoint_str(8), "0.012345");
        assert_eq!(Amount { fixed_point_integer: 12345600 }.into_fixedpoint_str(8), "0.123456");
        assert_eq!(Amount { fixed_point_integer: 123456700 }.into_fixedpoint_str(8), "1.234567");
        assert_eq!(Amount { fixed_point_integer: 1234567800 }.into_fixedpoint_str(8), "12.345678");
        assert_eq!(Amount { fixed_point_integer: 11234567800 }.into_fixedpoint_str(8), "112.345678");
    }

    #[rustfmt::skip]
    #[test]
    fn to_fixedpoint_0_decimals() {
        assert_eq!(Amount { fixed_point_integer: 1 }.into_fixedpoint_str(0), "1");
        assert_eq!(Amount { fixed_point_integer: 12 }.into_fixedpoint_str(0), "12");
        assert_eq!(Amount { fixed_point_integer: 123 }.into_fixedpoint_str(0), "123");
        assert_eq!(Amount { fixed_point_integer: 1234 }.into_fixedpoint_str(0), "1234");
        assert_eq!(Amount { fixed_point_integer: 12345 }.into_fixedpoint_str(0), "12345");
        assert_eq!(Amount { fixed_point_integer: 123456 }.into_fixedpoint_str(0), "123456");
        assert_eq!(Amount { fixed_point_integer: 1234567 }.into_fixedpoint_str(0), "1234567");
        assert_eq!(Amount { fixed_point_integer: 12345678 }.into_fixedpoint_str(0), "12345678");
        assert_eq!(Amount { fixed_point_integer: 123456789 }.into_fixedpoint_str(0), "123456789");
        assert_eq!(Amount { fixed_point_integer: 1234567890 }.into_fixedpoint_str(0), "1234567890");
        assert_eq!(Amount { fixed_point_integer: 12345678901 }.into_fixedpoint_str(0), "12345678901");
        assert_eq!(Amount { fixed_point_integer: 123456789012 }.into_fixedpoint_str(0), "123456789012");
        assert_eq!(Amount { fixed_point_integer: 1234567890123 }.into_fixedpoint_str(0), "1234567890123");
        assert_eq!(Amount { fixed_point_integer: 10 }.into_fixedpoint_str(0), "10");
        assert_eq!(Amount { fixed_point_integer: 120 }.into_fixedpoint_str(0), "120");
        assert_eq!(Amount { fixed_point_integer: 1230 }.into_fixedpoint_str(0), "1230");
        assert_eq!(Amount { fixed_point_integer: 12340 }.into_fixedpoint_str(0), "12340");
        assert_eq!(Amount { fixed_point_integer: 123450 }.into_fixedpoint_str(0), "123450");
        assert_eq!(Amount { fixed_point_integer: 1234560 }.into_fixedpoint_str(0), "1234560");
        assert_eq!(Amount { fixed_point_integer: 12345670 }.into_fixedpoint_str(0), "12345670");
        assert_eq!(Amount { fixed_point_integer: 123456780 }.into_fixedpoint_str(0), "123456780");
        assert_eq!(Amount { fixed_point_integer: 1234567890 }.into_fixedpoint_str(0), "1234567890");
        assert_eq!(Amount { fixed_point_integer: 12345678900 }.into_fixedpoint_str(0), "12345678900");
        assert_eq!(Amount { fixed_point_integer: 123456789010 }.into_fixedpoint_str(0), "123456789010");
        assert_eq!(Amount { fixed_point_integer: 1234567890120 }.into_fixedpoint_str(0), "1234567890120");
        assert_eq!(Amount { fixed_point_integer: 12345678901230 }.into_fixedpoint_str(0), "12345678901230");
        assert_eq!(Amount { fixed_point_integer: 100 }.into_fixedpoint_str(0), "100");
        assert_eq!(Amount { fixed_point_integer: 1200 }.into_fixedpoint_str(0), "1200");
        assert_eq!(Amount { fixed_point_integer: 12300 }.into_fixedpoint_str(0), "12300");
        assert_eq!(Amount { fixed_point_integer: 123400 }.into_fixedpoint_str(0), "123400");
        assert_eq!(Amount { fixed_point_integer: 1234500 }.into_fixedpoint_str(0), "1234500");
        assert_eq!(Amount { fixed_point_integer: 12345600 }.into_fixedpoint_str(0), "12345600");
        assert_eq!(Amount { fixed_point_integer: 123456700 }.into_fixedpoint_str(0), "123456700");
        assert_eq!(Amount { fixed_point_integer: 1234567800 }.into_fixedpoint_str(0), "1234567800");
        assert_eq!(Amount { fixed_point_integer: 12345678900 }.into_fixedpoint_str(0), "12345678900");
        assert_eq!(Amount { fixed_point_integer: 123456789000 }.into_fixedpoint_str(0), "123456789000");
        assert_eq!(Amount { fixed_point_integer: 1234567890100 }.into_fixedpoint_str(0), "1234567890100");
        assert_eq!(Amount { fixed_point_integer: 12345678901200 }.into_fixedpoint_str(0), "12345678901200");
        assert_eq!(Amount { fixed_point_integer: 123456789012300 }.into_fixedpoint_str(0), "123456789012300");
    }

    #[rustfmt::skip]
    #[test]
    fn to_fixedpoint_1_decimal() {
        assert_eq!(Amount { fixed_point_integer: 1 }.into_fixedpoint_str(1), "0.1");
        assert_eq!(Amount { fixed_point_integer: 12 }.into_fixedpoint_str(1), "1.2");
        assert_eq!(Amount { fixed_point_integer: 123 }.into_fixedpoint_str(1), "12.3");
        assert_eq!(Amount { fixed_point_integer: 1234 }.into_fixedpoint_str(1), "123.4");
        assert_eq!(Amount { fixed_point_integer: 12345 }.into_fixedpoint_str(1), "1234.5");
        assert_eq!(Amount { fixed_point_integer: 123456 }.into_fixedpoint_str(1), "12345.6");
        assert_eq!(Amount { fixed_point_integer: 1234567 }.into_fixedpoint_str(1), "123456.7");
        assert_eq!(Amount { fixed_point_integer: 12345678 }.into_fixedpoint_str(1), "1234567.8");
        assert_eq!(Amount { fixed_point_integer: 123456789 }.into_fixedpoint_str(1), "12345678.9");
        assert_eq!(Amount { fixed_point_integer: 1234567890 }.into_fixedpoint_str(1), "123456789");
        assert_eq!(Amount { fixed_point_integer: 12345678901 }.into_fixedpoint_str(1), "1234567890.1");
        assert_eq!(Amount { fixed_point_integer: 123456789012 }.into_fixedpoint_str(1), "12345678901.2");
        assert_eq!(Amount { fixed_point_integer: 1234567890123 }.into_fixedpoint_str(1), "123456789012.3");
        assert_eq!(Amount { fixed_point_integer: 10 }.into_fixedpoint_str(1), "1");
        assert_eq!(Amount { fixed_point_integer: 120 }.into_fixedpoint_str(1), "12");
        assert_eq!(Amount { fixed_point_integer: 1230 }.into_fixedpoint_str(1), "123");
        assert_eq!(Amount { fixed_point_integer: 12340 }.into_fixedpoint_str(1), "1234");
        assert_eq!(Amount { fixed_point_integer: 123450 }.into_fixedpoint_str(1), "12345");
        assert_eq!(Amount { fixed_point_integer: 1234560 }.into_fixedpoint_str(1), "123456");
        assert_eq!(Amount { fixed_point_integer: 12345670 }.into_fixedpoint_str(1), "1234567");
        assert_eq!(Amount { fixed_point_integer: 123456780 }.into_fixedpoint_str(1), "12345678");
        assert_eq!(Amount { fixed_point_integer: 1234567890 }.into_fixedpoint_str(1), "123456789");
        assert_eq!(Amount { fixed_point_integer: 12345678900 }.into_fixedpoint_str(1), "1234567890");
        assert_eq!(Amount { fixed_point_integer: 123456789010 }.into_fixedpoint_str(1), "12345678901");
        assert_eq!(Amount { fixed_point_integer: 1234567890120 }.into_fixedpoint_str(1), "123456789012");
        assert_eq!(Amount { fixed_point_integer: 12345678901230 }.into_fixedpoint_str(1), "1234567890123");
        assert_eq!(Amount { fixed_point_integer: 100 }.into_fixedpoint_str(1), "10");
        assert_eq!(Amount { fixed_point_integer: 1200 }.into_fixedpoint_str(1), "120");
        assert_eq!(Amount { fixed_point_integer: 12300 }.into_fixedpoint_str(1), "1230");
        assert_eq!(Amount { fixed_point_integer: 123400 }.into_fixedpoint_str(1), "12340");
        assert_eq!(Amount { fixed_point_integer: 1234500 }.into_fixedpoint_str(1), "123450");
        assert_eq!(Amount { fixed_point_integer: 12345600 }.into_fixedpoint_str(1), "1234560");
        assert_eq!(Amount { fixed_point_integer: 123456700 }.into_fixedpoint_str(1), "12345670");
        assert_eq!(Amount { fixed_point_integer: 1234567800 }.into_fixedpoint_str(1), "123456780");
        assert_eq!(Amount { fixed_point_integer: 12345678900 }.into_fixedpoint_str(1), "1234567890");
        assert_eq!(Amount { fixed_point_integer: 123456789000 }.into_fixedpoint_str(1), "12345678900");
        assert_eq!(Amount { fixed_point_integer: 1234567890100 }.into_fixedpoint_str(1), "123456789010");
        assert_eq!(Amount { fixed_point_integer: 12345678901200 }.into_fixedpoint_str(1), "1234567890120");
        assert_eq!(Amount { fixed_point_integer: 123456789012300 }.into_fixedpoint_str(1), "12345678901230");
    }
}
