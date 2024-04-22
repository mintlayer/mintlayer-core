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

use super::{signed::SignedIntType, *};

use randomness::Rng;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

#[test]
fn creation() {
    let x = Amount::from_atoms(555);
    assert_eq!(x, Amount { atoms: 555 });

    let y = Amount::from_atoms(123);
    assert_eq!(y, Amount { atoms: 123 });
}

#[test]
fn add_some() {
    assert_eq!(
        Amount { atoms: 2 } + Amount { atoms: 2 },
        Some(Amount { atoms: 4 })
    );
}

#[test]
fn sub_some() {
    assert_eq!(
        Amount { atoms: 4 } - Amount { atoms: 2 },
        Some(Amount { atoms: 2 })
    );
}

#[test]
fn mul_some() {
    assert_eq!(Amount { atoms: 3 } * 3, Some(Amount { atoms: 9 }));
}

#[test]
fn div_some() {
    assert_eq!(Amount { atoms: 9 } / 3, Some(Amount { atoms: 3 }));
}

#[test]
fn rem_some() {
    assert_eq!(Amount { atoms: 9 } % 4, Some(Amount { atoms: 1 }));
}

#[test]
fn add_overflow() {
    assert_eq!(
        Amount {
            atoms: UnsignedIntType::MAX
        } + Amount { atoms: 1 },
        None
    );
}

#[test]
fn sum_some() {
    let amounts = vec![Amount { atoms: 1 }, Amount { atoms: 2 }, Amount { atoms: 3 }];
    assert_eq!(
        amounts.into_iter().sum::<Option<Amount>>(),
        Some(Amount { atoms: 6 })
    );
}

#[test]
fn sum_overflow() {
    let amounts = vec![
        Amount { atoms: 1 },
        Amount { atoms: 2 },
        Amount {
            atoms: UnsignedIntType::MAX - 2,
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
            atoms: UnsignedIntType::MIN
        } - Amount { atoms: 1 },
        None
    );
}

#[test]
fn mul_overflow() {
    assert_eq!(
        Amount {
            atoms: UnsignedIntType::MAX / 2 + 1
        } * 2,
        None
    );
}

#[test]
fn comparison() {
    assert!(Amount { atoms: 1 } != Amount { atoms: 2 });
    assert!(Amount { atoms: 1 } < Amount { atoms: 2 });
    assert!(Amount { atoms: 1 } <= Amount { atoms: 2 });
    assert!(Amount { atoms: 2 } <= Amount { atoms: 2 });
    assert!(Amount { atoms: 2 } == Amount { atoms: 2 });
    assert!(Amount { atoms: 2 } >= Amount { atoms: 2 });
    assert!(Amount { atoms: 3 } > Amount { atoms: 2 });
}

#[test]
fn bit_ops() {
    let x = Amount { atoms: 5 };
    let y = Amount { atoms: 1 };
    let z = Amount { atoms: 2 };
    let zero: UnsignedIntType = 0;
    assert_eq!(x | y, Amount { atoms: 5 });
    assert_eq!(x & z, Amount { atoms: 0 });
    assert_eq!(x ^ y, Amount { atoms: 4 });
    assert_eq!(!zero, UnsignedIntType::MAX);
}

#[test]
fn bit_ops_assign() {
    let mut x = Amount { atoms: 5 };

    x ^= Amount { atoms: 1 };
    assert_eq!(x, Amount { atoms: 4 });

    x |= Amount { atoms: 2 };
    assert_eq!(x, Amount { atoms: 6 });

    x &= Amount { atoms: 5 };
    assert_eq!(x, Amount { atoms: 4 });
}

#[test]
fn bit_shifts() {
    let x = Amount { atoms: 1 };
    assert_eq!(x << 1, Some(Amount { atoms: 2 }));
    assert_eq!(x << 2, Some(Amount { atoms: 4 }));
    assert_eq!(x << 4, Some(Amount { atoms: 16 }));
    assert_eq!(x << 6, Some(Amount { atoms: 64 }));

    let y = Amount { atoms: 128 };
    assert_eq!(y >> 1, Some(Amount { atoms: 64 }));
    assert_eq!(y >> 2, Some(Amount { atoms: 32 }));
    assert_eq!(y >> 4, Some(Amount { atoms: 8 }));
    assert_eq!(y >> 6, Some(Amount { atoms: 2 }));
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
        assert_eq!(Amount::from_fixedpoint_str("987654321", 8).unwrap(), Amount { atoms: 98765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("87654321", 8).unwrap(), Amount { atoms: 8765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("7654321", 8).unwrap(), Amount { atoms: 765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("654321", 8).unwrap(), Amount { atoms: 65432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("54321", 8).unwrap(), Amount { atoms: 5432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("4321", 8).unwrap(), Amount { atoms: 432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("321", 8).unwrap(), Amount { atoms: 32100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21", 8).unwrap(), Amount { atoms: 2100000000 });
        assert_eq!(Amount::from_fixedpoint_str("1", 8).unwrap(), Amount { atoms: 100000000 });
        assert_eq!(Amount::from_fixedpoint_str("1.2", 8).unwrap(), Amount { atoms: 120000000 });
        assert_eq!(Amount::from_fixedpoint_str("1.23", 8).unwrap(), Amount { atoms: 123000000 });
        assert_eq!(Amount::from_fixedpoint_str("1.234", 8).unwrap(), Amount { atoms: 123400000 });
        assert_eq!(Amount::from_fixedpoint_str("1.2345", 8).unwrap(), Amount { atoms: 123450000 });
        assert_eq!(Amount::from_fixedpoint_str("1.23456", 8).unwrap(), Amount { atoms: 123456000 });
        assert_eq!(Amount::from_fixedpoint_str("1.234567", 8).unwrap(), Amount { atoms: 123456700 });
        assert_eq!(Amount::from_fixedpoint_str("1.2345678", 8).unwrap(), Amount { atoms: 123456780 });
        assert_eq!(Amount::from_fixedpoint_str("1.23456789", 8).unwrap(), Amount { atoms: 123456789 });
        assert_eq!(Amount::from_fixedpoint_str("21.23456789", 8).unwrap(), Amount { atoms: 2123456789 });
        assert_eq!(Amount::from_fixedpoint_str("321.23456789", 8).unwrap(), Amount { atoms: 32123456789 });
        assert_eq!(Amount::from_fixedpoint_str("4321.23456789", 8).unwrap(), Amount { atoms: 432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("54321.23456789", 8).unwrap(), Amount { atoms: 5432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("654321.23456789", 8).unwrap(), Amount { atoms: 65432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("7654321.23456789", 8).unwrap(), Amount { atoms: 765432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("87654321.23456789", 8).unwrap(), Amount { atoms: 8765432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("987654321.23456789", 8).unwrap(), Amount { atoms: 98765432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("1987654321.23456789", 8).unwrap(), Amount { atoms: 198765432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.23456789", 8).unwrap(), Amount { atoms: 2198765432123456789 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.2345678", 8).unwrap(), Amount { atoms: 2198765432123456780 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.234567", 8).unwrap(), Amount { atoms: 2198765432123456700 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.23456", 8).unwrap(), Amount { atoms: 2198765432123456000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.2345", 8).unwrap(), Amount { atoms: 2198765432123450000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.234", 8).unwrap(), Amount { atoms: 2198765432123400000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.23", 8).unwrap(), Amount { atoms: 2198765432123000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.2", 8).unwrap(), Amount { atoms: 2198765432120000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.", 8).unwrap(), Amount { atoms: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.0", 8).unwrap(), Amount { atoms: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.00", 8).unwrap(), Amount { atoms: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.000", 8).unwrap(), Amount { atoms: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.0000", 8).unwrap(), Amount { atoms: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.00000", 8).unwrap(), Amount { atoms: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.000000", 8).unwrap(), Amount { atoms: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.0000000", 8).unwrap(), Amount { atoms: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.00000000", 8).unwrap(), Amount { atoms: 2198765432100000000 });
        assert_eq!(Amount::from_fixedpoint_str(".2", 8).unwrap(), Amount { atoms: 20000000 });
        assert_eq!(Amount::from_fixedpoint_str(".23", 8).unwrap(), Amount { atoms: 23000000 });
        assert_eq!(Amount::from_fixedpoint_str(".234", 8).unwrap(), Amount { atoms: 23400000 });
        assert_eq!(Amount::from_fixedpoint_str(".2345", 8).unwrap(), Amount { atoms: 23450000 });
        assert_eq!(Amount::from_fixedpoint_str(".23456", 8).unwrap(), Amount { atoms: 23456000 });
        assert_eq!(Amount::from_fixedpoint_str(".234567", 8).unwrap(), Amount { atoms: 23456700 });
        assert_eq!(Amount::from_fixedpoint_str(".2345678", 8).unwrap(), Amount { atoms: 23456780 });
        assert_eq!(Amount::from_fixedpoint_str(".23456789", 8).unwrap(), Amount { atoms: 23456789 });
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
        assert_eq!(Amount::from_fixedpoint_str("987654321", 0).unwrap(), Amount { atoms: 987654321 });
        assert_eq!(Amount::from_fixedpoint_str("87654321", 0).unwrap(), Amount { atoms: 87654321 });
        assert_eq!(Amount::from_fixedpoint_str("7654321", 0).unwrap(), Amount { atoms: 7654321 });
        assert_eq!(Amount::from_fixedpoint_str("654321", 0).unwrap(), Amount { atoms: 654321 });
        assert_eq!(Amount::from_fixedpoint_str("54321", 0).unwrap(), Amount { atoms: 54321 });
        assert_eq!(Amount::from_fixedpoint_str("4321", 0).unwrap(), Amount { atoms: 4321 });
        assert_eq!(Amount::from_fixedpoint_str("321", 0).unwrap(), Amount { atoms: 321 });
        assert_eq!(Amount::from_fixedpoint_str("21", 0).unwrap(), Amount { atoms: 21 });
        assert_eq!(Amount::from_fixedpoint_str("1", 0).unwrap(), Amount { atoms: 1 });
        assert_eq!(Amount::from_fixedpoint_str("987654321.", 0).unwrap(), Amount { atoms: 987654321 });
        assert_eq!(Amount::from_fixedpoint_str("87654321.", 0).unwrap(), Amount { atoms: 87654321 });
        assert_eq!(Amount::from_fixedpoint_str("7654321.", 0).unwrap(), Amount { atoms: 7654321 });
        assert_eq!(Amount::from_fixedpoint_str("654321.", 0).unwrap(), Amount { atoms: 654321 });
        assert_eq!(Amount::from_fixedpoint_str("54321.", 0).unwrap(), Amount { atoms: 54321 });
        assert_eq!(Amount::from_fixedpoint_str("4321.", 0).unwrap(), Amount { atoms: 4321 });
        assert_eq!(Amount::from_fixedpoint_str("321.", 0).unwrap(), Amount { atoms: 321 });
        assert_eq!(Amount::from_fixedpoint_str("21.", 0).unwrap(), Amount { atoms: 21 });
        assert_eq!(Amount::from_fixedpoint_str("1.", 0).unwrap(), Amount { atoms: 1 });
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
        assert_eq!(Amount::from_fixedpoint_str("21987654321.", 0).unwrap(), Amount { atoms: 21987654321 });
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
        assert_eq!(Amount::from_fixedpoint_str("987654321", 1).unwrap(), Amount { atoms: 9876543210 });
        assert_eq!(Amount::from_fixedpoint_str("87654321", 1).unwrap(), Amount { atoms: 876543210 });
        assert_eq!(Amount::from_fixedpoint_str("7654321", 1).unwrap(), Amount { atoms: 76543210 });
        assert_eq!(Amount::from_fixedpoint_str("654321", 1).unwrap(), Amount { atoms: 6543210 });
        assert_eq!(Amount::from_fixedpoint_str("54321", 1).unwrap(), Amount { atoms: 543210 });
        assert_eq!(Amount::from_fixedpoint_str("4321", 1).unwrap(), Amount { atoms: 43210 });
        assert_eq!(Amount::from_fixedpoint_str("321", 1).unwrap(), Amount { atoms: 3210 });
        assert_eq!(Amount::from_fixedpoint_str("21", 1).unwrap(), Amount { atoms: 210 });
        assert_eq!(Amount::from_fixedpoint_str("1", 1).unwrap(), Amount { atoms: 10 });
        assert_eq!(Amount::from_fixedpoint_str("1.2", 1).unwrap(), Amount { atoms: 12 });
        assert_eq!(Amount::from_fixedpoint_str(".2", 1).unwrap(), Amount { atoms: 2 });
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
        assert_eq!(Amount::from_fixedpoint_str("21987654321.2", 1).unwrap(), Amount { atoms: 219876543212 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.", 1).unwrap(), Amount { atoms: 219876543210 });
        assert_eq!(Amount::from_fixedpoint_str("21987654321.0", 1).unwrap(), Amount { atoms: 219876543210 });
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
        assert_eq!(Amount { atoms: 0 }.into_fixedpoint_str(8), "0");
        assert_eq!(Amount { atoms: 1 }.into_fixedpoint_str(8), "0.00000001");
        assert_eq!(Amount { atoms: 12 }.into_fixedpoint_str(8), "0.00000012");
        assert_eq!(Amount { atoms: 123 }.into_fixedpoint_str(8), "0.00000123");
        assert_eq!(Amount { atoms: 1234 }.into_fixedpoint_str(8), "0.00001234");
        assert_eq!(Amount { atoms: 12345 }.into_fixedpoint_str(8), "0.00012345");
        assert_eq!(Amount { atoms: 123456 }.into_fixedpoint_str(8), "0.00123456");
        assert_eq!(Amount { atoms: 1234567 }.into_fixedpoint_str(8), "0.01234567");
        assert_eq!(Amount { atoms: 12345678 }.into_fixedpoint_str(8), "0.12345678");
        assert_eq!(Amount { atoms: 112345678 }.into_fixedpoint_str(8), "1.12345678");
        assert_eq!(Amount { atoms: 2112345678 }.into_fixedpoint_str(8), "21.12345678");
        assert_eq!(Amount { atoms: 32112345678 }.into_fixedpoint_str(8), "321.12345678");
        assert_eq!(Amount { atoms: 432112345678 }.into_fixedpoint_str(8), "4321.12345678");
        assert_eq!(Amount { atoms: 5432112345678 }.into_fixedpoint_str(8), "54321.12345678");
        assert_eq!(Amount { atoms: 65432112345678 }.into_fixedpoint_str(8), "654321.12345678");
        assert_eq!(Amount { atoms: 765432112345678 }.into_fixedpoint_str(8), "7654321.12345678");
        assert_eq!(Amount { atoms: 8765432112345678 }.into_fixedpoint_str(8), "87654321.12345678");
        assert_eq!(Amount { atoms: 98765432112345678 }.into_fixedpoint_str(8), "987654321.12345678");
        assert_eq!(Amount { atoms: 10 }.into_fixedpoint_str(8), "0.0000001");
        assert_eq!(Amount { atoms: 120 }.into_fixedpoint_str(8), "0.0000012");
        assert_eq!(Amount { atoms: 1230 }.into_fixedpoint_str(8), "0.0000123");
        assert_eq!(Amount { atoms: 12340 }.into_fixedpoint_str(8), "0.0001234");
        assert_eq!(Amount { atoms: 123450 }.into_fixedpoint_str(8), "0.0012345");
        assert_eq!(Amount { atoms: 1234560 }.into_fixedpoint_str(8), "0.0123456");
        assert_eq!(Amount { atoms: 12345670 }.into_fixedpoint_str(8), "0.1234567");
        assert_eq!(Amount { atoms: 123456780 }.into_fixedpoint_str(8), "1.2345678");
        assert_eq!(Amount { atoms: 1123456780 }.into_fixedpoint_str(8), "11.2345678");
        assert_eq!(Amount { atoms: 100 }.into_fixedpoint_str(8), "0.000001");
        assert_eq!(Amount { atoms: 1200 }.into_fixedpoint_str(8), "0.000012");
        assert_eq!(Amount { atoms: 12300 }.into_fixedpoint_str(8), "0.000123");
        assert_eq!(Amount { atoms: 123400 }.into_fixedpoint_str(8), "0.001234");
        assert_eq!(Amount { atoms: 1234500 }.into_fixedpoint_str(8), "0.012345");
        assert_eq!(Amount { atoms: 12345600 }.into_fixedpoint_str(8), "0.123456");
        assert_eq!(Amount { atoms: 123456700 }.into_fixedpoint_str(8), "1.234567");
        assert_eq!(Amount { atoms: 1234567800 }.into_fixedpoint_str(8), "12.345678");
        assert_eq!(Amount { atoms: 11234567800 }.into_fixedpoint_str(8), "112.345678");
    }

#[rustfmt::skip]
    #[test]
    fn to_fixedpoint_0_decimals() {
        assert_eq!(Amount { atoms: 1 }.into_fixedpoint_str(0), "1");
        assert_eq!(Amount { atoms: 12 }.into_fixedpoint_str(0), "12");
        assert_eq!(Amount { atoms: 123 }.into_fixedpoint_str(0), "123");
        assert_eq!(Amount { atoms: 1234 }.into_fixedpoint_str(0), "1234");
        assert_eq!(Amount { atoms: 12345 }.into_fixedpoint_str(0), "12345");
        assert_eq!(Amount { atoms: 123456 }.into_fixedpoint_str(0), "123456");
        assert_eq!(Amount { atoms: 1234567 }.into_fixedpoint_str(0), "1234567");
        assert_eq!(Amount { atoms: 12345678 }.into_fixedpoint_str(0), "12345678");
        assert_eq!(Amount { atoms: 123456789 }.into_fixedpoint_str(0), "123456789");
        assert_eq!(Amount { atoms: 1234567890 }.into_fixedpoint_str(0), "1234567890");
        assert_eq!(Amount { atoms: 12345678901 }.into_fixedpoint_str(0), "12345678901");
        assert_eq!(Amount { atoms: 123456789012 }.into_fixedpoint_str(0), "123456789012");
        assert_eq!(Amount { atoms: 1234567890123 }.into_fixedpoint_str(0), "1234567890123");
        assert_eq!(Amount { atoms: 10 }.into_fixedpoint_str(0), "10");
        assert_eq!(Amount { atoms: 120 }.into_fixedpoint_str(0), "120");
        assert_eq!(Amount { atoms: 1230 }.into_fixedpoint_str(0), "1230");
        assert_eq!(Amount { atoms: 12340 }.into_fixedpoint_str(0), "12340");
        assert_eq!(Amount { atoms: 123450 }.into_fixedpoint_str(0), "123450");
        assert_eq!(Amount { atoms: 1234560 }.into_fixedpoint_str(0), "1234560");
        assert_eq!(Amount { atoms: 12345670 }.into_fixedpoint_str(0), "12345670");
        assert_eq!(Amount { atoms: 123456780 }.into_fixedpoint_str(0), "123456780");
        assert_eq!(Amount { atoms: 1234567890 }.into_fixedpoint_str(0), "1234567890");
        assert_eq!(Amount { atoms: 12345678900 }.into_fixedpoint_str(0), "12345678900");
        assert_eq!(Amount { atoms: 123456789010 }.into_fixedpoint_str(0), "123456789010");
        assert_eq!(Amount { atoms: 1234567890120 }.into_fixedpoint_str(0), "1234567890120");
        assert_eq!(Amount { atoms: 12345678901230 }.into_fixedpoint_str(0), "12345678901230");
        assert_eq!(Amount { atoms: 100 }.into_fixedpoint_str(0), "100");
        assert_eq!(Amount { atoms: 1200 }.into_fixedpoint_str(0), "1200");
        assert_eq!(Amount { atoms: 12300 }.into_fixedpoint_str(0), "12300");
        assert_eq!(Amount { atoms: 123400 }.into_fixedpoint_str(0), "123400");
        assert_eq!(Amount { atoms: 1234500 }.into_fixedpoint_str(0), "1234500");
        assert_eq!(Amount { atoms: 12345600 }.into_fixedpoint_str(0), "12345600");
        assert_eq!(Amount { atoms: 123456700 }.into_fixedpoint_str(0), "123456700");
        assert_eq!(Amount { atoms: 1234567800 }.into_fixedpoint_str(0), "1234567800");
        assert_eq!(Amount { atoms: 12345678900 }.into_fixedpoint_str(0), "12345678900");
        assert_eq!(Amount { atoms: 123456789000 }.into_fixedpoint_str(0), "123456789000");
        assert_eq!(Amount { atoms: 1234567890100 }.into_fixedpoint_str(0), "1234567890100");
        assert_eq!(Amount { atoms: 12345678901200 }.into_fixedpoint_str(0), "12345678901200");
        assert_eq!(Amount { atoms: 123456789012300 }.into_fixedpoint_str(0), "123456789012300");
    }

#[rustfmt::skip]
    #[test]
    fn to_fixedpoint_1_decimal() {
        assert_eq!(Amount { atoms: 1 }.into_fixedpoint_str(1), "0.1");
        assert_eq!(Amount { atoms: 12 }.into_fixedpoint_str(1), "1.2");
        assert_eq!(Amount { atoms: 123 }.into_fixedpoint_str(1), "12.3");
        assert_eq!(Amount { atoms: 1234 }.into_fixedpoint_str(1), "123.4");
        assert_eq!(Amount { atoms: 12345 }.into_fixedpoint_str(1), "1234.5");
        assert_eq!(Amount { atoms: 123456 }.into_fixedpoint_str(1), "12345.6");
        assert_eq!(Amount { atoms: 1234567 }.into_fixedpoint_str(1), "123456.7");
        assert_eq!(Amount { atoms: 12345678 }.into_fixedpoint_str(1), "1234567.8");
        assert_eq!(Amount { atoms: 123456789 }.into_fixedpoint_str(1), "12345678.9");
        assert_eq!(Amount { atoms: 1234567890 }.into_fixedpoint_str(1), "123456789");
        assert_eq!(Amount { atoms: 12345678901 }.into_fixedpoint_str(1), "1234567890.1");
        assert_eq!(Amount { atoms: 123456789012 }.into_fixedpoint_str(1), "12345678901.2");
        assert_eq!(Amount { atoms: 1234567890123 }.into_fixedpoint_str(1), "123456789012.3");
        assert_eq!(Amount { atoms: 10 }.into_fixedpoint_str(1), "1");
        assert_eq!(Amount { atoms: 120 }.into_fixedpoint_str(1), "12");
        assert_eq!(Amount { atoms: 1230 }.into_fixedpoint_str(1), "123");
        assert_eq!(Amount { atoms: 12340 }.into_fixedpoint_str(1), "1234");
        assert_eq!(Amount { atoms: 123450 }.into_fixedpoint_str(1), "12345");
        assert_eq!(Amount { atoms: 1234560 }.into_fixedpoint_str(1), "123456");
        assert_eq!(Amount { atoms: 12345670 }.into_fixedpoint_str(1), "1234567");
        assert_eq!(Amount { atoms: 123456780 }.into_fixedpoint_str(1), "12345678");
        assert_eq!(Amount { atoms: 1234567890 }.into_fixedpoint_str(1), "123456789");
        assert_eq!(Amount { atoms: 12345678900 }.into_fixedpoint_str(1), "1234567890");
        assert_eq!(Amount { atoms: 123456789010 }.into_fixedpoint_str(1), "12345678901");
        assert_eq!(Amount { atoms: 1234567890120 }.into_fixedpoint_str(1), "123456789012");
        assert_eq!(Amount { atoms: 12345678901230 }.into_fixedpoint_str(1), "1234567890123");
        assert_eq!(Amount { atoms: 100 }.into_fixedpoint_str(1), "10");
        assert_eq!(Amount { atoms: 1200 }.into_fixedpoint_str(1), "120");
        assert_eq!(Amount { atoms: 12300 }.into_fixedpoint_str(1), "1230");
        assert_eq!(Amount { atoms: 123400 }.into_fixedpoint_str(1), "12340");
        assert_eq!(Amount { atoms: 1234500 }.into_fixedpoint_str(1), "123450");
        assert_eq!(Amount { atoms: 12345600 }.into_fixedpoint_str(1), "1234560");
        assert_eq!(Amount { atoms: 123456700 }.into_fixedpoint_str(1), "12345670");
        assert_eq!(Amount { atoms: 1234567800 }.into_fixedpoint_str(1), "123456780");
        assert_eq!(Amount { atoms: 12345678900 }.into_fixedpoint_str(1), "1234567890");
        assert_eq!(Amount { atoms: 123456789000 }.into_fixedpoint_str(1), "12345678900");
        assert_eq!(Amount { atoms: 1234567890100 }.into_fixedpoint_str(1), "123456789010");
        assert_eq!(Amount { atoms: 12345678901200 }.into_fixedpoint_str(1), "1234567890120");
        assert_eq!(Amount { atoms: 123456789012300 }.into_fixedpoint_str(1), "12345678901230");
    }

#[test]
fn serde_serialization() {
    let amount: Amount = Amount::from_atoms(123553758873844226);

    let serialized = serde_json::to_string(&amount).unwrap();

    // Ensure that these don't change for backwards compatibility
    assert!(serialized.contains("\"123553758873844226\""));
    assert!(serialized.contains("\"atoms\""));

    let deserialized = serde_json::from_str::<AmountSerde>(&serialized).unwrap();
    assert_eq!(amount, deserialized.into());

    let deserialized_json_value = serde_json::from_str::<serde_json::Value>(&serialized).unwrap();

    assert_eq!(deserialized_json_value["atoms"], "123553758873844226");
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn serde_serialization_randomized(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let amount: Amount = Amount::from_atoms(rng.gen());

    let serialized = serde_json::to_string(&amount).unwrap();

    // Ensure that these don't change for backwards compatibility
    assert!(serialized.contains(&format!("\"{}\"", amount.into_atoms())));
    assert!(serialized.contains("\"atoms\""));

    let deserialized = serde_json::from_str::<AmountSerde>(&serialized).unwrap();
    assert_eq!(amount, deserialized.into());

    let deserialized_json_value = serde_json::from_str::<serde_json::Value>(&serialized).unwrap();

    assert_eq!(
        deserialized_json_value["atoms"],
        amount.into_atoms().to_string()
    );
}
