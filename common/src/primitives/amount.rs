// use only unsigned types
// if you need a signed amount, we should create a separate type for it and implement proper conversion
pub type IntType = u128;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Amount {
    val: IntType,
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

impl std::ops::Mul for Amount {
    type Output = Option<Self>;

    fn mul(self, other: Self) -> Option<Self> {
        self.val.checked_mul(other.val).map(|n| Amount { val: n })
    }
}

impl std::ops::Div for Amount {
    type Output = Option<Self>;

    fn div(self, other: Self) -> Option<Self> {
        self.val.checked_div(other.val).map(|n| Amount { val: n })
    }
}

impl std::ops::Rem for Amount {
    type Output = Option<Self>;

    fn rem(self, other: Self) -> Option<Self> {
        self.val.checked_rem(other.val).map(|n| Amount { val: n })
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

impl std::ops::Shl for Amount {
    type Output = Self;

    fn shl(self, other: Self) -> Self {
        Amount {
            val: self.val.shl(other.val),
        }
    }
}

impl std::ops::ShlAssign for Amount {
    fn shl_assign(&mut self, other: Self) {
        self.val.shl_assign(other.val)
    }
}

impl std::ops::Shr for Amount {
    type Output = Self;

    fn shr(self, other: Self) -> Self {
        Amount {
            val: self.val.shr(other.val),
        }
    }
}

impl std::ops::ShrAssign for Amount {
    fn shr_assign(&mut self, other: Self) {
        self.val.shr_assign(other.val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(
            Amount { val: 3 } * Amount { val: 3 },
            Some(Amount { val: 9 })
        );
    }

    #[test]
    fn div_some() {
        assert_eq!(
            Amount { val: 9 } / Amount { val: 3 },
            Some(Amount { val: 3 })
        );
    }

    #[test]
    fn rem_some() {
        assert_eq!(
            Amount { val: 9 } % Amount { val: 4 },
            Some(Amount { val: 1 })
        );
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
            } * Amount { val: 2 },
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
        let x = 5;
        let y = 1;
        let z = 2;
        let zero: IntType = 0;
        assert_eq!(x | y, 5);
        assert_eq!(x & z, 0);
        assert_eq!(x ^ y, 4);
        assert!(!zero == IntType::MAX);
    }

    #[test]
    fn bit_ops_assign() {
        let mut x = 5;

        x ^= 1;
        assert_eq!(x, 4);

        x |= 2;
        assert_eq!(x, 6);

        x &= 5;
        assert_eq!(x, 4);
    }

    #[test]
    fn bit_shifts() {
        let x = 1;
        assert_eq!(x << 1, 2);
        assert_eq!(x << 2, 4);
        assert_eq!(x << 4, 16);
        assert_eq!(x << 6, 64);

        let y = 128;
        assert_eq!(y >> 1, 64);
        assert_eq!(y >> 2, 32);
        assert_eq!(y >> 4, 8);
        assert_eq!(y >> 6, 2);
    }

    #[test]
    fn bit_shifts_assign() {
        let mut x = 1;
        x <<= 1;
        assert_eq!(x, 2);
        x <<= 1;
        assert_eq!(x, 4);
        x <<= 2;
        assert_eq!(x, 16);
        x <<= 2;
        assert_eq!(x, 64);

        let mut y = 128;
        y >>= 1;
        assert_eq!(y, 64);
        y >>= 1;
        assert_eq!(y, 32);
        y >>= 2;
        assert_eq!(y, 8);
        y >>= 2;
        assert_eq!(y, 2);
    }
}
