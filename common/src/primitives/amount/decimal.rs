// Copyright (c) 2024 RBB S.r.l
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

use std::fmt::Write;

use utils::ensure;

use super::{Amount, UnsignedIntType};

const TEN: UnsignedIntType = 10;

/// Amount in fractional representation
///
/// Keeps track of the number of decimal digits that should be presented to the user. This is
/// mostly for presentation purposes so does not define any arithmetic operations. Convert to
/// `Amount` if arithmetic is needed.
///
/// Comparison operators are deliberately left out too. The reason is that there are two sensible
/// ways to compare `DecimalAmount`s:
/// 1. Compare the numerical values that they signify
/// 2. Compare the implied textual representation, e.g. "1.0" and "1.000" are considered different
/// The user is expected to convert to a number or a string before comparing to explicitly state
/// which for of comparison is desired in any given situation.
#[derive(Clone, Copy, Debug, serde_with::DeserializeFromStr, serde_with::SerializeDisplay)]
pub struct DecimalAmount {
    mantissa: UnsignedIntType,
    decimals: u8,
}

impl DecimalAmount {
    pub const ZERO: Self = Self::from_uint_integral(0);

    /// Convert from integer with no decimals
    pub const fn from_uint_integral(number: u128) -> Self {
        Self::from_uint_decimal(number, 0)
    }

    /// Convert from integer, interpreting the last N digits as the fractional part
    pub const fn from_uint_decimal(mantissa: UnsignedIntType, decimals: u8) -> Self {
        Self { mantissa, decimals }
    }

    /// Convert from amount, keeping all decimal digits
    pub const fn from_amount_full_padding(amount: Amount, decimals: u8) -> Self {
        Self::from_uint_decimal(amount.into_atoms(), decimals)
    }

    /// Convert from amount, keeping as few decimal digits as possible (without losing precision)
    pub const fn from_amount_no_padding(amount: Amount, decimals: u8) -> Self {
        Self::from_amount_full_padding(amount, decimals).without_padding()
    }

    /// Convert to amount using given number of decimals
    pub fn to_amount(self, decimals: u8) -> Option<Amount> {
        Some(Amount::from_atoms(self.with_decimals(decimals)?.mantissa))
    }

    /// Change the number of decimals. Can only increase decimals, otherwise we risk losing digits.
    pub fn with_decimals(self, decimals: u8) -> Option<Self> {
        let extra_decimals = decimals.checked_sub(self.decimals)?;
        let mantissa = self.mantissa.checked_mul(TEN.checked_pow(extra_decimals as u32)?)?;
        Some(Self::from_uint_decimal(mantissa, decimals))
    }

    /// Trim trailing zeroes in the fractional part
    pub const fn without_padding(mut self) -> Self {
        while self.decimals > 0 && self.mantissa % TEN == 0 {
            self.mantissa /= TEN;
            self.decimals -= 1;
        }
        self
    }

    /// Check this is the same number presented with the same precision
    pub fn is_same(&self, other: &Self) -> bool {
        (self.mantissa, self.decimals) == (other.mantissa, other.decimals)
    }

    pub fn mantissa(&self) -> UnsignedIntType {
        self.mantissa
    }

    pub fn decimals(&self) -> u8 {
        self.decimals
    }
}

fn empty_to_zero(s: &str) -> &str {
    match s {
        "" => "0",
        s => s,
    }
}

impl std::str::FromStr for DecimalAmount {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ensure!(s.len() <= 100, ParseError::StringTooLong);

        let s = s.trim_matches(' ');
        let s = s.replace('_', "");
        ensure!(!s.is_empty(), ParseError::EmptyString);

        let (int_str, frac_str) = s.split_once('.').unwrap_or((&s, ""));

        let mut chars = int_str.chars().chain(frac_str.chars());
        ensure!(chars.all(|c| c.is_ascii_digit()), ParseError::IllegalChar);
        ensure!(int_str.len() + frac_str.len() > 0, ParseError::NoDigits);

        let int: UnsignedIntType = empty_to_zero(int_str).parse()?;
        let frac: UnsignedIntType = empty_to_zero(frac_str).parse()?;

        let decimals: u8 = frac_str.len().try_into().expect("Checked string length above");

        let mantissa = TEN
            .checked_pow(decimals as u32)
            .and_then(|mul| int.checked_mul(mul))
            .and_then(|shifted| shifted.checked_add(frac))
            .ok_or(ParseError::OutOfRange)?;

        Ok(Self::from_uint_decimal(mantissa, decimals))
    }
}

impl std::fmt::Display for DecimalAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mantissa = self.mantissa;
        let decimals = self.decimals as usize;

        if decimals > 0 {
            // Max string length: ceil(log10(u128::MAX)) + 1 for decimal point = 40
            let mut buffer = String::with_capacity(40);
            write!(&mut buffer, "{mantissa:0>width$}", width = decimals + 1)?;
            assert!(buffer.len() > decimals);
            buffer.insert(buffer.len() - decimals, '.');
            f.pad(&buffer)
        } else {
            mantissa.fmt(f)
        }
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ParseError {
    #[error("Resulting number is too big")]
    OutOfRange,

    #[error("The number string is too long")]
    StringTooLong,

    #[error("Empty input")]
    EmptyString,

    #[error("Invalid character used in number")]
    IllegalChar,

    #[error("Number does not contain any digits")]
    NoDigits,

    #[error(transparent)]
    IntParse(#[from] std::num::ParseIntError),
}

/// Just like [DecimalAmount] but useful in error types, picking a different set of trade-offs.
///
/// While [DecimalAmount] is intended to be used as a type to serialize/deserialize amounts to/from
/// a string, [DisplayAmount] is for printing only. It has an equality comparison (comparing the
/// string representation). To prevent the result of the comparison from affecting subsequent
/// [Amount] calculations, there is no easy way of converting `DisplayAmount` to `Amount`.
///
/// To further encourage debuggability, we only provide the `from_amount_full` constructor for
/// converting from `Amount` while `from_amount_minimal` is omitted. The full variant keeps all the
/// trailing zeros, making it possible to see the amount both in coin/token units and in atoms.
///
/// This is most useful in error types where we want to display the amount and subsequently compare
/// the errors for equality in tests.
#[derive(Clone, Copy)]
pub struct DisplayAmount(DecimalAmount);

impl DisplayAmount {
    /// Convert from [DecimalAmount]
    pub const fn from_decimal_amount(value: DecimalAmount) -> Self {
        Self(value)
    }

    /// Convert from integer with no decimals
    pub const fn from_uint_integral(number: u128) -> Self {
        Self(DecimalAmount::from_uint_integral(number))
    }

    /// Convert from integer, interpreting the last N digits as the fractional part
    pub const fn from_uint_decimal(mantissa: UnsignedIntType, decimals: u8) -> Self {
        Self(DecimalAmount::from_uint_decimal(mantissa, decimals))
    }

    /// Convert from [Amount], keeping all decimal digits
    pub const fn from_amount_full(amount: Amount, decimals: u8) -> Self {
        Self(DecimalAmount::from_amount_full_padding(amount, decimals))
    }
}

impl std::cmp::PartialEq for DisplayAmount {
    fn eq(&self, other: &Self) -> bool {
        self.0.is_same(&other.0)
    }
}

impl std::cmp::Eq for DisplayAmount {}

impl From<DecimalAmount> for DisplayAmount {
    fn from(value: DecimalAmount) -> Self {
        Self::from_decimal_amount(value)
    }
}

impl std::fmt::Display for DisplayAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Debug for DisplayAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[rstest::rstest]
    // Zero decimals
    #[case("0", DecimalAmount::from_uint_integral(0))]
    #[case("00", DecimalAmount::from_uint_integral(0))]
    #[case("5", DecimalAmount::from_uint_integral(5))]
    #[case("123", DecimalAmount::from_uint_integral(123))]
    #[case("0123", DecimalAmount::from_uint_integral(123))]
    #[case("55555", DecimalAmount::from_uint_integral(55555))]
    #[case("9999", DecimalAmount::from_uint_integral(9999))]
    #[case(
        "340282366920938463463374607431768211455",
        DecimalAmount::from_uint_integral(u128::MAX)
    )]
    // Trailing dot
    #[case("0123.", DecimalAmount::from_uint_integral(123))]
    #[case("55555.", DecimalAmount::from_uint_integral(55555))]
    #[case("9999.", DecimalAmount::from_uint_integral(9999))]
    #[case(
        "340282366920938463463374607431768211455.",
        DecimalAmount::from_uint_integral(u128::MAX)
    )]
    // One decimal
    #[case("0.0", DecimalAmount::from_uint_decimal(0, 1))]
    #[case("00.0", DecimalAmount::from_uint_decimal(0, 1))]
    #[case("5.3", DecimalAmount::from_uint_decimal(53, 1))]
    #[case("123.0", DecimalAmount::from_uint_decimal(1230, 1))]
    #[case("0123.4", DecimalAmount::from_uint_decimal(1234, 1))]
    #[case("55555.0", DecimalAmount::from_uint_decimal(555550, 1))]
    #[case("9999.0", DecimalAmount::from_uint_decimal(99990, 1))]
    #[case("0123.7", DecimalAmount::from_uint_decimal(1237, 1))]
    #[case("55555.6", DecimalAmount::from_uint_decimal(555556, 1))]
    #[case("9999.9", DecimalAmount::from_uint_decimal(99999, 1))]
    #[case(
        "34028236692093846346337460743176821.1455",
        DecimalAmount::from_uint_decimal(u128::MAX, 4)
    )]
    fn parse_ok(#[case] s: &str, #[case] amt: DecimalAmount) {
        assert!(amt.is_same(&s.parse().expect("parsing failed")));

        let roundtrip = amt.to_string().parse().expect("parsing failed");
        assert!(amt.is_same(&roundtrip));
    }

    #[rstest::rstest]
    #[case("", ParseError::EmptyString)]
    #[case("  ", ParseError::EmptyString)]
    #[case(" _ _ ", ParseError::IllegalChar)]
    #[case(".", ParseError::NoDigits)]
    #[case("._", ParseError::NoDigits)]
    #[case("_.", ParseError::NoDigits)]
    #[case("_._", ParseError::NoDigits)]
    #[case("_.___", ParseError::NoDigits)]
    #[case("x", ParseError::IllegalChar)]
    #[case("-", ParseError::IllegalChar)]
    #[case("%", ParseError::IllegalChar)]
    #[case("13.5e2", ParseError::IllegalChar)]
    #[case("34028236692093846346337460743176821145.6", ParseError::OutOfRange)]
    #[case("3.40282366920938463463374607431768211456", ParseError::OutOfRange)]
    #[case(
        "99999_99999_99999_99999_99999.99999_99999_99999_99999_99999",
        ParseError::OutOfRange
    )]
    fn parse_err(#[case] s: &str, #[case] expected_err: ParseError) {
        let err = s.parse::<DecimalAmount>().expect_err("parsing succeeded");
        assert_eq!(err, expected_err);
    }
}
