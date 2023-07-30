// Copyright (c) 2023 RBB S.r.l
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

use crypto::random::Rng;
use serialization::{Decode, Encode, Error, Input};

use super::Amount;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Encode, Debug)]
pub struct PerThousand(u16);

impl PerThousand {
    pub const fn new(value: u16) -> Option<Self> {
        if value <= 1000 {
            Some(Self(value))
        } else {
            None
        }
    }

    pub fn new_from_rng(rng: &mut impl Rng) -> Self {
        Self(rng.gen_range(0..=1000))
    }

    pub fn value(&self) -> u16 {
        self.0
    }

    pub fn from_decimal_str(s: &str) -> Option<Self> {
        // TODO: abstract from_fixedpoint_str() outside of Amount
        let amount = if s.trim().ends_with("%") {
            let s = s.trim_end_matches('%');
            let amount = Amount::from_fixedpoint_str(s, 1)?;
            amount
        } else {
            let amount = Amount::from_fixedpoint_str(s, 3)?;
            amount
        };
        let value: u16 = amount.into_atoms().try_into().ok()?;

        let result = Self::new(value)?;
        Some(result)
    }
}

impl Decode for PerThousand {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let decoded_value = u16::decode(input)?;
        Self::new(decoded_value).ok_or(
            serialization::Error::from("PerThousand deserialization failed")
                .chain(format!("With decoded value: {}", decoded_value)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crypto::random::Rng;
    use rstest::rstest;
    use test_utils::random::Seed;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_from_decimal_str(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        for _ in 0..1000 {
            let value = rng.gen_range(0..=1000);
            let per_thousand = PerThousand::new(value).unwrap();
            let per_thousand_str =
                Amount::into_fixedpoint_str(Amount::from_atoms(value as u128), 3);
            let per_thousand_str_percent =
                Amount::into_fixedpoint_str(Amount::from_atoms(value as u128), 1) + "%";
            assert_eq!(
                PerThousand::from_decimal_str(&per_thousand_str).unwrap(),
                per_thousand
            );
            assert_eq!(
                PerThousand::from_decimal_str(&per_thousand_str_percent).unwrap(),
                per_thousand
            );
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_per_thousand(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        assert!(PerThousand::new_from_rng(&mut rng).value() <= 1000);

        assert_eq!(PerThousand::new(0).unwrap().value(), 0);
        assert_eq!(PerThousand::new(1000).unwrap().value(), 1000);

        assert!(PerThousand::new(1001).is_none());
        assert!(PerThousand::new(u16::MAX).is_none());

        {
            let valid_value = rng.gen_range(0..=1000);
            assert_eq!(PerThousand::new(valid_value).unwrap().value(), valid_value);
        }

        {
            let invalid_value = rng.gen_range(1001..=u16::MAX);
            assert!(PerThousand::new(invalid_value).is_none());
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_encode_decode(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let encoded_valid = PerThousand::new_from_rng(&mut rng).encode();
        PerThousand::decode(&mut encoded_valid.as_slice()).unwrap();

        let encoded_invalid = rng.gen_range(1001..=u16::MAX).encode();
        PerThousand::decode(&mut encoded_invalid.as_slice()).unwrap_err();

        let mut encoded_1001: &[u8] = b"\xE9\x03";
        PerThousand::decode(&mut encoded_1001).unwrap_err();
    }
}
