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

use std::fmt::Display;

use crypto::random::Rng;
use serialization::{Decode, Encode, Error, Input};
use thiserror::Error;

use super::Amount;

const DENOMINATOR: u16 = 1000;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Encode, Debug)]
pub struct PerThousand(u16);

impl PerThousand {
    pub const fn new(value: u16) -> Option<Self> {
        if value <= DENOMINATOR {
            Some(Self(value))
        } else {
            None
        }
    }

    pub fn new_from_rng(rng: &mut impl Rng) -> Self {
        Self(rng.gen_range(0..=DENOMINATOR))
    }

    pub fn value(&self) -> u16 {
        self.0
    }

    pub const fn denominator(&self) -> u16 {
        DENOMINATOR
    }

    #[allow(clippy::float_arithmetic)]
    pub fn as_f64(&self) -> f64 {
        self.0 as f64 / DENOMINATOR as f64
    }

    // Note: among other things, this function is used as Clap's value_parser, which requires it
    // to return a Result. That's why we return it here instead of Option,
    pub fn from_decimal_str(s: &str) -> Result<Self, PerThousandParseError> {
        let body = || {
            // TODO: abstract from_fixedpoint_str() outside of Amount
            let amount = if s.trim().ends_with('%') {
                let s = s.trim_end_matches('%');
                Amount::from_fixedpoint_str(s, 1)?
            } else {
                Amount::from_fixedpoint_str(s, 3)?
            };
            let value: u16 = amount.into_atoms().try_into().ok()?;

            let result = Self::new(value)?;
            Some(result)
        };

        body().ok_or_else(|| PerThousandParseError {
            bad_value: s.to_owned(),
        })
    }

    pub fn into_percentage_str(&self) -> String {
        let mut result = String::new();
        self.write_as_percentage_str(&mut result)
            .expect("Writing to string must succeed");
        result
    }

    fn write_as_percentage_str(&self, dest: &mut impl std::fmt::Write) -> std::fmt::Result {
        write!(
            dest,
            "{}%",
            Amount::from_atoms(self.0.into()).into_fixedpoint_str(1)
        )
    }
}

#[derive(Error, Debug)]
#[error("Incorrect per-thousand value: {bad_value}")]
pub struct PerThousandParseError {
    bad_value: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum StringOrUInt {
    String(String),
    UInt(u16),
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

impl Display for PerThousand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.write_as_percentage_str(f)
    }
}

impl<'de> serde::Deserialize<'de> for PerThousand {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;

        let value = match StringOrUInt::deserialize(deserializer)? {
            StringOrUInt::String(s) => Self::from_decimal_str(&s).map_err(|e| {
                D::Error::custom(format!(
                    "Provided String for PerThousand ({s}) is not a valid percentage or decimal. Error: {e}"
                ))
            })?,
            StringOrUInt::UInt(v) => {
                Self::new(v).ok_or(D::Error::custom(format!(
                    "Integer {} has invalid value for PerThousand",
                    v
                )))?
            }
        };
        Ok(value)
    }
}

impl serde::Serialize for PerThousand {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.into_percentage_str().serialize(serializer)
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
        for value in 0..=DENOMINATOR {
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
        // test an invalid value
        {
            let value = rng.gen_range(1001..u16::MAX);
            let per_thousand_str =
                Amount::into_fixedpoint_str(Amount::from_atoms(value as u128), 3);
            let per_thousand_str_percent =
                Amount::into_fixedpoint_str(Amount::from_atoms(value as u128), 1) + "%";
            assert!(PerThousand::from_decimal_str(&per_thousand_str).is_err());
            assert!(PerThousand::from_decimal_str(&per_thousand_str_percent).is_err());
        }
    }

    #[test]
    fn test_into_percentage_str() {
        assert_eq!(PerThousand::new(1).unwrap().into_percentage_str(), "0.1%");
        assert_eq!(PerThousand::new(10).unwrap().into_percentage_str(), "1%");
        assert_eq!(PerThousand::new(100).unwrap().into_percentage_str(), "10%");
        assert_eq!(
            PerThousand::new(1000).unwrap().into_percentage_str(),
            "100%"
        );

        assert_eq!(PerThousand::new(11).unwrap().into_percentage_str(), "1.1%");
        assert_eq!(PerThousand::new(23).unwrap().into_percentage_str(), "2.3%");
        assert_eq!(PerThousand::new(98).unwrap().into_percentage_str(), "9.8%");

        assert_eq!(
            PerThousand::new(311).unwrap().into_percentage_str(),
            "31.1%"
        );
        assert_eq!(
            PerThousand::new(564).unwrap().into_percentage_str(),
            "56.4%"
        );
        assert_eq!(
            PerThousand::new(827).unwrap().into_percentage_str(),
            "82.7%"
        );
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", PerThousand::new(1).unwrap()), "0.1%");
        assert_eq!(format!("{}", PerThousand::new(10).unwrap()), "1%");
        assert_eq!(format!("{}", PerThousand::new(100).unwrap()), "10%");
        assert_eq!(format!("{}", PerThousand::new(1000).unwrap()), "100%");

        assert_eq!(format!("{}", PerThousand::new(11).unwrap()), "1.1%");
        assert_eq!(format!("{}", PerThousand::new(23).unwrap()), "2.3%");
        assert_eq!(format!("{}", PerThousand::new(98).unwrap()), "9.8%");

        assert_eq!(format!("{}", PerThousand::new(311).unwrap()), "31.1%");
        assert_eq!(format!("{}", PerThousand::new(564).unwrap()), "56.4%");
        assert_eq!(format!("{}", PerThousand::new(827).unwrap()), "82.7%");
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_per_thousand(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        assert!(PerThousand::new_from_rng(&mut rng).value() <= DENOMINATOR);

        assert_eq!(PerThousand::new(0).unwrap().value(), 0);
        assert_eq!(PerThousand::new(DENOMINATOR).unwrap().value(), DENOMINATOR);

        assert!(PerThousand::new(1001).is_none());
        assert!(PerThousand::new(u16::MAX).is_none());

        {
            let valid_value = rng.gen_range(0..=DENOMINATOR);
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

    #[test]
    fn test_json_basic() {
        let v = PerThousand::new(15).unwrap();
        let v_json = serde_json::to_string(&v).unwrap();
        assert_eq!("\"1.5%\"", &v_json);
        let v_decoded = serde_json::from_str::<PerThousand>(&v_json).unwrap();
        assert_eq!(v_decoded, v);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_json_roundtrip(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let v = PerThousand::new_from_rng(&mut rng);

        let v_json = serde_json::to_string(&v).unwrap();
        let v_decoded = serde_json::from_str::<PerThousand>(&v_json).unwrap();
        assert_eq!(v_decoded, v);
    }

    #[test]
    fn test_json_decoding() {
        assert_eq!(
            PerThousand::new(20).unwrap(),
            serde_json::from_str::<PerThousand>("\"2.0%\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(20).unwrap(),
            serde_json::from_str::<PerThousand>("\"2%\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(20).unwrap(),
            serde_json::from_str::<PerThousand>("\"0.02\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(20).unwrap(),
            serde_json::from_str::<PerThousand>("20").unwrap()
        );

        ////////////////////////////////////////////////////////////////////////

        assert_eq!(
            PerThousand::new(1000).unwrap(),
            serde_json::from_str::<PerThousand>("\"100%\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(1000).unwrap(),
            serde_json::from_str::<PerThousand>("\"100.%\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(1000).unwrap(),
            serde_json::from_str::<PerThousand>("\"100.0%\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(1000).unwrap(),
            serde_json::from_str::<PerThousand>("\"1\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(1000).unwrap(),
            serde_json::from_str::<PerThousand>("\"1.\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(1000).unwrap(),
            serde_json::from_str::<PerThousand>("1000").unwrap()
        );

        ////////////////////////////////////////////////////////////////////////

        assert_eq!(
            PerThousand::new(0).unwrap(),
            serde_json::from_str::<PerThousand>("\"0%\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(0).unwrap(),
            serde_json::from_str::<PerThousand>("\"0.%\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(0).unwrap(),
            serde_json::from_str::<PerThousand>("\"0.0%\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(0).unwrap(),
            serde_json::from_str::<PerThousand>("\"0.0\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(0).unwrap(),
            serde_json::from_str::<PerThousand>("\"0.\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(0).unwrap(),
            serde_json::from_str::<PerThousand>("\"0\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(0).unwrap(),
            serde_json::from_str::<PerThousand>("\".0\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(0).unwrap(),
            serde_json::from_str::<PerThousand>("0").unwrap()
        );

        ////////////////////////////////////////////////////////////////////////

        assert_eq!(
            PerThousand::new(1).unwrap(),
            serde_json::from_str::<PerThousand>("\".1%\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(1).unwrap(),
            serde_json::from_str::<PerThousand>("\"0.1%\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(1).unwrap(),
            serde_json::from_str::<PerThousand>("\".1%\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(1).unwrap(),
            serde_json::from_str::<PerThousand>("\"0.001\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(1).unwrap(),
            serde_json::from_str::<PerThousand>("\".001\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(1).unwrap(),
            serde_json::from_str::<PerThousand>("1").unwrap()
        );

        ////////////////////////////////////////////////////////////////////////

        assert_eq!(
            PerThousand::new(421).unwrap(),
            serde_json::from_str::<PerThousand>("\"42.1%\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(421).unwrap(),
            serde_json::from_str::<PerThousand>("\"0.421\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(421).unwrap(),
            serde_json::from_str::<PerThousand>("\".421\"").unwrap()
        );

        assert_eq!(
            PerThousand::new(421).unwrap(),
            serde_json::from_str::<PerThousand>("421").unwrap()
        );
    }
}
