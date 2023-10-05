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

use crate::chain::ChainConfig;

use super::{traits::Addressable, Address};
use regex::Regex;
use serde::{de::Error, Deserialize};
use serialization::DecodeAll;

const REGEX_SUFFIX: &str = r"\{0x([0-9a-fA-F]+)\}";

/// A hexified address is an address that's formatted in such a way that it can be safely replaced with a real address using the object Address<A>.
/// This whole thing is a workaround due to the fact that serde doesn't support stateful serialization, so the ChainConfig cannot be passed while
/// serializing.
pub struct HexifiedAddress<'a, A> {
    addressable: &'a A,
}

impl<'a, A: Addressable + DecodeAll + 'a> HexifiedAddress<'a, A> {
    pub fn new(addressable: &'a A) -> Self {
        Self { addressable }
    }

    fn make_regex_pattern() -> String {
        A::json_wrapper_prefix().to_string() + REGEX_SUFFIX
    }

    fn make_regex_object() -> Regex {
        Regex::new(&Self::make_regex_pattern()).expect("Regex pattern cannot fail")
    }

    pub fn is_hexified_address(target_str: &str) -> bool {
        let matcher = Self::make_regex_object();
        matcher.is_match(target_str)
    }

    pub fn extract_hexified_address(target_str: impl AsRef<str>) -> Option<String> {
        let matcher = Self::make_regex_object();
        let caps = matcher.captures(target_str.as_ref())?;
        let hex_data = caps.get(1)?.as_str();
        Some(hex_data.to_string())
    }

    #[must_use]
    pub fn replace_with_address(chain_config: &ChainConfig, target_str: &str) -> String {
        let matcher = Self::make_regex_object();
        let replacer = AddressableReplacer::<A>::new(chain_config);
        let result = matcher.replace_all(target_str, replacer);

        result.to_string()
    }

    /// Deserialize a hex string with proper error reporting
    fn serde_hex_deserialize<'de, D>(
        hex_string: impl AsRef<str> + std::fmt::Display,
    ) -> Result<A, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_string = if hex_string.as_ref().starts_with("0x") {
            // Get rid of the 0x prefix
            hex_string.as_ref().trim_start_matches("0x")
        } else {
            hex_string.as_ref()
        };

        let bytes = hex::decode(hex_string).map_err(|e| {
                D::Error::custom(format!(
                "Failed to decode hex to bytes for address from string {hex_string} with hexified json prefix {} with error {e}",
                A::json_wrapper_prefix()
            ))
            })?;
        let obj = A::decode_all(&mut &*bytes).map_err(|e| {
                D::Error::custom(format!(
                "Failed to decode bytes to object for address from string {hex_string} with hexified json prefix {} with error {e}",
                A::json_wrapper_prefix()
            ))
            })?;

        Ok(obj)
    }

    pub fn serde_serialize<S>(addressable: &'a A, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&Self::new(addressable).to_string())
    }

    pub fn serde_deserialize<'de, D>(deserializer: D) -> Result<A, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if Self::is_hexified_address(&s) {
            // If the object is hexified and isn't an address, we de-hexify it

            let hex_string =
                Self::extract_hexified_address(&s).ok_or(D::Error::custom(format!(
                "Failed to extract hexified address from string {s} with hexified json prefix {}",
                A::json_wrapper_prefix()
            )))?;

            Self::serde_hex_deserialize::<D>(&hex_string)
        } else if s.starts_with("0x") {
            Self::serde_hex_deserialize::<D>(&s)
        } else {
            Address::<A>::from_str_no_hrp_verify(&s).map_err(D::Error::custom)
        }
    }
}

impl<'a, A: Addressable> std::fmt::Display for HexifiedAddress<'a, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let result = format!(
            "{}{{0x{}}}",
            A::json_wrapper_prefix(),
            hex::ToHex::encode_hex::<String>(&self.addressable.encode_to_bytes_for_address())
        );
        result.fmt(f)
    }
}

struct AddressableReplacer<'a, A> {
    chain_config: &'a ChainConfig,
    _marker: std::marker::PhantomData<A>,
}

impl<'a, A: Addressable> AddressableReplacer<'a, A> {
    pub fn new(chain_config: &'a ChainConfig) -> Self {
        Self {
            chain_config,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'a, A: Addressable + DecodeAll> regex::Replacer for AddressableReplacer<'a, A> {
    fn replace_append(&mut self, caps: &regex::Captures<'_>, dst: &mut String) {
        let hex_data = caps.get(1).expect("It's already verified it exists").as_str();
        let bytes = match hex::decode(hex_data) {
            Ok(bytes) => bytes,
            Err(_) => {
                logging::log::error!(
                    "While de-hexifying, failed to decode hex to bytes for a {}",
                    A::json_wrapper_prefix()
                );
                // replace with hex value
                dst.push_str("0x");
                dst.push_str(hex_data);
                return;
            }
        };
        let obj = match A::decode_all(&mut &*bytes) {
            Ok(obj) => obj,
            Err(_) => {
                logging::log::error!(
                    "While de-hexifying, failed to decode bytes to data for object for a {}",
                    A::json_wrapper_prefix()
                );
                // replace with hex value
                dst.push_str("0x");
                dst.push_str(hex_data);
                return;
            }
        };
        let address = match Address::new(self.chain_config, &obj) {
            Ok(address) => address,
            Err(_) => {
                logging::log::error!(
                    "While de-hexifying, failed to create address for object for a {}",
                    A::json_wrapper_prefix()
                );
                // replace with hex value
                dst.push_str("0x");
                dst.push_str(hex_data);
                return;
            }
        };
        dst.push_str(&address.to_string())
    }
}

#[cfg(test)]
mod tests {
    use crypto::{
        key::{KeyKind, PrivateKey},
        random,
    };
    use rstest::rstest;
    use serialization::Encode;
    use test_utils::random::{make_seedable_rng, Rng, Seed};

    use crate::{
        address::{
            hexified::HexifiedAddress, pubkeyhash::PublicKeyHash, traits::Addressable, Address,
        },
        chain::{config::create_regtest, Destination},
        primitives::H256,
    };

    fn random_string(length: usize, rng: &mut impl Rng) -> String {
        rng.sample_iter(&random::distributions::Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn basic_search_and_replace(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let (_private_key, public_key) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let address = Destination::PublicKey(public_key);

        let chain_config = create_regtest();

        let s = format!("{}", HexifiedAddress::new(&address));
        let res = HexifiedAddress::<Destination>::replace_with_address(&chain_config, &s);
        assert_eq!(
            res,
            format!("{}", Address::new(&chain_config, &address).unwrap())
        );
    }

    #[test]
    fn basic_search_and_replace_simple_invalid_wont_change() {
        let chain_config = create_regtest();

        let s = "some-random-stuff";
        let res = HexifiedAddress::<Destination>::replace_with_address(&chain_config, s);
        assert_eq!(res, s)
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn many_random_instances(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let chain_config = create_regtest();

        let strings = (0..100)
            .map(|_| {
                let size = rng.gen::<usize>() % 50;
                random_string(size, &mut rng)
            })
            .collect::<Vec<String>>();

        let keys = (0..strings.len())
            .map(|_| match rng.gen::<usize>() % Destination::VARIANT_COUNT {
                0..=1 => {
                    let (_private_key, public_key) =
                        PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
                    Destination::PublicKey(public_key)
                }
                2 => {
                    let (_private_key, public_key) =
                        PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
                    Destination::Address(PublicKeyHash::from(&public_key))
                }
                3 => Destination::ScriptHash(crate::primitives::Id::new(H256::random_using(
                    &mut rng,
                ))),
                4 => {
                    let (_private_key, public_key) =
                        PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
                    Destination::ClassicMultisig(PublicKeyHash::from(&public_key))
                }
                _ => unreachable!(),
            })
            .collect::<Vec<_>>();

        let final_str = strings
            .iter()
            .zip(keys.iter())
            .map(|(s, k)| {
                let hexified = HexifiedAddress::new(k);
                s.clone() + &hexified.to_string()
            })
            .collect::<Vec<_>>()
            .join("");

        let to_test =
            HexifiedAddress::<Destination>::replace_with_address(&chain_config, &final_str);

        let expected = strings
            .iter()
            .zip(keys.iter())
            .map(|(s, k)| {
                let address_str = Address::new(&chain_config, k).unwrap();
                s.clone() + &address_str.to_string()
            })
            .collect::<Vec<_>>()
            .join("");

        assert_eq!(to_test, expected);
    }

    #[test]
    fn invalid_match_should_replace_with_hex_case_invalid_hex() {
        let chain_config = create_regtest();

        let s = format!("{}{{0xabc}}", Destination::json_wrapper_prefix()); // Invalid hex

        let re = HexifiedAddress::<Destination>::make_regex_object();
        assert!(re.is_match(&s));

        let res = HexifiedAddress::<Destination>::replace_with_address(&chain_config, &s);
        assert_eq!(res, "0xabc");
    }

    #[test]
    fn invalid_match_should_replace_with_hex_case_invalid_obj() {
        let chain_config = create_regtest();

        let s = format!("{}{{0xabcd}}", Destination::json_wrapper_prefix()); // Invalid object

        let re = HexifiedAddress::<Destination>::make_regex_object();
        assert!(re.is_match(&s));

        let res = HexifiedAddress::<Destination>::replace_with_address(&chain_config, &s);
        assert_eq!(res, "0xabcd");
    }

    #[test]
    fn invalid_match_should_replace_with_hex_creating_case_address_creation_error() {
        let chain_config = create_regtest();

        let s = format!("{}", HexifiedAddress::new(&Destination::AnyoneCanSpend)); // AnyoneCanSpend cannot be converted to an address

        let re = HexifiedAddress::<Destination>::make_regex_object();
        assert!(re.is_match(&s));

        let res = HexifiedAddress::<Destination>::replace_with_address(&chain_config, &s);
        assert_eq!(
            res,
            "0x".to_string()
                + &hex::ToHex::encode_hex::<String>(&Destination::AnyoneCanSpend.encode())
        );
    }

    #[test]
    fn serde_serialize_something_that_cannot_go_to_address() {
        let chain_config = create_regtest();

        // AnyoneCanSpend is too short to go to an address
        let obj = Destination::AnyoneCanSpend;
        let obj_json = serde_json::to_string(&obj).unwrap();

        {
            assert_eq!(obj_json, "\"HexifiedDestination{0x00}\"");
            let obj_deserialized: Destination = serde_json::from_str(&obj_json).unwrap();
            assert_eq!(obj_deserialized, obj);
        }

        {
            // Do the replacement, which will make it a hex starting with 0x, and deserialization will still succeed
            let obj_json_replaced =
                HexifiedAddress::<Destination>::replace_with_address(&chain_config, &obj_json);
            assert_eq!(obj_json_replaced, "\"0x00\"");
            let obj_deserialized: Destination = serde_json::from_str(&obj_json_replaced).unwrap();
            assert_eq!(obj_deserialized, obj);
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn serde_serialize_something_that_can_be_an_address(#[case] seed: Seed) {
        let chain_config = create_regtest();

        let mut rng = make_seedable_rng(seed);
        let (_private_key, public_key) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let obj = Destination::PublicKey(public_key);
        let obj_json = serde_json::to_string(&obj).unwrap();

        {
            let obj_hex: String = hex::ToHex::encode_hex(&obj.encode());
            assert_eq!(obj_json, format!("\"HexifiedDestination{{0x{obj_hex}}}\""));
            let obj_deserialized: Destination = serde_json::from_str(&obj_json).unwrap();
            assert_eq!(obj_deserialized, obj);
        }

        {
            // Do the replacement, which will make the hexified address become a real address
            let expected_address = Address::new(&chain_config, &obj).unwrap();
            let obj_json_replaced =
                HexifiedAddress::<Destination>::replace_with_address(&chain_config, &obj_json);
            assert_eq!(obj_json_replaced, format!("\"{expected_address}\""));
            let obj_deserialized: Destination = serde_json::from_str(&obj_json_replaced).unwrap();
            assert_eq!(obj_deserialized, obj);
        }
    }
}
