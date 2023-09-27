use crate::chain::ChainConfig;

use super::{traits::Addressable, Address};
use parity_scale_codec::DecodeAll;
use regex::Regex;

const REGEX_SUFFIX: &str = r#"\{0x([0-9a-fA-F]+)\}"#;

pub struct HexifiedAddress<A> {
    addressable: A,
}

impl<A: Addressable + DecodeAll> HexifiedAddress<A> {
    pub fn new(addressable: A) -> Self {
        Self { addressable }
    }

    fn make_regex_pattern() -> String {
        A::json_wrapper_prefix().to_string() + REGEX_SUFFIX
    }

    fn make_regex_object() -> Regex {
        Regex::new(&Self::make_regex_pattern()).expect("Regex pattern cannot fail")
    }

    #[must_use]
    pub fn replace_with_address(chain_config: &ChainConfig, target_str: &str) -> String {
        let matcher = Self::make_regex_object();
        let replacer = AddressableReplacer::<A>::new(chain_config);
        let result = matcher.replace_all(target_str, replacer);

        result.to_string()
    }
}

impl<A: Addressable> std::fmt::Display for HexifiedAddress<A> {
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
                dst.push_str(&hex_data);
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
                dst.push_str(&hex_data);
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
                dst.push_str(&hex_data);
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
    use parity_scale_codec::Encode;
    use rstest::rstest;
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

        let s = format!("{}", HexifiedAddress::new(address.clone()));
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
        let res = HexifiedAddress::<Destination>::replace_with_address(&chain_config, &s);
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
                let hexified = HexifiedAddress::new(k.clone());
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

        let s = format!("{}", HexifiedAddress::new(Destination::AnyoneCanSpend)); // AnyoneCanSpend cannot be converted to an address

        let re = HexifiedAddress::<Destination>::make_regex_object();
        assert!(re.is_match(&s));

        let res = HexifiedAddress::<Destination>::replace_with_address(&chain_config, &s);
        assert_eq!(
            res,
            "0x".to_string()
                + &hex::ToHex::encode_hex::<String>(&Destination::AnyoneCanSpend.encode())
        );
    }
}
