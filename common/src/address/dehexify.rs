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

use crypto::vrf::VRFPublicKey;
use serialization::json_encoded::JsonEncoded;

use crate::chain::{tokens::TokenId, ChainConfig, DelegationId, Destination, OrderId, PoolId};

use super::hexified::HexifiedAddress;

#[allow(clippy::let_and_return)]
pub fn dehexify_all_addresses(conf: &ChainConfig, input: &str) -> String {
    let result = HexifiedAddress::<Destination>::replace_with_address(conf, input).to_string();
    let result = HexifiedAddress::<PoolId>::replace_with_address(conf, &result).to_string();
    let result = HexifiedAddress::<DelegationId>::replace_with_address(conf, &result).to_string();
    let result = HexifiedAddress::<TokenId>::replace_with_address(conf, &result).to_string();
    let result = HexifiedAddress::<OrderId>::replace_with_address(conf, &result).to_string();
    let result = HexifiedAddress::<VRFPublicKey>::replace_with_address(conf, &result).to_string();

    result
}

pub fn to_dehexified_json<T: serde::Serialize>(
    conf: &ChainConfig,
    object: T,
) -> serde_json::Result<serde_json::Value> {
    // TODO: It would be more robust to do the transformation on the `serde_json::Value` directly.
    let json_str = JsonEncoded::new(object).to_string();
    serde_json::from_str(&dehexify_all_addresses(conf, &json_str))
}

// TODO: add tests that create blocks, and ensure the replacement in json works properly.
#[cfg(test)]
mod tests {
    use crypto::{
        key::{KeyKind, PrivateKey},
        vrf::{VRFKeyKind, VRFPrivateKey, VRFPublicKey},
    };
    use rstest::rstest;
    use strum::{EnumCount, EnumDiscriminants, EnumIter, IntoEnumIterator};
    use test_utils::random::{make_seedable_rng, Rng, Seed};

    use crate::{
        address::{hexified::HexifiedAddress, pubkeyhash::PublicKeyHash, Address},
        chain::{
            config::create_regtest, tokens::TokenId, DelegationId, Destination, DestinationTag,
            OrderId, PoolId,
        },
        primitives::H256,
    };

    fn random_string(length: usize, rng: &mut impl Rng) -> String {
        rng.sample_iter(&randomness::distributions::Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }

    #[derive(PartialEq, Eq, PartialOrd, Ord, EnumCount, EnumDiscriminants)]
    #[strum_discriminants(name(HexifiableTag), derive(EnumIter))]
    enum Hexifiable {
        Destination(Destination),
        PoolId(PoolId),
        DelegationId(DelegationId),
        TokenId(TokenId),
        OrderId(OrderId),
        VRFPublicKey(VRFPublicKey),
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn many_random_instances(#[case] seed: Seed) {
        use crate::address::dehexify::dehexify_all_addresses;
        use randomness::seq::IteratorRandom;

        let mut rng = make_seedable_rng(seed);
        let chain_config = create_regtest();

        let strings = (0..100)
            .map(|_| {
                let size = rng.gen::<usize>() % 50;
                random_string(size, &mut rng)
            })
            .collect::<Vec<String>>();

        let keys = (0..strings.len())
            .map(|_| {
                //

                match HexifiableTag::iter().choose(&mut rng).unwrap() {
                    HexifiableTag::Destination => {
                        let dest = match DestinationTag::iter().choose(&mut rng).unwrap() {
                            DestinationTag::AnyoneCanSpend => Destination::AnyoneCanSpend,
                            DestinationTag::PublicKey => {
                                let (_private_key, public_key) =
                                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
                                Destination::PublicKey(public_key)
                            }
                            DestinationTag::PublicKeyHash => {
                                let (_private_key, public_key) =
                                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
                                Destination::PublicKeyHash(PublicKeyHash::from(&public_key))
                            }
                            DestinationTag::ScriptHash => Destination::ScriptHash(
                                crate::primitives::Id::new(H256::random_using(&mut rng)),
                            ),
                            DestinationTag::ClassicMultisig => {
                                let (_private_key, public_key) =
                                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
                                Destination::ClassicMultisig(PublicKeyHash::from(&public_key))
                            }
                        };
                        Hexifiable::Destination(dest)
                    }
                    HexifiableTag::PoolId => Hexifiable::PoolId(PoolId::random_using(&mut rng)),
                    HexifiableTag::DelegationId => {
                        Hexifiable::DelegationId(DelegationId::random_using(&mut rng))
                    }
                    HexifiableTag::TokenId => Hexifiable::TokenId(TokenId::random_using(&mut rng)),
                    HexifiableTag::OrderId => Hexifiable::OrderId(OrderId::random_using(&mut rng)),
                    HexifiableTag::VRFPublicKey => Hexifiable::VRFPublicKey(
                        VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel).1,
                    ),
                }
            })
            .collect::<Vec<_>>();

        let final_str = strings
            .iter()
            .zip(keys.iter())
            .map(|(s, k)| {
                let hexified = match k {
                    Hexifiable::Destination(d) => HexifiedAddress::new(d).to_string(),
                    Hexifiable::PoolId(d) => HexifiedAddress::new(d).to_string(),
                    Hexifiable::DelegationId(d) => HexifiedAddress::new(d).to_string(),
                    Hexifiable::TokenId(d) => HexifiedAddress::new(d).to_string(),
                    Hexifiable::OrderId(d) => HexifiedAddress::new(d).to_string(),
                    Hexifiable::VRFPublicKey(d) => HexifiedAddress::new(d).to_string(),
                };
                s.clone() + &hexified
            })
            .collect::<Vec<_>>()
            .join("");

        let to_test = dehexify_all_addresses(&chain_config, &final_str);

        let expected = strings
            .iter()
            .zip(keys.into_iter())
            .map(|(s, k)| {
                let address_str = match k {
                    Hexifiable::Destination(d) => {
                        Address::new(&chain_config, d).unwrap().to_string()
                    }
                    Hexifiable::PoolId(d) => Address::new(&chain_config, d).unwrap().to_string(),
                    Hexifiable::DelegationId(d) => {
                        Address::new(&chain_config, d).unwrap().to_string()
                    }
                    Hexifiable::TokenId(d) => Address::new(&chain_config, d).unwrap().to_string(),
                    Hexifiable::OrderId(d) => Address::new(&chain_config, d).unwrap().to_string(),
                    Hexifiable::VRFPublicKey(d) => {
                        Address::new(&chain_config, d).unwrap().to_string()
                    }
                };
                s.clone() + &address_str
            })
            .collect::<Vec<_>>()
            .join("");

        assert_eq!(to_test, expected);
    }
}
