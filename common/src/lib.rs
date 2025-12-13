// Copyright (c) 2021-2022 RBB S.r.l
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

pub mod address;
pub mod chain;
pub mod primitives;
pub mod size_estimation;
pub mod text_summary;
pub mod time_getter;
pub mod uint;

pub use uint::{Uint128, Uint256, Uint512, UintConversionError};

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use crypto::vrf::VRFPublicKey;
    use hex::FromHex;
    use rpc_description::HasValueHint;
    use serialization::DecodeAll as _;

    use crate::{
        address::pubkeyhash::PublicKeyHash,
        chain::{
            tokens::TokenId, Block, DelegationId, Destination, GenBlock, OrderId, PoolId,
            Transaction,
        },
        primitives::{Id, H256},
    };

    #[ctor::ctor]
    fn init() {
        logging::init_logging();
    }

    #[test]
    fn basic_serialization_test() {
        let hash256 =
            H256::from_str("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
                .unwrap();

        // Destination
        {
            type TypeToTest = Destination;
            let val = Destination::PublicKeyHash(
                PublicKeyHash::from_str("0011223344556677889900112233445566778899").unwrap(),
            );

            let serialized_val = serde_json::to_string(&val).unwrap();
            assert_eq!(
                serialized_val,
                r#""HexifiedDestination{0x010011223344556677889900112233445566778899}""#
            );

            let expected_value_hint = rpc_description::ValueHint::Prim("hexified destination");
            assert_eq!(TypeToTest::HINT_SER, expected_value_hint);
            assert_eq!(TypeToTest::HINT_DE, expected_value_hint);

            let deserialized_val = serde_json::from_str::<TypeToTest>(&serialized_val).unwrap();
            assert_eq!(deserialized_val, val);
        }

        // Pool id
        {
            type TypeToTest = PoolId;
            let val = TypeToTest::new(hash256);

            let serialized_val = serde_json::to_string(&val).unwrap();
            assert_eq!(
                serialized_val,
                r#""HexifiedPoolId{0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}""#
            );

            let expected_value_hint = rpc_description::ValueHint::Prim("hexified pool id");
            assert_eq!(TypeToTest::HINT_SER, expected_value_hint);
            assert_eq!(TypeToTest::HINT_DE, expected_value_hint);

            let deserialized_val = serde_json::from_str::<TypeToTest>(&serialized_val).unwrap();
            assert_eq!(deserialized_val, val);
        }

        // Delegation id
        {
            type TypeToTest = DelegationId;
            let val = TypeToTest::new(hash256);

            let serialized_val = serde_json::to_string(&val).unwrap();
            assert_eq!(
                serialized_val,
                r#""HexifiedDelegationId{0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}""#
            );

            let expected_value_hint = rpc_description::ValueHint::Prim("hexified delegation id");
            assert_eq!(TypeToTest::HINT_SER, expected_value_hint);
            assert_eq!(TypeToTest::HINT_DE, expected_value_hint);

            let deserialized_val = serde_json::from_str::<TypeToTest>(&serialized_val).unwrap();
            assert_eq!(deserialized_val, val);
        }

        // Token id
        {
            type TypeToTest = TokenId;
            let val = TypeToTest::new(hash256);

            let serialized_val = serde_json::to_string(&val).unwrap();
            assert_eq!(
                serialized_val,
                r#""HexifiedTokenId{0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}""#
            );

            let expected_value_hint = rpc_description::ValueHint::Prim("hexified token id");
            assert_eq!(TypeToTest::HINT_SER, expected_value_hint);
            assert_eq!(TypeToTest::HINT_DE, expected_value_hint);

            let deserialized_val = serde_json::from_str::<TypeToTest>(&serialized_val).unwrap();
            assert_eq!(deserialized_val, val);
        }

        // Order id
        {
            type TypeToTest = OrderId;
            let val = TypeToTest::new(hash256);

            let serialized_val = serde_json::to_string(&val).unwrap();
            assert_eq!(
                serialized_val,
                r#""HexifiedOrderId{0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}""#
            );

            let expected_value_hint = rpc_description::ValueHint::Prim("hexified order id");
            assert_eq!(TypeToTest::HINT_SER, expected_value_hint);
            assert_eq!(TypeToTest::HINT_DE, expected_value_hint);

            let deserialized_val = serde_json::from_str::<TypeToTest>(&serialized_val).unwrap();
            assert_eq!(deserialized_val, val);
        }

        // Block id
        {
            type TypeToTest = Id<Block>;
            let val = TypeToTest::new(hash256);

            let serialized_val = serde_json::to_string(&val).unwrap();
            assert_eq!(
                serialized_val,
                r#""00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff""#
            );

            let expected_value_hint = rpc_description::ValueHint::Prim("hex string");
            assert_eq!(TypeToTest::HINT_SER, expected_value_hint);
            assert_eq!(TypeToTest::HINT_DE, expected_value_hint);

            let deserialized_val = serde_json::from_str::<TypeToTest>(&serialized_val).unwrap();
            assert_eq!(deserialized_val, val);
        }

        // GenBlock id
        {
            type TypeToTest = Id<GenBlock>;
            let val = TypeToTest::new(hash256);

            let serialized_val = serde_json::to_string(&val).unwrap();
            assert_eq!(
                serialized_val,
                r#""00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff""#
            );

            let expected_value_hint = rpc_description::ValueHint::Prim("hex string");
            assert_eq!(TypeToTest::HINT_SER, expected_value_hint);
            assert_eq!(TypeToTest::HINT_DE, expected_value_hint);

            let deserialized_val = serde_json::from_str::<TypeToTest>(&serialized_val).unwrap();
            assert_eq!(deserialized_val, val);
        }

        // Transaction id
        {
            type TypeToTest = Id<Transaction>;
            let val = TypeToTest::new(hash256);

            let serialized_val = serde_json::to_string(&val).unwrap();
            assert_eq!(
                serialized_val,
                r#""00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff""#
            );

            let expected_value_hint = rpc_description::ValueHint::Prim("hex string");
            assert_eq!(TypeToTest::HINT_SER, expected_value_hint);
            assert_eq!(TypeToTest::HINT_DE, expected_value_hint);

            let deserialized_val = serde_json::from_str::<TypeToTest>(&serialized_val).unwrap();
            assert_eq!(deserialized_val, val);
        }

        // Additionally check VRFPublicKey, which is currently serialized as plain hex
        // and doesn't have a ValueHint.
        {
            let pk_encoded: Vec<u8> = FromHex::from_hex(
                "00c0158e93e3904b404a12f56493802f3a325939fa780dc0fc415370599be27c68",
            )
            .unwrap();
            let pk = VRFPublicKey::decode_all(&mut pk_encoded.as_slice()).unwrap();

            let serialized_pk = serde_json::to_string(&pk).unwrap();
            assert_eq!(
                serialized_pk,
                r#""00c0158e93e3904b404a12f56493802f3a325939fa780dc0fc415370599be27c68""#
            );

            let deserialized_pk = serde_json::from_str::<VRFPublicKey>(&serialized_pk).unwrap();
            assert_eq!(deserialized_pk, pk);
        }
    }
}
