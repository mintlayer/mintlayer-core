// Copyright (c) 2021-2025 RBB S.r.l
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

use rstest::rstest;

use randomness::Rng;
use test_utils::random::{make_seedable_rng, Seed};

use super::*;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_and_verify(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let key = make_private_key();
    assert_eq!(key.len(), 33);

    let public_key = public_key_from_private_key(&key).unwrap();

    let message_size = 1 + rng.gen::<usize>() % 10000;
    let message: Vec<u8> = (0..message_size).map(|_| rng.gen::<u8>()).collect();

    let signature = sign_message_for_spending(&key, &message).unwrap();

    {
        // Valid reference signature
        let verification_result =
            verify_signature_for_spending(&public_key, &signature, &message).unwrap();
        assert!(verification_result);
    }
    {
        // Tamper with the message
        let mut tampered_message = message.clone();
        let tamper_bit_index = rng.gen::<usize>() % message_size;
        tampered_message[tamper_bit_index] = tampered_message[tamper_bit_index].wrapping_add(1);
        let verification_result =
            verify_signature_for_spending(&public_key, &signature, &tampered_message).unwrap();
        assert!(!verification_result);
    }
    {
        // Tamper with the signature
        let mut tampered_signature = signature.clone();
        // Ignore the first byte because the it is the key kind
        let tamper_bit_index = 1 + rng.gen::<usize>() % (signature.len() - 1);
        tampered_signature[tamper_bit_index] = tampered_signature[tamper_bit_index].wrapping_add(1);
        let verification_result =
            verify_signature_for_spending(&public_key, &tampered_signature, &message).unwrap();
        assert!(!verification_result);
    }
    {
        // Wrong keys
        let private_key = make_private_key();
        let public_key = public_key_from_private_key(&private_key).unwrap();
        let verification_result =
            verify_signature_for_spending(&public_key, &signature, &message).unwrap();
        assert!(!verification_result);
    }
}

#[test]
fn transaction_get_id() {
    let expected_tx_id = "35a7938c2a2aad5ae324e7d0536de245bf9e439169aa3c16f1492be117e5d0e0";
    let tx_hex = "0100040000ff5d9a94390ee97208d31aa5c3b5ddbd8df9d308069df2ebf5283f7ce3e4261401000000080340f9924e4da0af7dc8c5be71a9c9e05962c7bf4ef96127fde7a7b4e1469e48620f0080e03779c31102000365807e3b4147cb978b78715e60606092f89dc769586e98456850bd3b449c87b400203015e9ef9fc142569e0f966bc0188464fa712a841e14002e0fe952a076a26c01e539c5f0ceba927ab8f8f55f274af739ce4eef3700000b00204aa9d10100000b409e4c355d010199e4ec3a5b176140ef9cd58c7d3579fdb0ecb21a";
    let tx_signed_hex = "0100040000ff5d9a94390ee97208d31aa5c3b5ddbd8df9d308069df2ebf5283f7ce3e4261401000000080340f9924e4da0af7dc8c5be71a9c9e05962c7bf4ef96127fde7a7b4e1469e48620f0080e03779c31102000365807e3b4147cb978b78715e60606092f89dc769586e98456850bd3b449c87b400203015e9ef9fc142569e0f966bc0188464fa712a841e14002e0fe952a076a26c01e539c5f0ceba927ab8f8f55f274af739ce4eef3700000b00204aa9d10100000b409e4c355d010199e4ec3a5b176140ef9cd58c7d3579fdb0ecb21a0401018d010002eddd003bfb6333123e682abe6923da1d38faa4f0e0d9e2ee42d5aa46c152a34800a749a30c8c9c33696ce407fc145ebc9824e17b778d0d9ccc8129be52f37b74160e60f6689ac2f481071e1a63d9cf0f6eab84c2703b5e9f229cd8188ce092edd4";

    let tx_bin = hex::decode(tx_hex).unwrap();
    let tx_signed_bin = hex::decode(tx_signed_hex).unwrap();

    assert_eq!(get_transaction_id(&tx_bin, true).unwrap(), expected_tx_id);
    assert_eq!(get_transaction_id(&tx_bin, false).unwrap(), expected_tx_id);

    get_transaction_id(&tx_signed_bin, true).unwrap_err();
    assert_eq!(
        get_transaction_id(&tx_signed_bin, false).unwrap(),
        expected_tx_id
    );
}
