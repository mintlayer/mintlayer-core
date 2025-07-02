// Copyright (c) 2022 RBB S.r.l
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

use itertools::Itertools;

use crypto::key::{KeyKind, PrivateKey};
use rstest::rstest;
use script::Script;
use test_utils::random::Seed;

use super::utils::*;
use crate::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        config::create_mainnet,
        signature::{
            sighash::sighashtype::{OutputsMode, SigHashType},
            DestinationSigError,
        },
        Destination,
    },
    primitives::{Id, H256},
};

// Generate a transaction with a different number of inputs and outputs, then sign it as a whole.
// For `ALL`, `ALL | ANYONECANPAY`, `NONE` and `NONE | ANYONECANPAY` it should succeed in all cases
// except for `ScriptHash` and `AnyoneCanSpend` destinations.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_and_verify_all_and_none(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let test_data = [(0, 31), (31, 0), (20, 3), (3, 20)];
    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    for ((destination, sighash_type), (inputs_count, outputs_count)) in
        destinations(&mut rng, public_key)
            .cartesian_product(sig_hash_types().filter(|t| t.outputs_mode() != OutputsMode::Single))
            .cartesian_product(test_data)
    {
        let input_commitments = generate_input_commitments(&mut rng, inputs_count);

        let tx = generate_unsigned_tx(
            &mut rng,
            &destination,
            input_commitments.len(),
            outputs_count,
        )
        .unwrap();
        let signed_tx = sign_whole_tx(
            &mut rng,
            tx,
            &input_commitments,
            &private_key,
            sighash_type,
            &destination,
        );
        // `sign_whole_tx` does nothing if there no inputs.
        if destination == Destination::AnyoneCanSpend && inputs_count > 0 {
            assert_eq!(
                signed_tx,
                Err(DestinationSigError::AttemptedToProduceSignatureForAnyoneCanSpend)
            );
        } else if matches!(destination, Destination::ScriptHash(_)) && inputs_count > 0 {
            // This should be updated after ScriptHash support is implemented.
            assert_eq!(signed_tx, Err(DestinationSigError::Unsupported));
        } else {
            let signed_tx = signed_tx.expect("{sighash_type:?} {destination:?}");
            verify_signed_tx(&chain_config, &signed_tx, &input_commitments, &destination)
                .expect("{sighash_type:?} {destination:?}")
        }
    }
}

// Same as `sign_and_verify_all_and_none` but for `SINGLE` and `SINGLE | ANYONECANPAY` signature
// hash types.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_and_verify_single(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let test_data = [
        // SigHashType::SINGLE. Destination = PubKey.
        (
            Destination::PublicKey(public_key.clone()),
            SigHashType::try_from(SigHashType::SINGLE).unwrap(),
            0,
            31,
            Ok(()),
        ),
        (
            Destination::PublicKey(public_key.clone()),
            SigHashType::try_from(SigHashType::SINGLE).unwrap(),
            31,
            0,
            Err(DestinationSigError::InvalidInputIndex(0, 0)),
        ),
        (
            Destination::PublicKey(public_key.clone()),
            SigHashType::try_from(SigHashType::SINGLE).unwrap(),
            21,
            3,
            Err(DestinationSigError::InvalidInputIndex(3, 3)),
        ),
        (
            Destination::PublicKey(public_key.clone()),
            SigHashType::try_from(SigHashType::SINGLE).unwrap(),
            3,
            21,
            Ok(()),
        ),
        // SigHashType::SINGLE | SigHashType::ANYONECANPAY. Destination = PubKey.
        (
            Destination::PublicKey(public_key.clone()),
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap(),
            0,
            33,
            Ok(()),
        ),
        (
            Destination::PublicKey(public_key.clone()),
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap(),
            21,
            0,
            Err(DestinationSigError::InvalidInputIndex(0, 0)),
        ),
        (
            Destination::PublicKey(public_key.clone()),
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap(),
            15,
            33,
            Ok(()),
        ),
        (
            Destination::PublicKey(public_key.clone()),
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap(),
            21,
            7,
            Err(DestinationSigError::InvalidInputIndex(7, 7)),
        ),
        // SigHashType::SINGLE. Destination = Address.
        (
            Destination::PublicKeyHash(PublicKeyHash::from(&public_key)),
            SigHashType::try_from(SigHashType::SINGLE).unwrap(),
            0,
            33,
            Ok(()),
        ),
        (
            Destination::PublicKeyHash(PublicKeyHash::from(&public_key)),
            SigHashType::try_from(SigHashType::SINGLE).unwrap(),
            21,
            0,
            Err(DestinationSigError::InvalidInputIndex(0, 0)),
        ),
        (
            Destination::PublicKeyHash(PublicKeyHash::from(&public_key)),
            SigHashType::try_from(SigHashType::SINGLE).unwrap(),
            15,
            33,
            Ok(()),
        ),
        (
            Destination::PublicKeyHash(PublicKeyHash::from(&public_key)),
            SigHashType::try_from(SigHashType::SINGLE).unwrap(),
            21,
            7,
            Err(DestinationSigError::InvalidInputIndex(7, 7)),
        ),
        // SigHashType::SINGLE | SigHashType::ANYONECANPAY. Destination = Address.
        (
            Destination::PublicKeyHash(PublicKeyHash::from(&public_key)),
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap(),
            0,
            33,
            Ok(()),
        ),
        (
            Destination::PublicKeyHash(PublicKeyHash::from(&public_key)),
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap(),
            21,
            0,
            Err(DestinationSigError::InvalidInputIndex(0, 0)),
        ),
        (
            Destination::PublicKeyHash(PublicKeyHash::from(&public_key)),
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap(),
            15,
            33,
            Ok(()),
        ),
        (
            Destination::PublicKeyHash(PublicKeyHash::from(&public_key)),
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap(),
            21,
            7,
            Err(DestinationSigError::InvalidInputIndex(7, 7)),
        ),
        // SigHashType::SINGLE. Destination = AnyoneCanSpend.
        (
            Destination::AnyoneCanSpend,
            SigHashType::try_from(SigHashType::SINGLE).unwrap(),
            21,
            33,
            Err(DestinationSigError::AttemptedToProduceSignatureForAnyoneCanSpend),
        ),
        // SigHashType::SINGLE | SigHashType::ANYONECANPAY. Destination = AnyoneCanSpend.
        (
            Destination::AnyoneCanSpend,
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap(),
            21,
            33,
            Err(DestinationSigError::AttemptedToProduceSignatureForAnyoneCanSpend),
        ),
        // SigHashType::SINGLE. Destination = ScriptHash.
        // This is currently unsupported, so test should be updated in the future.
        (
            Destination::ScriptHash(Id::<Script>::from(H256::random_using(&mut rng))),
            SigHashType::try_from(SigHashType::SINGLE).unwrap(),
            21,
            33,
            Err(DestinationSigError::Unsupported),
        ),
        // SigHashType::SINGLE | SigHashType::ANYONECANPAY. Destination = ScriptHash
        // This is currently unsupported, so test should be updated in the future.
        (
            Destination::ScriptHash(Id::<Script>::from(H256::random_using(&mut rng))),
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap(),
            21,
            33,
            Err(DestinationSigError::Unsupported),
        ),
    ];

    for (destination, sighash_type, inputs_count, outputs_count, expected) in test_data.into_iter()
    {
        let input_commitments = generate_input_commitments(&mut rng, inputs_count);

        let tx = generate_unsigned_tx(
            &mut rng,
            &destination,
            input_commitments.len(),
            outputs_count,
        )
        .unwrap();
        match sign_whole_tx(
            &mut rng,
            tx,
            &input_commitments,
            &private_key,
            sighash_type,
            &destination,
        ) {
            Ok(signed_tx) => {
                verify_signed_tx(&chain_config, &signed_tx, &input_commitments, &destination)
                    .expect("{sighash_type:X?}, {destination:?}")
            }
            Err(err) => assert_eq!(Err(err), expected, "{sighash_type:X?}, {destination:?}"),
        }
    }
}
