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

use itertools::iproduct;

use crypto::key::{KeyKind, PrivateKey};
use rstest::rstest;
use test_utils::random::Seed;

use super::utils::*;
use crate::chain::config::create_mainnet;
use crate::chain::{signature::inputsig::InputWitness, Destination};

// Create a transaction with a different signature hash type for every input.
// This test takes a long time to finish, so it is ignored by default.
#[ignore]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mixed_sighash_types(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let destination = Destination::PublicKey(public_key);

    // Test all combinations of signature hash types in every position.
    for sighash_types in iproduct!(
        sig_hash_types(),
        sig_hash_types(),
        sig_hash_types(),
        sig_hash_types(),
        sig_hash_types(),
        sig_hash_types()
    ) {
        let tx = generate_unsigned_tx(&mut rng, &destination, 6, 6).unwrap();

        let sigs = [
            sighash_types.0,
            sighash_types.1,
            sighash_types.2,
            sighash_types.3,
            sighash_types.4,
            sighash_types.5,
        ]
        .into_iter()
        .enumerate()
        .map(|(input, sighash_type)| {
            InputWitness::Standard(
                make_signature(&tx, input, &private_key, sighash_type, destination.clone())
                    .unwrap(),
            )
        })
        .collect::<Vec<_>>();

        let signed_tx = tx.with_signatures(sigs).unwrap();

        verify_signed_tx(&chain_config, &signed_tx, &destination)
            .expect("Signature verification failed")
    }
}
