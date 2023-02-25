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

pub mod authorize_pubkey_spend;
pub mod authorize_pubkeyhash_spend;
pub mod standard_signature;

use serialization::{Decode, Encode};

use self::standard_signature::StandardInputSignature;

#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum InputWitness {
    #[codec(index = 0)]
    NoSignature(Option<Vec<u8>>),
    #[codec(index = 1)]
    Standard(StandardInputSignature),
}

#[cfg(test)]
mod test {
    use crate::{
        address::pubkeyhash::PublicKeyHash,
        chain::transaction::signature::tests::utils::{generate_unsigned_tx, sig_hash_types},
    };

    use super::*;
    use crate::chain::signature::{signature_hash, TransactionSigError};
    use crate::chain::Destination;
    use crypto::key::{KeyKind, PrivateKey};
    use itertools::Itertools;
    use rstest::rstest;
    use test_utils::random::Seed;

    const INPUT_NUM: usize = 0;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn produce_signature_address_missmatch(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let (private_key, _) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let (_, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let destination = Destination::Address(PublicKeyHash::from(&public_key));
        let tx = generate_unsigned_tx(&mut rng, &destination, 1, 2).unwrap();

        for sighash_type in sig_hash_types() {
            assert_eq!(
                Err(TransactionSigError::PublicKeyToAddressMismatch),
                StandardInputSignature::produce_signature_for_input(
                    &private_key,
                    sighash_type,
                    destination.clone(),
                    &tx,
                    INPUT_NUM,
                ),
                "{sighash_type:X?}"
            );
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn produce_signature_key_missmatch(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let (private_key, _) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let (_, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let destination = Destination::PublicKey(public_key);
        let tx = generate_unsigned_tx(&mut rng, &destination, 1, 2).unwrap();

        for sighash_type in sig_hash_types() {
            assert_eq!(
                Err(TransactionSigError::SpendeePrivatePublicKeyMismatch),
                StandardInputSignature::produce_signature_for_input(
                    &private_key,
                    sighash_type,
                    destination.clone(),
                    &tx,
                    INPUT_NUM,
                ),
                "{sighash_type:X?}"
            );
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn produce_and_verify(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let (private_key, public_key) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let outpoints = [
            Destination::Address(PublicKeyHash::from(&public_key)),
            Destination::PublicKey(public_key),
        ];

        for (sighash_type, destination) in sig_hash_types().cartesian_product(outpoints.into_iter())
        {
            let tx = generate_unsigned_tx(&mut rng, &destination, 1, 2).unwrap();
            let witness = StandardInputSignature::produce_signature_for_input(
                &private_key,
                sighash_type,
                destination.clone(),
                &tx,
                INPUT_NUM,
            )
            .unwrap();

            let sighash = signature_hash(witness.sighash_type(), &tx, INPUT_NUM).unwrap();
            witness
                .verify_signature(&destination, &sighash)
                .unwrap_or_else(|_| panic!("{sighash_type:X?} {destination:?}"));
        }
    }
}
