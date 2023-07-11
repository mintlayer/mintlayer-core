// Copyright (c) 2021-2022 RBB S.r.l&
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

use crypto::key::{PublicKey, Signature};
use serialization::{Decode, DecodeAll, Encode};

use crate::{
    address::pubkeyhash::PublicKeyHash, chain::signature::TransactionSigError, primitives::H256,
};

#[derive(Debug, Encode, Decode, PartialEq, Eq)]
pub struct AuthorizedPublicKeyHashSpend {
    public_key: PublicKey,
    signature: Signature,
}

impl AuthorizedPublicKeyHashSpend {
    pub fn from_data<T: AsRef<[u8]>>(data: T) -> Result<Self, TransactionSigError> {
        let decoded = AuthorizedPublicKeyHashSpend::decode_all(&mut data.as_ref())
            .map_err(|e| TransactionSigError::AddressAuthDecodingFailed(e.to_string()))?;
        Ok(decoded)
    }

    pub fn new(public_key: PublicKey, signature: Signature) -> Self {
        Self { public_key, signature }
    }
}

pub fn verify_address_spending(
    spendee_addr: &PublicKeyHash,
    sig_components: &AuthorizedPublicKeyHashSpend,
    sighash: &H256,
) -> Result<(), TransactionSigError> {
    let calculated_addr = PublicKeyHash::from(&sig_components.public_key);
    if calculated_addr != *spendee_addr {
        return Err(TransactionSigError::PublicKeyToAddressMismatch);
    }
    let msg = sighash.encode();
    if !sig_components.public_key.verify_message(&sig_components.signature, &msg) {
        return Err(TransactionSigError::SignatureVerificationFailed);
    }
    Ok(())
}

pub fn sign_address_spending(
    private_key: &crypto::key::PrivateKey,
    spendee_addr: &PublicKeyHash,
    sighash: &H256,
) -> Result<AuthorizedPublicKeyHashSpend, TransactionSigError> {
    let public_key = PublicKey::from_private_key(private_key);
    let calculated_addr = PublicKeyHash::from(&public_key);
    if calculated_addr != *spendee_addr {
        return Err(TransactionSigError::PublicKeyToAddressMismatch);
    }
    let msg = sighash.encode();
    let signature = private_key
        .sign_message(&msg)
        .map_err(TransactionSigError::ProducingSignatureFailed)?;

    Ok(AuthorizedPublicKeyHashSpend::new(public_key, signature))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::chain::signature::tests::utils::generate_inputs_utxos;
    use crate::chain::{
        signature::{inputsig::StandardInputSignature, sighash::signature_hash},
        transaction::signature::tests::utils::{generate_unsigned_tx, sig_hash_types},
        Destination,
    };
    use crypto::key::{KeyKind, PrivateKey};
    use crypto::random::Rng;
    use rstest::rstest;
    use test_utils::random::Seed;

    const INPUTS: usize = 10;
    const OUTPUTS: usize = 10;

    // Try to produce a signature for a non-existent input.
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn invalid_input_index(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let (private_key, public_key) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let pubkey_hash = PublicKeyHash::from(&public_key);
        let destination = Destination::Address(pubkey_hash);

        let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 1);
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

        let tx = generate_unsigned_tx(&mut rng, &destination, &inputs_utxos, 2).unwrap();

        for sighash_type in sig_hash_types() {
            let res = StandardInputSignature::produce_uniparty_signature_for_input(
                &private_key,
                sighash_type,
                destination.clone(),
                &tx,
                &inputs_utxos_refs,
                1,
            );
            assert_eq!(res, Err(TransactionSigError::InvalidInputIndex(1, 1)));
        }
    }

    // Using Destination::PublicKey for AuthorizedPublicKeyHashSpend.
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn wrong_destination_type(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let (private_key, public_key) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let destination = Destination::PublicKey(public_key);

        let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, INPUTS);
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

        let tx = generate_unsigned_tx(&mut rng, &destination, &inputs_utxos, OUTPUTS).unwrap();

        for sighash_type in sig_hash_types() {
            let witness = StandardInputSignature::produce_uniparty_signature_for_input(
                &private_key,
                sighash_type,
                destination.clone(),
                &tx,
                &inputs_utxos_refs,
                rng.gen_range(0..inputs_utxos.len()),
            )
            .unwrap();
            assert!(
                matches!(
                    AuthorizedPublicKeyHashSpend::from_data(witness.raw_signature()),
                    Err(TransactionSigError::AddressAuthDecodingFailed(_))
                ),
                "{sighash_type:X?}"
            )
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn invalid_signature_type(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let (private_key, public_key) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let pubkey_hash = PublicKeyHash::from(&public_key);
        let destination = Destination::Address(pubkey_hash);

        let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, INPUTS);
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

        let tx = generate_unsigned_tx(&mut rng, &destination, &inputs_utxos, OUTPUTS).unwrap();

        for sighash_type in sig_hash_types() {
            let witness = StandardInputSignature::produce_uniparty_signature_for_input(
                &private_key,
                sighash_type,
                destination.clone(),
                &tx,
                &inputs_utxos_refs,
                rng.gen_range(0..inputs_utxos.len()),
            )
            .unwrap();

            let mut raw_signature = witness.raw_signature().to_vec();
            AuthorizedPublicKeyHashSpend::from_data(&raw_signature).unwrap();

            // Changing the first byte doesn't changes the signature data, instead it changes the
            // signature enum discriminant, therefore it changes the signature type.
            raw_signature[0] = raw_signature[0].wrapping_add(2);
            assert!(
                matches!(
                    AuthorizedPublicKeyHashSpend::from_data(&raw_signature),
                    Err(TransactionSigError::AddressAuthDecodingFailed(_))
                ),
                "{sighash_type:X?}"
            )
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_verify_address_spending(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let (private_key, public_key) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let pubkey_hash = PublicKeyHash::from(&public_key);
        let destination = Destination::Address(pubkey_hash);

        let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, INPUTS);
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

        let tx = generate_unsigned_tx(&mut rng, &destination, &inputs_utxos, OUTPUTS).unwrap();

        for sighash_type in sig_hash_types() {
            let input = rng.gen_range(0..INPUTS);
            let witness = StandardInputSignature::produce_uniparty_signature_for_input(
                &private_key,
                sighash_type,
                destination.clone(),
                &tx,
                &inputs_utxos_refs,
                input,
            )
            .unwrap();
            let spender_signature =
                AuthorizedPublicKeyHashSpend::from_data(witness.raw_signature()).unwrap();
            let sighash =
                signature_hash(witness.sighash_type(), &tx, &inputs_utxos_refs, input).unwrap();

            verify_address_spending(&pubkey_hash, &spender_signature, &sighash)
                .unwrap_or_else(|_| panic!("{sighash_type:X?}"));
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_sign_address_spending(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let (private_key, public_key) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let destination = Destination::PublicKey(public_key.clone());
        let pubkey_hash = PublicKeyHash::from(&public_key);

        let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, INPUTS);
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

        let tx = generate_unsigned_tx(&mut rng, &destination, &inputs_utxos, OUTPUTS).unwrap();

        for sighash_type in sig_hash_types() {
            let input = rng.gen_range(0..inputs_utxos.len());
            let witness = StandardInputSignature::produce_uniparty_signature_for_input(
                &private_key,
                sighash_type,
                destination.clone(),
                &tx,
                &inputs_utxos_refs,
                input,
            )
            .unwrap();
            let sighash =
                signature_hash(witness.sighash_type(), &tx, &inputs_utxos_refs, input).unwrap();

            sign_address_spending(&private_key, &pubkey_hash, &sighash)
                .unwrap_or_else(|_| panic!("{sighash_type:X?}"));
        }
    }
}
