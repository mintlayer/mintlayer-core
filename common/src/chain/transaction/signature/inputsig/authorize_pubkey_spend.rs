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

use crypto::key::{SigAuxDataProvider, Signature};
use serialization::{Decode, DecodeAll, Encode};

use crate::{chain::signature::DestinationSigError, primitives::H256};

#[derive(Debug, Encode, Decode, PartialEq, Eq)]
pub struct AuthorizedPublicKeySpend {
    signature: Signature,
}

impl AuthorizedPublicKeySpend {
    pub fn from_data(data: &[u8]) -> Result<Self, DestinationSigError> {
        let decoded = AuthorizedPublicKeySpend::decode_all(&mut &data[..])
            .map_err(|_| DestinationSigError::InvalidSignatureEncoding)?;
        Ok(decoded)
    }

    pub fn new(signature: Signature) -> Self {
        Self { signature }
    }
}

pub fn verify_public_key_spending(
    spendee_pubkey: &crypto::key::PublicKey,
    spender_signature: &AuthorizedPublicKeySpend,
    sighash: &H256,
) -> Result<(), DestinationSigError> {
    let msg = sighash.encode();
    if !spendee_pubkey.verify_message(&spender_signature.signature, &msg) {
        return Err(DestinationSigError::SignatureVerificationFailed);
    }
    Ok(())
}

pub fn sign_public_key_spending<AuxP: SigAuxDataProvider + ?Sized>(
    private_key: &crypto::key::PrivateKey,
    spendee_pubkey: &crypto::key::PublicKey,
    sighash: &H256,
    sig_aux_data_provider: &mut AuxP,
) -> Result<AuthorizedPublicKeySpend, DestinationSigError> {
    let calculated_public_key = crypto::key::PublicKey::from_private_key(private_key);
    if *spendee_pubkey != calculated_public_key {
        return Err(DestinationSigError::SpendeePrivatePublicKeyMismatch);
    }
    let msg = sighash.encode();
    let signature = private_key
        .sign_message(&msg, sig_aux_data_provider)
        .map_err(DestinationSigError::ProducingSignatureFailed)?;

    Ok(AuthorizedPublicKeySpend::new(signature))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::chain::signature::sighash::signature_hash;
    use crate::chain::signature::tests::utils::generate_inputs_utxos;
    use crate::{
        address::pubkeyhash::PublicKeyHash,
        chain::{
            signature::inputsig::StandardInputSignature,
            transaction::signature::tests::utils::{generate_unsigned_tx, sig_hash_types},
            Destination,
        },
    };
    use crypto::key::{KeyKind, PrivateKey};
    use randomness::Rng;
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
        let destination = Destination::PublicKey(public_key);

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
                &mut rng,
            );
            assert_eq!(res, Err(DestinationSigError::InvalidInputIndex(1, 1)));
        }
    }

    // Using Destination::Address for AuthorizedPublicKeySpend.
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn wrong_destination_type(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let (private_key, public_key) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let destination = Destination::PublicKeyHash(PublicKeyHash::from(&public_key));

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
                &mut rng,
            )
            .unwrap();

            assert_eq!(
                Err(DestinationSigError::InvalidSignatureEncoding),
                AuthorizedPublicKeySpend::from_data(witness.raw_signature()),
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
                rng.gen_range(0..INPUTS),
                &mut rng,
            )
            .unwrap();

            let mut raw_signature = witness.raw_signature().to_vec();
            AuthorizedPublicKeySpend::from_data(&raw_signature).unwrap();

            // Changing the first byte doesn't changes the signature data, instead it changes the
            // signature enum discriminant, therefore it changes the signature type.
            raw_signature[0] = raw_signature[0].wrapping_add(2);
            assert_eq!(
                Err(DestinationSigError::InvalidSignatureEncoding),
                AuthorizedPublicKeySpend::from_data(&raw_signature),
                "{sighash_type:X?}"
            )
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_verify_public_key_spending(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let (private_key, public_key) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let destination = Destination::PublicKey(public_key.clone());

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
                &mut rng,
            )
            .unwrap();
            let spender_signature =
                AuthorizedPublicKeySpend::from_data(witness.raw_signature()).unwrap();
            let sighash =
                signature_hash(witness.sighash_type(), &tx, &inputs_utxos_refs, input).unwrap();
            verify_public_key_spending(&public_key, &spender_signature, &sighash)
                .unwrap_or_else(|_| panic!("{sighash_type:X?}"));
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_sign_public_key_spending(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let (private_key, public_key) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let destination = Destination::PublicKey(public_key.clone());

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
                &mut rng,
            )
            .unwrap();
            let sighash =
                signature_hash(witness.sighash_type(), &tx, &inputs_utxos_refs, input).unwrap();
            sign_public_key_spending(&private_key, &public_key, &sighash, &mut rng)
                .unwrap_or_else(|_| panic!("{sighash_type:X?}"));
        }
    }
}
