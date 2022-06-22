// Copyright (c) 2021 RBB S.r.l&
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach & L. Kuklinek

use crypto::key::{PublicKey, Signature};
use parity_scale_codec::{Decode, DecodeAll, Encode};

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
        Self {
            public_key,
            signature,
        }
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
    let public_key = crypto::key::PublicKey::from_private_key(private_key);
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
    use crate::chain::{
        signature::{inputsig::StandardInputSignature, signature_hash},
        transaction::signature::tests::utils::{generate_unsigned_tx, sig_hash_types},
        Destination,
    };
    use crypto::key::{KeyKind, PrivateKey};
    use rand::Rng;

    const INPUTS: usize = 10;
    const OUTPUTS: usize = 10;

    // Try to produce a signature for a non-existent input.
    #[test]
    fn invalid_input_index() {
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let pubkey_hash = PublicKeyHash::from(&public_key);
        let destination = Destination::Address(pubkey_hash);
        let tx = generate_unsigned_tx(&destination, 1, 2).unwrap();

        for sighash_type in sig_hash_types() {
            let res = StandardInputSignature::produce_signature_for_input(
                &private_key,
                sighash_type,
                destination.clone(),
                &tx,
                1,
            );
            assert_eq!(res, Err(TransactionSigError::InvalidInputIndex(1, 1)));
        }
    }

    // Using Destination::PublicKey for AuthorizedPublicKeyHashSpend.
    #[test]
    fn wrong_destination_type() {
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let destination = Destination::PublicKey(public_key);
        let tx = generate_unsigned_tx(&destination, INPUTS, OUTPUTS).unwrap();
        let mut rng = rand::thread_rng();

        for sighash_type in sig_hash_types() {
            let witness = StandardInputSignature::produce_signature_for_input(
                &private_key,
                sighash_type,
                destination.clone(),
                &tx,
                rng.gen_range(0..INPUTS),
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

    #[test]
    fn invalid_signature_type() {
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let pubkey_hash = PublicKeyHash::from(&public_key);
        let destination = Destination::Address(pubkey_hash);
        let tx = generate_unsigned_tx(&destination, INPUTS, OUTPUTS).unwrap();
        let mut rng = rand::thread_rng();

        for sighash_type in sig_hash_types() {
            let witness = StandardInputSignature::produce_signature_for_input(
                &private_key,
                sighash_type,
                destination.clone(),
                &tx,
                rng.gen_range(0..INPUTS),
            )
            .unwrap();

            let mut raw_signature = witness.raw_signature().clone();
            AuthorizedPublicKeyHashSpend::from_data(&raw_signature).unwrap();

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

    #[test]
    fn test_verify_address_spending() {
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let pubkey_hash = PublicKeyHash::from(&public_key);
        let destination = Destination::Address(pubkey_hash);
        let tx = generate_unsigned_tx(&destination, INPUTS, OUTPUTS).unwrap();
        let mut rng = rand::thread_rng();

        for sighash_type in sig_hash_types() {
            let input = rng.gen_range(0..INPUTS);
            let witness = StandardInputSignature::produce_signature_for_input(
                &private_key,
                sighash_type,
                destination.clone(),
                &tx,
                input,
            )
            .unwrap();
            let spender_signature =
                AuthorizedPublicKeyHashSpend::from_data(witness.raw_signature()).unwrap();
            let sighash = signature_hash(witness.sighash_type(), &tx, input).unwrap();

            verify_address_spending(&pubkey_hash, &spender_signature, &sighash)
                .expect(&format!("{sighash_type:X?}"));
        }
    }

    #[test]
    fn test_sign_address_spending() {
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let destination = Destination::PublicKey(public_key.clone());
        let pubkey_hash = PublicKeyHash::from(&public_key);
        let tx = generate_unsigned_tx(&destination, INPUTS, OUTPUTS).unwrap();
        let mut rng = rand::thread_rng();

        for sighash_type in sig_hash_types() {
            let input = rng.gen_range(0..INPUTS);
            let witness = StandardInputSignature::produce_signature_for_input(
                &private_key,
                sighash_type,
                destination.clone(),
                &tx,
                input,
            )
            .unwrap();
            let sighash = signature_hash(witness.sighash_type(), &tx, input).unwrap();

            sign_address_spending(&private_key, &pubkey_hash, &sighash)
                .expect(&format!("{sighash_type:X?}"));
        }
    }
}
