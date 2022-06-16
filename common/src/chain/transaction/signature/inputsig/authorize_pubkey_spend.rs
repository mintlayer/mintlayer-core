// Copyright (c) 2021 RBB S.r.l
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

use crypto::key::Signature;
use parity_scale_codec::{Decode, Encode};

use crate::{chain::signature::TransactionSigError, primitives::H256};

#[derive(Debug, Encode, Decode, PartialEq, Eq)]
pub struct AuthorizedPublicKeySpend {
    signature: Signature,
}

impl AuthorizedPublicKeySpend {
    pub fn from_data(data: &Vec<u8>) -> Result<Self, TransactionSigError> {
        let decoded = AuthorizedPublicKeySpend::decode(&mut data.as_slice())
            .map_err(|_| TransactionSigError::InvalidSignatureEncoding)?;
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
) -> Result<(), TransactionSigError> {
    let msg = sighash.encode();
    if !spendee_pubkey.verify_message(&spender_signature.signature, &msg) {
        return Err(TransactionSigError::SignatureVerificationFailed);
    }
    Ok(())
}

pub fn sign_pubkey_spending(
    private_key: &crypto::key::PrivateKey,
    spendee_pubkey: &crypto::key::PublicKey,
    sighash: &H256,
) -> Result<AuthorizedPublicKeySpend, TransactionSigError> {
    let calculated_public_key = crypto::key::PublicKey::from_private_key(private_key);
    if *spendee_pubkey != calculated_public_key {
        return Err(TransactionSigError::SpendeePrivatePublicKeyMismatch);
    }
    let msg = sighash.encode();
    let signature = private_key
        .sign_message(&msg)
        .map_err(TransactionSigError::ProducingSignatureFailed)?;

    Ok(AuthorizedPublicKeySpend::new(signature))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        address::pubkeyhash::PublicKeyHash,
        chain::{
            signature::{inputsig::StandardInputSignature, signature_hash},
            transaction::signature::tests::utils::{generate_unsigned_tx, sig_hash_types},
            Destination,
        },
    };
    use crypto::key::{KeyKind, PrivateKey};

    const INPUT_NUM: usize = 0;

    // Using Destination::Address for AuthorizedPublicKeySpend.
    #[test]
    fn wrong_destination() {
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::Address(PublicKeyHash::from(&public_key));
        let tx = generate_unsigned_tx(outpoint_dest.clone(), 1, 2).unwrap();

        for sighash_type in sig_hash_types() {
            let witness = StandardInputSignature::produce_signature_for_input(
                &private_key,
                sighash_type,
                outpoint_dest.clone(),
                &tx,
                INPUT_NUM,
            )
            .unwrap();

            assert_eq!(
                Err(TransactionSigError::InvalidSignatureEncoding),
                AuthorizedPublicKeySpend::from_data(witness.get_raw_signature()),
                "{sighash_type:X?}"
            )
        }
    }

    #[test]
    fn invalid_signature() {
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::PublicKey(public_key.clone());
        let tx = generate_unsigned_tx(outpoint_dest.clone(), 1, 2).unwrap();

        for sighash_type in sig_hash_types() {
            let witness = StandardInputSignature::produce_signature_for_input(
                &private_key,
                sighash_type,
                outpoint_dest.clone(),
                &tx,
                INPUT_NUM,
            )
            .unwrap();
            let mut raw_signature = witness.get_raw_signature().clone();
            raw_signature[0] = raw_signature[0].wrapping_add(2);

            assert_eq!(
                Err(TransactionSigError::InvalidSignatureEncoding),
                AuthorizedPublicKeySpend::from_data(&raw_signature),
                "{sighash_type:X?}"
            )
        }
    }

    #[test]
    fn test_verify_public_key_spending() {
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::PublicKey(public_key.clone());
        let tx = generate_unsigned_tx(outpoint_dest.clone(), 1, 2).unwrap();

        for sighash_type in sig_hash_types() {
            let witness = StandardInputSignature::produce_signature_for_input(
                &private_key,
                sighash_type,
                outpoint_dest.clone(),
                &tx,
                INPUT_NUM,
            )
            .unwrap();
            let spender_signature =
                AuthorizedPublicKeySpend::from_data(witness.get_raw_signature()).unwrap();
            let sighash = signature_hash(witness.sighash_type(), &tx, INPUT_NUM).unwrap();
            verify_public_key_spending(&public_key, &spender_signature, &sighash)
                .expect(&format!("{sighash_type:X?}"));
        }
    }

    #[test]
    fn test_sign_pubkey_spending() {
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::PublicKey(public_key.clone());
        let tx = generate_unsigned_tx(outpoint_dest.clone(), 1, 2).unwrap();

        for sighash_type in sig_hash_types() {
            let witness = StandardInputSignature::produce_signature_for_input(
                &private_key,
                sighash_type,
                outpoint_dest.clone(),
                &tx,
                INPUT_NUM,
            )
            .unwrap();
            let sighash = signature_hash(witness.sighash_type(), &tx, INPUT_NUM).unwrap();
            sign_pubkey_spending(&private_key, &public_key, &sighash)
                .expect(&format!("{sighash_type:X?}"));
        }
    }
}
