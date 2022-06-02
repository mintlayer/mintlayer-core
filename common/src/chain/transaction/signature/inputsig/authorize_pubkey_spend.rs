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

#[derive(Debug, Encode, Decode)]
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

// TODO: tests

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        address::pubkeyhash::PublicKeyHash,
        chain::{
            signature::{
                inputsig::{InputWitness, StandardInputSignature},
                sighashtype::SigHashType,
                signature_hash,
            },
            Destination, Transaction, TransactionCreationError, TxInput, TxOutput,
        },
        primitives::{Amount, Id},
    };
    use crypto::key::{KeyKind, PrivateKey, PublicKey};

    fn generate_unsigned_tx(
        outpoint_dest: Destination,
    ) -> Result<Transaction, TransactionCreationError> {
        let tx = Transaction::new(
            0,
            vec![TxInput::new(
                Id::<Transaction>::new(&H256::zero()).into(),
                0,
                InputWitness::NoSignature(None),
            )],
            vec![TxOutput::new(Amount::from_atoms(100), outpoint_dest)],
            0,
        )?;
        Ok(tx)
    }

    fn make_data_for_verify(
        sighash_type: SigHashType,
    ) -> (PublicKey, AuthorizedPublicKeySpend, H256) {
        const INPUT_NUM: usize = 0;
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::PublicKey(public_key.clone());
        let tx = generate_unsigned_tx(outpoint_dest.clone()).unwrap();
        let witness = StandardInputSignature::produce_signature_for_input(
            &private_key,
            sighash_type,
            outpoint_dest,
            &tx,
            INPUT_NUM,
        )
        .unwrap();
        let spender_signature =
            AuthorizedPublicKeySpend::from_data(witness.get_raw_signature()).unwrap();
        let sighash = signature_hash(witness.sighash_type(), &tx, INPUT_NUM).unwrap();
        (public_key, spender_signature, sighash)
    }

    #[test]
    fn test_verify_public_key_spending() {
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let (public_key, spender_signature, sighash) = make_data_for_verify(sighash_type);
        verify_public_key_spending(&public_key, &spender_signature, &sighash).unwrap();

        let sighash_type =
            SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
        let (public_key, spender_signature, sighash) = make_data_for_verify(sighash_type);
        verify_public_key_spending(&public_key, &spender_signature, &sighash).unwrap();

        let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
        let (public_key, spender_signature, sighash) = make_data_for_verify(sighash_type);
        verify_public_key_spending(&public_key, &spender_signature, &sighash).unwrap();

        let sighash_type =
            SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
        let (public_key, spender_signature, sighash) = make_data_for_verify(sighash_type);
        verify_public_key_spending(&public_key, &spender_signature, &sighash).unwrap();

        let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
        let (public_key, spender_signature, sighash) = make_data_for_verify(sighash_type);
        verify_public_key_spending(&public_key, &spender_signature, &sighash).unwrap();

        let sighash_type =
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
        let (public_key, spender_signature, sighash) = make_data_for_verify(sighash_type);
        verify_public_key_spending(&public_key, &spender_signature, &sighash).unwrap();
    }

    fn prepare_data_for_wrong_destination(sighash_type: SigHashType) -> StandardInputSignature {
        const INPUT_NUM: usize = 0;
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::Address(PublicKeyHash::from(&public_key));
        let tx = generate_unsigned_tx(outpoint_dest.clone()).unwrap();
        StandardInputSignature::produce_signature_for_input(
            &private_key,
            sighash_type,
            outpoint_dest,
            &tx,
            INPUT_NUM,
        )
        .unwrap()
    }

    #[test]
    fn test_wrong_destination() {
        use std::mem::discriminant;
        // Destination = PubKey, but we try to use here AuthorizedPublicKeySpend
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let witness = prepare_data_for_wrong_destination(sighash_type);
        // Compare Err(TransactionSigError) without inner message
        assert_eq!(
            discriminant(&AuthorizedPublicKeySpend::from_data(
                witness.get_raw_signature()
            )),
            discriminant(&Err(TransactionSigError::AddressAuthDecodingFailed(
                String::new()
            )))
        );
        let sighash_type =
            SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
        let witness = prepare_data_for_wrong_destination(sighash_type);
        assert_eq!(
            discriminant(&AuthorizedPublicKeySpend::from_data(
                witness.get_raw_signature()
            )),
            discriminant(&Err(TransactionSigError::AddressAuthDecodingFailed(
                String::new()
            )))
        );
        let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
        let witness = prepare_data_for_wrong_destination(sighash_type);
        assert_eq!(
            discriminant(&AuthorizedPublicKeySpend::from_data(
                witness.get_raw_signature()
            )),
            discriminant(&Err(TransactionSigError::AddressAuthDecodingFailed(
                String::new()
            )))
        );
        let sighash_type =
            SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
        let witness = prepare_data_for_wrong_destination(sighash_type);
        assert_eq!(
            discriminant(&AuthorizedPublicKeySpend::from_data(
                witness.get_raw_signature()
            )),
            discriminant(&Err(TransactionSigError::AddressAuthDecodingFailed(
                String::new()
            )))
        );

        let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
        let witness = prepare_data_for_wrong_destination(sighash_type);
        assert_eq!(
            discriminant(&AuthorizedPublicKeySpend::from_data(
                witness.get_raw_signature()
            )),
            discriminant(&Err(TransactionSigError::AddressAuthDecodingFailed(
                String::new()
            )))
        );

        let sighash_type =
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
        let witness = prepare_data_for_wrong_destination(sighash_type);
        assert_eq!(
            discriminant(&AuthorizedPublicKeySpend::from_data(
                witness.get_raw_signature()
            )),
            discriminant(&Err(TransactionSigError::AddressAuthDecodingFailed(
                String::new()
            )))
        );
    }

    fn prepare_data_for_sign(sighash_type: SigHashType) -> (PrivateKey, PublicKey, H256) {
        const INPUT_NUM: usize = 0;
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::PublicKey(public_key.clone());
        let tx = generate_unsigned_tx(outpoint_dest.clone()).unwrap();
        let witness = StandardInputSignature::produce_signature_for_input(
            &private_key,
            sighash_type,
            outpoint_dest,
            &tx,
            INPUT_NUM,
        )
        .unwrap();
        let sighash = signature_hash(witness.sighash_type(), &tx, INPUT_NUM).unwrap();
        (private_key, public_key, sighash)
    }

    #[test]
    fn test_sign_pubkey_spending() {
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let (private_key, public_key, sighash) = prepare_data_for_sign(sighash_type);
        let _ = sign_pubkey_spending(&private_key, &public_key, &sighash).unwrap();

        let sighash_type =
            SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
        let (private_key, public_key, sighash) = prepare_data_for_sign(sighash_type);
        let _ = sign_pubkey_spending(&private_key, &public_key, &sighash).unwrap();

        let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
        let (private_key, public_key, sighash) = prepare_data_for_sign(sighash_type);
        let _ = sign_pubkey_spending(&private_key, &public_key, &sighash).unwrap();

        let sighash_type =
            SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
        let (private_key, public_key, sighash) = prepare_data_for_sign(sighash_type);
        let _ = sign_pubkey_spending(&private_key, &public_key, &sighash).unwrap();

        let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
        let (private_key, public_key, sighash) = prepare_data_for_sign(sighash_type);
        let _ = sign_pubkey_spending(&private_key, &public_key, &sighash).unwrap();

        let sighash_type =
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
        let (private_key, public_key, sighash) = prepare_data_for_sign(sighash_type);
        let _ = sign_pubkey_spending(&private_key, &public_key, &sighash).unwrap();
    }
}
