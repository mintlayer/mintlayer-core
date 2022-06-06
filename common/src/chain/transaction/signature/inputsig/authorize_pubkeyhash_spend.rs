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

#[derive(Debug, Encode, Decode, PartialEq)]
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
    use crypto::key::{KeyKind, PrivateKey};

    use crate::{
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

    use super::*;

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

    fn prepare_data_for_verify(
        sighash_type: SigHashType,
    ) -> (PublicKeyHash, AuthorizedPublicKeyHashSpend, H256) {
        const INPUT_NUM: usize = 0;
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let pubkey_hash = PublicKeyHash::from(&public_key);
        let outpoint_dest = Destination::Address(pubkey_hash);
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
            AuthorizedPublicKeyHashSpend::from_data(witness.get_raw_signature()).unwrap();
        let sighash = signature_hash(witness.sighash_type(), &tx, INPUT_NUM).unwrap();
        (pubkey_hash, spender_signature, sighash)
    }

    fn prepare_data_for_wrong_destination(sighash_type: SigHashType) -> StandardInputSignature {
        const INPUT_NUM: usize = 0;
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::PublicKey(public_key);
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
        // Destination = Address, but we try to use here AuthorizedPublicKeyHashSpend
        {
            let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
            let witness = prepare_data_for_wrong_destination(sighash_type);
            // Compare Err(TransactionSigError) without inner message
            assert!(matches!(
                AuthorizedPublicKeyHashSpend::from_data(witness.get_raw_signature()).unwrap_err(),
                TransactionSigError::AddressAuthDecodingFailed(_)
            ));
        }
        {
            let sighash_type =
                SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
            let witness = prepare_data_for_wrong_destination(sighash_type);
            assert!(matches!(
                AuthorizedPublicKeyHashSpend::from_data(witness.get_raw_signature()).unwrap_err(),
                TransactionSigError::AddressAuthDecodingFailed(_)
            ));
        }
        {
            let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
            let witness = prepare_data_for_wrong_destination(sighash_type);
            assert!(matches!(
                AuthorizedPublicKeyHashSpend::from_data(witness.get_raw_signature()).unwrap_err(),
                TransactionSigError::AddressAuthDecodingFailed(_)
            ));
        }
        {
            let sighash_type =
                SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
            let witness = prepare_data_for_wrong_destination(sighash_type);
            assert!(matches!(
                AuthorizedPublicKeyHashSpend::from_data(witness.get_raw_signature()).unwrap_err(),
                TransactionSigError::AddressAuthDecodingFailed(_)
            ));
        }
        {
            let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
            let witness = prepare_data_for_wrong_destination(sighash_type);
            assert!(matches!(
                AuthorizedPublicKeyHashSpend::from_data(witness.get_raw_signature()).unwrap_err(),
                TransactionSigError::AddressAuthDecodingFailed(_)
            ));
        }
        {
            let sighash_type =
                SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
            let witness = prepare_data_for_wrong_destination(sighash_type);
            assert!(matches!(
                AuthorizedPublicKeyHashSpend::from_data(witness.get_raw_signature()).unwrap_err(),
                TransactionSigError::AddressAuthDecodingFailed(_)
            ));
        }
    }

    #[test]
    fn test_verify_address_spending() {
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let (public_key, spender_signature, sighash) = prepare_data_for_verify(sighash_type);
        verify_address_spending(&public_key, &spender_signature, &sighash).unwrap();

        let sighash_type =
            SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
        let (public_key, spender_signature, sighash) = prepare_data_for_verify(sighash_type);
        verify_address_spending(&public_key, &spender_signature, &sighash).unwrap();

        let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
        let (public_key, spender_signature, sighash) = prepare_data_for_verify(sighash_type);
        verify_address_spending(&public_key, &spender_signature, &sighash).unwrap();

        let sighash_type =
            SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
        let (public_key, spender_signature, sighash) = prepare_data_for_verify(sighash_type);
        verify_address_spending(&public_key, &spender_signature, &sighash).unwrap();

        let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
        let (public_key, spender_signature, sighash) = prepare_data_for_verify(sighash_type);
        verify_address_spending(&public_key, &spender_signature, &sighash).unwrap();

        let sighash_type =
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
        let (public_key, spender_signature, sighash) = prepare_data_for_verify(sighash_type);
        verify_address_spending(&public_key, &spender_signature, &sighash).unwrap();
    }

    fn prepare_data_for_sign(sighash_type: SigHashType) -> (PrivateKey, PublicKeyHash, H256) {
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
        (private_key, PublicKeyHash::from(&public_key), sighash)
    }

    #[test]
    fn test_sign_address_spending() {
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let (private_key, public_key, sighash) = prepare_data_for_sign(sighash_type);
        let _ = sign_address_spending(&private_key, &public_key, &sighash).unwrap();

        let sighash_type =
            SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
        let (private_key, public_key, sighash) = prepare_data_for_sign(sighash_type);
        let _ = sign_address_spending(&private_key, &public_key, &sighash).unwrap();

        let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
        let (private_key, public_key, sighash) = prepare_data_for_sign(sighash_type);
        let _ = sign_address_spending(&private_key, &public_key, &sighash).unwrap();

        let sighash_type =
            SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
        let (private_key, public_key, sighash) = prepare_data_for_sign(sighash_type);
        let _ = sign_address_spending(&private_key, &public_key, &sighash).unwrap();

        let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
        let (private_key, public_key, sighash) = prepare_data_for_sign(sighash_type);
        let _ = sign_address_spending(&private_key, &public_key, &sighash).unwrap();

        let sighash_type =
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
        let (private_key, public_key, sighash) = prepare_data_for_sign(sighash_type);
        let _ = sign_address_spending(&private_key, &public_key, &sighash).unwrap();
    }
}
