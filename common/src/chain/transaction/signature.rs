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

use crypto::hash::StreamHasher;

use crate::primitives::{
    id::{hash_encoded_to, DefaultHashAlgoStream},
    H256,
};

use self::inputsig::StandardInputSignature;

use super::{Destination, Transaction};

pub mod inputsig;
pub mod sighashtype;

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum TransactionSigError {
    #[error("Invalid sighash value provided")]
    InvalidSigHashValue(u8),
    #[error("Invalid input index was provided (provided: `{0}` vs available: `{1}`")]
    InvalidInputIndex(usize, usize),
    #[error("Input corresponding to output number {0} does not exist (number of inputs is {1})")]
    InvalidOutputIndexForModeSingle(usize, usize),
    #[error("Decoding witness failed ")]
    DecodingWitnessFailed,
    #[error("Signature verification failed ")]
    SignatureVerificationFailed,
    #[error("Public key to address mismatch")]
    PublicKeyToAddressMismatch,
    #[error("Address authorization decoding failed")]
    AddressAuthDecodingFailed(String),
    #[error("Signature decoding failed")]
    InvalidSignatureEncoding,
    #[error("No signature!")]
    SignatureNotFound,
    #[error("Producing signature failed!")]
    ProducingSignatureFailed(crypto::key::SignatureError),
    #[error("Private key does not match with spender public key")]
    SpendeePrivatePublicKeyMismatch,
    #[error("Unsupported yet!")]
    Unsupported,
}

pub fn signature_hash(
    mode: sighashtype::SigHashType,
    tx: &Transaction,
    input_num: usize,
) -> Result<H256, TransactionSigError> {
    let mut stream = DefaultHashAlgoStream::new();

    // TODO: even though this works fine, we need to make this function
    // pull the inputs/outputs automatically through macros;
    // the current way is not safe and may produce issues in the future

    let target_input = tx
        .get_inputs()
        .get(input_num)
        .ok_or_else(|| TransactionSigError::InvalidInputIndex(input_num, tx.get_inputs().len()))?;

    hash_encoded_to(&mode.get(), &mut stream);
    hash_encoded_to(&tx.version_byte(), &mut stream);
    hash_encoded_to(&tx.get_flags(), &mut stream);

    match mode.inputs_mode() {
        sighashtype::InputsMode::CommitWhoPays => {
            hash_encoded_to(&(tx.get_inputs().len() as u32), &mut stream);
            for input in tx.get_inputs() {
                hash_encoded_to(&input.get_outpoint(), &mut stream);
            }
        }
        sighashtype::InputsMode::AnyoneCanPay => {
            hash_encoded_to(&target_input.get_outpoint(), &mut stream);
        }
    }

    match mode.outputs_mode() {
        sighashtype::OutputsMode::All => {
            hash_encoded_to(tx.get_outputs(), &mut stream);
        }
        sighashtype::OutputsMode::None => (),
        sighashtype::OutputsMode::Single => {
            let output = tx.get_outputs().get(input_num).ok_or_else(|| {
                TransactionSigError::InvalidInputIndex(input_num, tx.get_outputs().len())
            })?;
            hash_encoded_to(&output, &mut stream);
        }
    }

    hash_encoded_to(&tx.get_lock_time(), &mut stream);

    // TODO: for P2SH add OP_CODESEPARATOR position
    hash_encoded_to(&u32::MAX, &mut stream);

    let result = stream.finalize().into();
    Ok(result)
}

fn verify_standard_input_signature(
    outpoint_destination: &Destination,
    witness: &StandardInputSignature,
    tx: &Transaction,
    input_num: usize,
) -> Result<(), TransactionSigError> {
    let sighash = signature_hash(witness.sighash_type(), tx, input_num)?;
    witness.verify_signature(outpoint_destination, &sighash)?;
    Ok(())
}

pub fn verify_signature(
    outpoint_destination: &Destination,
    tx: &Transaction,
    input_num: usize,
) -> Result<(), TransactionSigError> {
    let target_input = tx
        .get_inputs()
        .get(input_num)
        .ok_or_else(|| TransactionSigError::InvalidInputIndex(input_num, tx.get_inputs().len()))?;
    let input_witness = target_input.get_witness();
    match input_witness {
        inputsig::InputWitness::NoSignature(_) => {
            return Err(TransactionSigError::SignatureNotFound)
        }
        inputsig::InputWitness::Standard(witness) => {
            verify_standard_input_signature(outpoint_destination, witness, tx, input_num)?
        }
    }
    Ok(())
}
// TODO: write tests

#[cfg(test)]
mod test {
    use std::vec;

    use crypto::key::{KeyKind, PrivateKey};

    use super::{
        inputsig::{InputWitness, StandardInputSignature},
        sighashtype::SigHashType,
    };
    use crate::{
        chain::{
            signature::{verify_signature, TransactionSigError},
            Destination, Transaction, TransactionCreationError, TxInput, TxOutput,
        },
        primitives::{Amount, Id, H256},
    };

    fn generate_tx(
        private_key: PrivateKey,
        sighash_type: SigHashType,
        dest: Destination,
    ) -> Result<Transaction, TransactionCreationError> {
        let mut tx = Transaction::new(
            0,
            vec![
                TxInput::new(
                    Id::<Transaction>::new(&H256::zero()).into(),
                    0,
                    InputWitness::NoSignature(None),
                ),
                TxInput::new(
                    Id::<Transaction>::new(&H256::random()).into(),
                    1,
                    InputWitness::NoSignature(None),
                ),
            ],
            vec![TxOutput::new(Amount::from_atoms(100), dest.clone())],
            0,
        )?;

        let signature = StandardInputSignature::produce_signature_for_input(
            &private_key,
            sighash_type,
            dest.clone(),
            &tx,
            0,
        )
        .unwrap();

        tx.update_witness(0, InputWitness::Standard(signature.clone())).unwrap();
        Ok(tx)
    }

    fn sign_tx(
        tx: &mut Transaction,
        private_key: &PrivateKey,
        sighash_type: SigHashType,
        dest: Destination,
    ) {
        for i in 0..tx.get_inputs().len() {
            let input_sign = StandardInputSignature::produce_signature_for_input(
                private_key,
                sighash_type,
                dest.clone(),
                &tx,
                0,
            )
            .unwrap();
            tx.update_witness(i, InputWitness::Standard(input_sign)).unwrap();
        }
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn check_sign_and_verify() {
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::PublicKey(public_key);
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let mut tx = generate_tx(private_key.clone(), sighash_type, outpoint_dest.clone()).unwrap();
        sign_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
        assert!(verify_signature(&outpoint_dest, &tx, 0).is_ok());
        assert!(verify_signature(&outpoint_dest, &tx, 1).is_ok());

        // ALL
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let tx = generate_tx(private_key.clone(), sighash_type, outpoint_dest.clone()).unwrap();
        assert!(verify_signature(&outpoint_dest, &tx, 0).is_ok());
        assert!(verify_signature(&outpoint_dest, &tx, 1).is_err());

        let sighash_type =
            SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
        let tx = generate_tx(private_key.clone(), sighash_type, outpoint_dest.clone()).unwrap();
        assert!(verify_signature(&outpoint_dest, &tx, 0).is_ok());
        assert!(verify_signature(&outpoint_dest, &tx, 1).is_err());

        // NONE
        let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
        let tx = generate_tx(private_key.clone(), sighash_type, outpoint_dest.clone()).unwrap();
        assert!(verify_signature(&outpoint_dest, &tx, 0).is_ok());
        assert!(verify_signature(&outpoint_dest, &tx, 1).is_err());

        let sighash_type =
            SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
        let tx = generate_tx(private_key.clone(), sighash_type, outpoint_dest.clone()).unwrap();
        assert!(verify_signature(&outpoint_dest, &tx, 0).is_ok());
        assert!(verify_signature(&outpoint_dest, &tx, 1).is_err());

        // SINGLE
        let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
        let tx = generate_tx(private_key.clone(), sighash_type, outpoint_dest.clone()).unwrap();
        assert!(verify_signature(&outpoint_dest, &tx, 0).is_ok());
        assert!(verify_signature(&outpoint_dest, &tx, 1).is_err());

        let sighash_type =
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
        let tx = generate_tx(private_key.clone(), sighash_type, outpoint_dest.clone()).unwrap();
        assert!(verify_signature(&outpoint_dest, &tx, 0).is_ok());
        assert!(verify_signature(&outpoint_dest, &tx, 1).is_err());
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn check_verify_fails() {
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::PublicKey(public_key);
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let mut tx = generate_tx(private_key.clone(), sighash_type, outpoint_dest.clone()).unwrap();
        tx.update_witness(
            0,
            InputWitness::NoSignature(Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9])),
        )
        .unwrap();
        assert!(verify_signature(&outpoint_dest, &tx, 0).is_err());

        // ALL
        tx.update_witness(
            0,
            InputWitness::Standard(StandardInputSignature::new(
                SigHashType::try_from(SigHashType::ALL).unwrap(),
                vec![],
            )),
        )
        .unwrap();
        assert!(verify_signature(&outpoint_dest, &tx, 0).is_err());

        tx.update_witness(
            0,
            InputWitness::Standard(StandardInputSignature::new(
                SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap(),
                vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
            )),
        )
        .unwrap();
        assert!(verify_signature(&outpoint_dest, &tx, 0).is_err());

        // NONE
        tx.update_witness(
            0,
            InputWitness::Standard(StandardInputSignature::new(
                SigHashType::try_from(SigHashType::NONE).unwrap(),
                vec![],
            )),
        )
        .unwrap();
        assert!(verify_signature(&outpoint_dest, &tx, 0).is_err());

        tx.update_witness(
            0,
            InputWitness::Standard(StandardInputSignature::new(
                SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap(),
                vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
            )),
        )
        .unwrap();
        assert!(verify_signature(&outpoint_dest, &tx, 0).is_err());

        // SINGLE
        tx.update_witness(
            0,
            InputWitness::Standard(StandardInputSignature::new(
                SigHashType::try_from(SigHashType::SINGLE).unwrap(),
                vec![],
            )),
        )
        .unwrap();
        assert!(verify_signature(&outpoint_dest, &tx, 0).is_err());

        tx.update_witness(
            0,
            InputWitness::Standard(StandardInputSignature::new(
                SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap(),
                vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
            )),
        )
        .unwrap();
        assert!(verify_signature(&outpoint_dest, &tx, 0).is_err());
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn check_invalid_input_index() {
        const INVALID_INPUT_INDEX: usize = 1234567890;

        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::PublicKey(public_key);
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let tx = generate_tx(private_key.clone(), sighash_type, outpoint_dest.clone()).unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INVALID_INPUT_INDEX),
            Err(TransactionSigError::InvalidInputIndex(
                INVALID_INPUT_INDEX,
                2
            ))
        );
    }
}
