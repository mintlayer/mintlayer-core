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
    use super::{
        inputsig::{InputWitness, StandardInputSignature},
        sighashtype::SigHashType,
    };
    use crate::{
        chain::{
            signature::{verify_signature, TransactionSigError},
            Destination, OutPointSourceId, Transaction, TransactionCreationError, TxInput,
            TxOutput,
        },
        primitives::{Amount, Id, H256},
    };
    use crypto::key::{KeyKind, PrivateKey};
    use std::vec;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TransactionUpdater {
        pub flags: u32,
        pub inputs: Vec<TxInput>,
        pub outputs: Vec<TxOutput>,
        pub lock_time: u32,
    }

    impl TryFrom<&Transaction> for TransactionUpdater {
        type Error = &'static str;

        fn try_from(tx: &Transaction) -> Result<Self, Self::Error> {
            Ok(Self {
                flags: tx.get_flags(),
                inputs: tx.get_inputs().clone(),
                outputs: tx.get_outputs().clone(),
                lock_time: tx.get_lock_time(),
            })
        }
    }

    impl TransactionUpdater {
        fn generate_tx(&self) -> Result<Transaction, TransactionCreationError> {
            Transaction::new(
                self.flags,
                self.inputs.clone(),
                self.outputs.clone(),
                self.lock_time,
            )
        }
    }

    fn generate_unsign_tx(
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

    fn sign_tx(
        tx: &mut Transaction,
        private_key: &PrivateKey,
        sighash_type: SigHashType,
        outpoint_dest: Destination,
    ) {
        for i in 0..tx.get_inputs().len() {
            let input_sign = StandardInputSignature::produce_signature_for_input(
                private_key,
                sighash_type,
                outpoint_dest.clone(),
                tx,
                i,
            )
            .unwrap();
            tx.update_witness(i, InputWitness::Standard(input_sign)).unwrap();
        }
    }

    fn verify_sign_tx(
        tx: &Transaction,
        outpoint_dest: &Destination,
    ) -> Result<(), TransactionSigError> {
        for i in 0..tx.get_inputs().len() {
            verify_signature(outpoint_dest, tx, i)?
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn sign_and_verify_different_sighash_types() {
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::PublicKey(public_key);
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let mut tx = generate_unsign_tx(outpoint_dest.clone()).unwrap();
        sign_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
        assert_eq!(verify_sign_tx(&tx, &outpoint_dest), Ok(()));

        // ALL
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let mut tx = generate_unsign_tx(outpoint_dest.clone()).unwrap();
        sign_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
        assert_eq!(verify_sign_tx(&tx, &outpoint_dest), Ok(()));

        let sighash_type =
            SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
        let mut tx = generate_unsign_tx(outpoint_dest.clone()).unwrap();
        sign_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
        assert_eq!(verify_sign_tx(&tx, &outpoint_dest), Ok(()));

        // NONE
        let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
        let mut tx = generate_unsign_tx(outpoint_dest.clone()).unwrap();
        sign_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
        assert_eq!(verify_sign_tx(&tx, &outpoint_dest), Ok(()));

        let sighash_type =
            SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
        let mut tx = generate_unsign_tx(outpoint_dest.clone()).unwrap();
        dbg!(tx.get_outputs().len());
        sign_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
        assert_eq!(verify_sign_tx(&tx, &outpoint_dest), Ok(()));

        // SINGLE
        let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
        let mut tx = generate_unsign_tx(outpoint_dest.clone()).unwrap();
        sign_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
        assert_eq!(verify_sign_tx(&tx, &outpoint_dest), Ok(()));

        let sighash_type =
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
        let mut tx = generate_unsign_tx(outpoint_dest.clone()).unwrap();
        sign_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
        assert_eq!(verify_sign_tx(&tx, &outpoint_dest), Ok(()));
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn check_verify_fails_different_sighash_types() {
        let (_, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::PublicKey(public_key);
        let mut tx = generate_unsign_tx(outpoint_dest.clone()).unwrap();
        // Try verify sign for tx with InputWitness::NoSignature and some data
        tx.update_witness(
            0,
            InputWitness::NoSignature(Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9])),
        )
        .unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureNotFound)
        );

        // SigHashType ALL - must fail because there are no bytes in raw_signature
        tx.update_witness(
            0,
            InputWitness::Standard(StandardInputSignature::new(
                SigHashType::try_from(SigHashType::ALL).unwrap(),
                vec![],
            )),
        )
        .unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::InvalidSignatureEncoding)
        );
        // SigHashType ALL - must fail because there are wrong bytes in raw_signature
        tx.update_witness(
            0,
            InputWitness::Standard(StandardInputSignature::new(
                SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap(),
                vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
            )),
        )
        .unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::InvalidSignatureEncoding)
        );

        // SigHashType NONE - must fail because there are no bytes in raw_signature
        tx.update_witness(
            0,
            InputWitness::Standard(StandardInputSignature::new(
                SigHashType::try_from(SigHashType::NONE).unwrap(),
                vec![],
            )),
        )
        .unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::InvalidSignatureEncoding)
        );

        // SigHashType NONE - must fail because there are wrong bytes in raw_signature
        tx.update_witness(
            0,
            InputWitness::Standard(StandardInputSignature::new(
                SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap(),
                vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
            )),
        )
        .unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::InvalidSignatureEncoding)
        );

        // SigHashType SINGLE - must fail because there are no bytes in raw_signature
        tx.update_witness(
            0,
            InputWitness::Standard(StandardInputSignature::new(
                SigHashType::try_from(SigHashType::SINGLE).unwrap(),
                vec![],
            )),
        )
        .unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::InvalidSignatureEncoding)
        );

        // SigHashType SINGLE - must fail because there are wrong bytes in raw_signature
        tx.update_witness(
            0,
            InputWitness::Standard(StandardInputSignature::new(
                SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap(),
                vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
            )),
        )
        .unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::InvalidSignatureEncoding)
        );
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn check_invalid_input_index_for_verify_signature() {
        const INVALID_INPUT_INDEX: usize = 1234567890;

        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::PublicKey(public_key);
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let mut tx = generate_unsign_tx(outpoint_dest.clone()).unwrap();
        sign_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
        // input index out of range
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INVALID_INPUT_INDEX),
            Err(TransactionSigError::InvalidInputIndex(
                INVALID_INPUT_INDEX,
                1
            ))
        );
    }

    #[test]
    fn sign_modify_then_verify() {
        // Create and sign tx, and then modify and verify it.
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::PublicKey(public_key);
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let mut original_tx = generate_unsign_tx(outpoint_dest.clone()).unwrap();
        sign_tx(
            &mut original_tx,
            &private_key,
            sighash_type,
            outpoint_dest.clone(),
        );
        assert_eq!(verify_sign_tx(&original_tx, &outpoint_dest), Ok(()));

        // Should failed due to changed flags
        let mut tx_updater = TransactionUpdater::try_from(&original_tx).unwrap();
        tx_updater.flags = 1234567890;
        let tx = tx_updater.generate_tx().unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
        // Should failed due to changed lock_time
        let mut tx_updater = TransactionUpdater::try_from(&original_tx).unwrap();
        tx_updater.lock_time = 1234567890;
        let tx = tx_updater.generate_tx().unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
        // Should failed due to add a new input
        let mut tx_updater = TransactionUpdater::try_from(&original_tx).unwrap();
        let outpoinr_source_id =
            OutPointSourceId::Transaction(Id::<Transaction>::new(&H256::random()));

        tx_updater.inputs.push(TxInput::new(
            outpoinr_source_id,
            1,
            InputWitness::NoSignature(None),
        ));
        let tx = tx_updater.generate_tx().unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
        // Should failed due to change in witness
        let mut tx_updater = TransactionUpdater::try_from(&original_tx).unwrap();
        let signature = match tx_updater.inputs[0].get_witness() {
            InputWitness::Standard(signature) => {
                // Let's change around 20ish last bytes, it's also avoided SCALE errors
                let mut raw_signature = (&signature.get_raw_signature()[0..60]).to_vec();
                let body_signature: Vec<u8> = signature
                    .get_raw_signature()
                    .iter()
                    .skip(60)
                    .map(|item| {
                        if item < &u8::MAX {
                            item.wrapping_add(1)
                        } else {
                            item.wrapping_sub(1)
                        }
                    })
                    .collect();

                raw_signature.extend(body_signature);
                StandardInputSignature::new(signature.sighash_type(), raw_signature)
            }
            InputWitness::NoSignature(_) => unreachable!(),
        };
        tx_updater.inputs[0].update_witness(InputWitness::Standard(signature));
        let tx = tx_updater.generate_tx().unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
        // Should failed due to add a new output
        let mut tx_updater = TransactionUpdater::try_from(&original_tx).unwrap();
        let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        tx_updater.outputs.push(TxOutput::new(
            Amount::from_atoms(1234567890),
            Destination::PublicKey(pub_key),
        ));
        let tx = tx_updater.generate_tx().unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
        // Should failed due to change in output value
        let mut tx_updater = TransactionUpdater::try_from(&original_tx).unwrap();
        tx_updater.outputs[0] = TxOutput::new(
            (tx_updater.outputs[0].get_value() + Amount::from_atoms(100)).unwrap(),
            tx_updater.outputs[0].get_destination().clone(),
        );
        let tx = tx_updater.generate_tx().unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }
}
