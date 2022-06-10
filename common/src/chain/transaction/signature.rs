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
use parity_scale_codec::Encode;

use crate::{
    chain::TxInput,
    primitives::{
        id::{hash_encoded_to, DefaultHashAlgoStream},
        H256,
    },
};

use self::inputsig::StandardInputSignature;

use super::{Destination, Transaction, TxOutput};

pub mod inputsig;
pub mod sighashtype;

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum TransactionSigError {
    #[error("Invalid sighash value provided")]
    InvalidSigHashValue(u8),
    #[error("Invalid input index was provided (provided: `{0}` vs available: `{1}`")]
    InvalidInputIndex(usize, usize),
    #[error("Requested signature hash without the presence of any inputs")]
    SigHashRequestWithoutInputs,
    #[error("Attempted to verify signatures for a transaction without inputs")]
    SignatureVerificationWithoutInputs,
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
    #[error("AnyoneCanSpend should not use standard signatures, this place should be unreachable")]
    AttemptedToVerifyStandardSignatureForAnyoneCanSpend,
    #[error("AnyoneCanSpend should not use standard signatures, so producing a signature for it is not possible")]
    AttemptedToProduceSignatureForAnyoneCanSpend,
    #[error("Unsupported yet!")]
    Unsupported,
}

pub fn signature_hash_for_inputs(
    stream: &mut DefaultHashAlgoStream,
    mode: sighashtype::SigHashType,
    inputs: &[TxInput],
    target_input: &TxInput,
) {
    match mode.inputs_mode() {
        sighashtype::InputsMode::CommitWhoPays => {
            hash_encoded_to(&(inputs.len() as u32), stream);
            for input in inputs {
                hash_encoded_to(&input.get_outpoint(), stream);
            }
        }
        sighashtype::InputsMode::AnyoneCanPay => {
            hash_encoded_to(&target_input.get_outpoint(), stream);
        }
    }
}

pub fn signature_hash_for_outputs(
    stream: &mut DefaultHashAlgoStream,
    mode: sighashtype::SigHashType,
    outputs: &[TxOutput],
    target_input_num: usize,
) -> Result<(), TransactionSigError> {
    match mode.outputs_mode() {
        sighashtype::OutputsMode::All => {
            hash_encoded_to(&outputs, stream);
        }
        sighashtype::OutputsMode::None => (),
        sighashtype::OutputsMode::Single => {
            let output = outputs.get(target_input_num).ok_or({
                TransactionSigError::InvalidInputIndex(target_input_num, outputs.len())
            })?;
            hash_encoded_to(&output, stream);
        }
    }
    Ok(())
}

trait SignatureHashableElement {
    fn signature_hash(
        &self,
        stream: &mut DefaultHashAlgoStream,
        mode: sighashtype::SigHashType,
        target_input: &TxInput,
        target_input_num: usize,
    ) -> Result<(), TransactionSigError>;
}

impl SignatureHashableElement for &[TxInput] {
    fn signature_hash(
        &self,
        stream: &mut DefaultHashAlgoStream,
        mode: sighashtype::SigHashType,
        target_input: &TxInput,
        _target_input_num: usize,
    ) -> Result<(), TransactionSigError> {
        match mode.inputs_mode() {
            sighashtype::InputsMode::CommitWhoPays => {
                hash_encoded_to(&(self.len() as u32), stream);
                for input in *self {
                    hash_encoded_to(&input.get_outpoint(), stream);
                }
            }
            sighashtype::InputsMode::AnyoneCanPay => {
                hash_encoded_to(&target_input.get_outpoint(), stream);
            }
        }
        Ok(())
    }
}

impl SignatureHashableElement for &[TxOutput] {
    fn signature_hash(
        &self,
        stream: &mut DefaultHashAlgoStream,
        mode: sighashtype::SigHashType,
        _target_input: &TxInput,
        target_input_num: usize,
    ) -> Result<(), TransactionSigError> {
        match mode.outputs_mode() {
            sighashtype::OutputsMode::All => {
                hash_encoded_to(self, stream);
            }
            sighashtype::OutputsMode::None => (),
            sighashtype::OutputsMode::Single => {
                let output = self.get(target_input_num).ok_or({
                    TransactionSigError::InvalidInputIndex(target_input_num, self.len())
                })?;
                hash_encoded_to(&output, stream);
            }
        }
        Ok(())
    }
}

fn hash_encoded_if_some<T: Encode>(val: &Option<T>, stream: &mut DefaultHashAlgoStream) {
    match val {
        Some(ref v) => hash_encoded_to(&v, stream),
        None => (),
    }
}

pub trait Transactable {
    fn inputs(&self) -> Option<&[TxInput]>;
    fn outputs(&self) -> Option<&[TxOutput]>;
    fn version_byte(&self) -> Option<u8>;
    fn lock_time(&self) -> Option<u32>;
    fn flags(&self) -> Option<u32>;
}

impl Transactable for Transaction {
    fn inputs(&self) -> Option<&[TxInput]> {
        Some(self.get_inputs())
    }

    fn outputs(&self) -> Option<&[TxOutput]> {
        Some(self.get_outputs())
    }

    fn version_byte(&self) -> Option<u8> {
        Some(self.version_byte())
    }

    fn lock_time(&self) -> Option<u32> {
        Some(self.get_lock_time())
    }

    fn flags(&self) -> Option<u32> {
        Some(self.get_flags())
    }
}

fn stream_signature_hash<T: Transactable>(
    tx: &T,
    stream: &mut DefaultHashAlgoStream,
    mode: sighashtype::SigHashType,
    target_input_num: usize,
) -> Result<(), TransactionSigError> {
    // TODO: even though this works fine, we need to make this function
    // pull the inputs/outputs automatically through macros;
    // the current way is not safe and may produce issues in the future

    let inputs = match tx.inputs() {
        Some(ins) => ins,
        None => return Err(TransactionSigError::SigHashRequestWithoutInputs),
    };

    let outputs = tx.outputs().unwrap_or_default();

    let target_input = inputs.get(target_input_num).ok_or(
        TransactionSigError::InvalidInputIndex(target_input_num, inputs.len()),
    )?;

    hash_encoded_to(&mode.get(), stream);

    hash_encoded_if_some(&tx.version_byte(), stream);
    hash_encoded_if_some(&tx.flags(), stream);
    hash_encoded_if_some(&tx.lock_time(), stream);

    inputs.signature_hash(stream, mode, target_input, target_input_num)?;
    outputs.signature_hash(stream, mode, target_input, target_input_num)?;

    // TODO: consider doing just like taproot, and hash in all outputs that come from the outpoints of inputs,
    //       this would be a good solution to avoid having to download full trasactions to verify inputs

    // TODO: for P2SH add OP_CODESEPARATOR position
    hash_encoded_to(&u32::MAX, stream);

    Ok(())
}

pub fn signature_hash<T: Transactable>(
    mode: sighashtype::SigHashType,
    tx: &T,
    input_num: usize,
) -> Result<H256, TransactionSigError> {
    let mut stream = DefaultHashAlgoStream::new();

    stream_signature_hash(tx, &mut stream, mode, input_num)?;

    let result = stream.finalize().into();
    Ok(result)
}

fn verify_standard_input_signature<T: Transactable>(
    outpoint_destination: &Destination,
    witness: &StandardInputSignature,
    tx: &T,
    input_num: usize,
) -> Result<(), TransactionSigError> {
    let sighash = signature_hash(witness.sighash_type(), tx, input_num)?;
    witness.verify_signature(outpoint_destination, &sighash)?;
    Ok(())
}

pub fn verify_signature<T: Transactable>(
    outpoint_destination: &Destination,
    tx: &T,
    input_num: usize,
) -> Result<(), TransactionSigError> {
    let inputs = tx.inputs().ok_or(TransactionSigError::SignatureVerificationWithoutInputs)?;
    let target_input = inputs.get(input_num).ok_or(TransactionSigError::InvalidInputIndex(
        input_num,
        inputs.len(),
    ))?;
    let input_witness = target_input.get_witness();
    match input_witness {
        inputsig::InputWitness::NoSignature(_) => match outpoint_destination {
            Destination::Address(_) => return Err(TransactionSigError::SignatureNotFound),
            Destination::PublicKey(_) => return Err(TransactionSigError::SignatureNotFound),
            Destination::ScriptHash(_) => return Err(TransactionSigError::SignatureNotFound),
            Destination::AnyoneCanSpend => {}
        },
        inputsig::InputWitness::Standard(witness) => {
            verify_standard_input_signature(outpoint_destination, witness, tx, input_num)?
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::{
        inputsig::{InputWitness, StandardInputSignature},
        sighashtype::SigHashType,
    };
    use crate::{
        address::pubkeyhash::PublicKeyHash,
        chain::{
            signature::{verify_signature, TransactionSigError},
            Destination, OutPointSourceId, Transaction, TransactionCreationError, TxInput,
            TxOutput,
        },
        primitives::{Amount, Id, H256},
    };
    use crypto::key::{KeyKind, PrivateKey};
    use script::Script;
    use std::vec;

    // This is required because we can't access private fields of the Transaction class
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MutableTransaction {
        pub flags: u32,
        pub inputs: Vec<TxInput>,
        pub outputs: Vec<TxOutput>,
        pub lock_time: u32,
    }

    impl TryFrom<&Transaction> for MutableTransaction {
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

    impl MutableTransaction {
        fn generate_tx(&self) -> Result<Transaction, TransactionCreationError> {
            Transaction::new(
                self.flags,
                self.inputs.clone(),
                self.outputs.clone(),
                self.lock_time,
            )
        }
    }

    fn generate_unsigned_tx(
        outpoint_dest: Destination,
        inputs_amount: u32,
    ) -> Result<Transaction, TransactionCreationError> {
        let mut inputs = Vec::new();
        for output_index in 0..inputs_amount {
            inputs.push(TxInput::new(
                Id::<Transaction>::new(&H256::random()).into(),
                output_index,
                InputWitness::NoSignature(None),
            ));
        }
        let tx = Transaction::new(
            0,
            inputs,
            vec![TxOutput::new(Amount::from_atoms(100), outpoint_dest)],
            0,
        )?;
        Ok(tx)
    }

    fn sign_whole_tx(
        tx: &mut Transaction,
        private_key: &PrivateKey,
        sighash_type: SigHashType,
        outpoint_dest: Destination,
    ) -> Result<(), TransactionSigError> {
        for i in 0..tx.get_inputs().len() {
            update_signature(tx, i, private_key, sighash_type, outpoint_dest.clone())?;
        }
        Ok(())
    }

    fn update_signature(
        tx: &mut Transaction,
        input_num: usize,
        private_key: &PrivateKey,
        sighash_type: SigHashType,
        outpoint_dest: Destination,
    ) -> Result<(), TransactionSigError> {
        let input_sign = StandardInputSignature::produce_signature_for_input(
            private_key,
            sighash_type,
            outpoint_dest.clone(),
            tx,
            input_num,
        )?;
        tx.update_witness(input_num, InputWitness::Standard(input_sign)).unwrap();
        Ok(())
    }

    fn verify_signed_tx(
        tx: &Transaction,
        outpoint_dest: &Destination,
    ) -> Result<(), TransactionSigError> {
        for i in 0..tx.get_inputs().len() {
            verify_signature(outpoint_dest, tx, i)?
        }
        Ok(())
    }

    #[test]
    fn sign_and_verify_sighash_all() {
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        {
            // Sign 20 inputs as SigHashType::ALL and verify them all
            // Destination = PubKey
            let outpoint_dest = Destination::PublicKey(public_key.clone());
            let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 20).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
            assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
        }
        {
            // Sign 20 inputs as SigHashType::ALL | SigHashType::ANYONECANPAY and verify them all
            // - Destination = PubKey
            let outpoint_dest = Destination::PublicKey(public_key.clone());
            let sighash_type =
                SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 20).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
            assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
        }
        {
            // Sign 20 inputs as SigHashType::ALL and verify them all
            // - Destination = Address
            let outpoint_dest = Destination::Address(PublicKeyHash::from(&public_key));
            let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 20).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
            assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
        }
        {
            // Sign 20 inputs as SigHashType::ALL | SigHashType::ANYONECANPAY and verify them all
            // - Destination = Address
            let outpoint_dest = Destination::Address(PublicKeyHash::from(&public_key));
            let sighash_type =
                SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 20).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
            assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
        }
        {
            // Sign 20 inputs as SigHashType::ALL and verify them all
            // - Destination = AnyoneCanSpend
            let outpoint_dest = Destination::AnyoneCanSpend;
            let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 20).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
            assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
        }
        {
            // Sign 20 inputs as SigHashType::ALL | SigHashType::ANYONECANPAY and verify them all
            // - Destination = AnyoneCanSpend
            let outpoint_dest = Destination::AnyoneCanSpend;
            let sighash_type =
                SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 20).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
            assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
        }
        {
            // Sign 20 inputs as SigHashType::ALL and verify them all
            // - Destination = ScriptHash
            let outpoint_dest = Destination::ScriptHash(Id::<Script>::from(H256::random()));
            let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 20).unwrap();

            // TODO: if ScriptHash works fine, we should update this test
            assert_eq!(
                sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()),
                Err(TransactionSigError::Unsupported)
            );
        }
        {
            // Sign 20 inputs as SigHashType::ALL | SigHashType::ANYONECANPAY and verify them all
            // - Destination = ScriptHash
            let outpoint_dest = Destination::ScriptHash(Id::<Script>::from(H256::random()));
            let sighash_type =
                SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 20).unwrap();

            // TODO: if ScriptHash works fine, we should update this test
            assert_eq!(
                sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()),
                Err(TransactionSigError::Unsupported)
            );
        }
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn sign_and_verify_different_sighash_types() {
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::PublicKey(public_key);
        {
            // ALL
            let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
            assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
        }
        {
            let sighash_type =
                SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
            assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
        }
        {
            // NONE
            let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
            assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
        }
        {
            let sighash_type =
                SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
            assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
        }
        {
            // SINGLE
            let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
            assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
        }
        {
            let sighash_type =
                SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
            assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
        }
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn check_verify_fails_different_sighash_types() {
        let (_, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::PublicKey(public_key);
        let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3).unwrap();
        {
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
        }
        {
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
        }
        {
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
        }
        {
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
        }
        {
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
        }
        {
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
        }
        {
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
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn check_invalid_input_index_for_verify_signature() {
        const INVALID_INPUT_INDEX: usize = 1234567890;
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::PublicKey(public_key);
        {
            let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
            // input index out of range
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, INVALID_INPUT_INDEX),
                Err(TransactionSigError::InvalidInputIndex(
                    INVALID_INPUT_INDEX,
                    1
                ))
            );
        }
        {
            // ALL | ANYONECANPAY
            let sighash_type =
                SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, INVALID_INPUT_INDEX),
                Err(TransactionSigError::InvalidInputIndex(
                    INVALID_INPUT_INDEX,
                    1
                ))
            );
        }
        {
            // SINGLE
            let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, INVALID_INPUT_INDEX),
                Err(TransactionSigError::InvalidInputIndex(
                    INVALID_INPUT_INDEX,
                    1
                ))
            );
        }
        {
            // SINGLE | ANYONECANPAY
            let sighash_type =
                SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, INVALID_INPUT_INDEX),
                Err(TransactionSigError::InvalidInputIndex(
                    INVALID_INPUT_INDEX,
                    1
                ))
            );
        }
        {
            // NONE
            let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, INVALID_INPUT_INDEX),
                Err(TransactionSigError::InvalidInputIndex(
                    INVALID_INPUT_INDEX,
                    1
                ))
            );
        }
        {
            // NONE | ANYONECANPAY
            let sighash_type =
                SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
            let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3).unwrap();
            sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone());
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, INVALID_INPUT_INDEX),
                Err(TransactionSigError::InvalidInputIndex(
                    INVALID_INPUT_INDEX,
                    1
                ))
            );
        }
    }

    fn sign_modify_then_verify(
        private_key: &PrivateKey,
        sighash_type: SigHashType,
        outpoint_dest: &Destination,
    ) -> Transaction {
        // Create and sign tx, and then modify and verify it.
        let mut original_tx = generate_unsigned_tx(outpoint_dest.clone(), 3).unwrap();
        sign_whole_tx(
            &mut original_tx,
            private_key,
            sighash_type,
            outpoint_dest.clone(),
        );
        assert_eq!(verify_signed_tx(&original_tx, outpoint_dest), Ok(()));

        check_change_flags(&original_tx, outpoint_dest);
        check_change_locktime(&original_tx, outpoint_dest);
        check_change_witness(&original_tx, outpoint_dest);
        original_tx
    }

    fn check_change_flags(original_tx: &Transaction, outpoint_dest: &Destination) {
        let mut tx_updater = MutableTransaction::try_from(original_tx).unwrap();
        tx_updater.flags = 1234567890;
        let tx = tx_updater.generate_tx().unwrap();
        assert_eq!(
            verify_signature(outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }

    fn check_change_locktime(original_tx: &Transaction, outpoint_dest: &Destination) {
        let mut tx_updater = MutableTransaction::try_from(original_tx).unwrap();
        tx_updater.lock_time = 1234567890;
        let tx = tx_updater.generate_tx().unwrap();
        assert_eq!(
            verify_signature(outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }

    fn check_insert_input(original_tx: &Transaction, outpoint_dest: &Destination) {
        let mut tx_updater = MutableTransaction::try_from(original_tx).unwrap();
        let outpoinr_source_id =
            OutPointSourceId::Transaction(Id::<Transaction>::new(&H256::random()));
        tx_updater.inputs.push(TxInput::new(
            outpoinr_source_id,
            1,
            InputWitness::NoSignature(None),
        ));
        let tx = tx_updater.generate_tx().unwrap();
        assert_eq!(
            verify_signature(outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }

    fn check_change_witness(original_tx: &Transaction, outpoint_dest: &Destination) {
        // Should failed due to change in witness
        let mut tx_updater = MutableTransaction::try_from(original_tx).unwrap();
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
            verify_signature(outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }

    fn check_insert_output(original_tx: &Transaction, outpoint_dest: &Destination) {
        let mut tx_updater = MutableTransaction::try_from(original_tx).unwrap();
        let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        tx_updater.outputs.push(TxOutput::new(
            Amount::from_atoms(1234567890),
            Destination::PublicKey(pub_key),
        ));
        let tx = tx_updater.generate_tx().unwrap();
        assert_eq!(
            verify_signature(outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }

    fn check_change_output(original_tx: &Transaction, outpoint_dest: &Destination) {
        // Should failed due to change in output value
        let mut tx_updater = MutableTransaction::try_from(original_tx).unwrap();
        tx_updater.outputs[0] = TxOutput::new(
            (tx_updater.outputs[0].get_value() + Amount::from_atoms(100)).unwrap(),
            tx_updater.outputs[0].get_destination().clone(),
        );
        let tx = tx_updater.generate_tx().unwrap();
        assert_eq!(
            verify_signature(outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }

    fn check_change_input(original_tx: &Transaction, outpoint_dest: &Destination) {
        // Should failed due to change in output value
        let mut tx_updater = MutableTransaction::try_from(original_tx).unwrap();
        tx_updater.inputs[0] = TxInput::new(
            OutPointSourceId::Transaction(Id::<Transaction>::from(H256::random())),
            9999,
            tx_updater.inputs[0].get_witness().clone(),
        );
        let tx = tx_updater.generate_tx().unwrap();
        assert_eq!(
            verify_signature(outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn test_sign_modify_then_verify() {
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let outpoint_dest = Destination::PublicKey(public_key);
        {
            // ALL - It signs every input and output, and any change to the transaction will render the signature invalid.
            let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
            let original_tx = sign_modify_then_verify(&private_key, sighash_type, &outpoint_dest);
            check_insert_input(&original_tx, &outpoint_dest);
            check_insert_output(&original_tx, &outpoint_dest);
            check_change_output(&original_tx, &outpoint_dest);
            check_change_input(&original_tx, &outpoint_dest);
        }
        {
            // ALL | ANYONECANPAY
            let sighash_type =
                SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
            let original_tx = sign_modify_then_verify(&private_key, sighash_type, &outpoint_dest);
            check_insert_output(&original_tx, &outpoint_dest);
            check_change_output(&original_tx, &outpoint_dest);
            check_change_input(&original_tx, &outpoint_dest);
        }
        {
            // NONE -  This signs all the inputs to the transaction, but none of the outputs.
            let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
            let original_tx = sign_modify_then_verify(&private_key, sighash_type, &outpoint_dest);
            check_change_input(&original_tx, &outpoint_dest);
            check_insert_input(&original_tx, &outpoint_dest);
        }
        {
            // NONE | ANYONECANPAY
            let sighash_type =
                SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
            let original_tx = sign_modify_then_verify(&private_key, sighash_type, &outpoint_dest);
            check_change_input(&original_tx, &outpoint_dest);
        }
        {
            // SINGLE
            let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
            let original_tx = sign_modify_then_verify(&private_key, sighash_type, &outpoint_dest);
            check_insert_input(&original_tx, &outpoint_dest);
            check_change_output(&original_tx, &outpoint_dest);
            check_change_input(&original_tx, &outpoint_dest);
        }
        {
            // SINGLE | ANYONECANPAY
            let sighash_type =
                SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
            let original_tx = sign_modify_then_verify(&private_key, sighash_type, &outpoint_dest);
            check_change_output(&original_tx, &outpoint_dest);
            check_change_input(&original_tx, &outpoint_dest);
        }
    }
}
