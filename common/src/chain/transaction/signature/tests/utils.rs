// Copyright (c) 2022 RBB S.r.l
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

use itertools::Itertools;
use rand::Rng;

use crypto::key::{PrivateKey, PublicKey};
use script::Script;

use crate::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        signature::{
            inputsig::{InputWitness, StandardInputSignature},
            sighashtype::SigHashType,
            verify_signature, TransactionSigError,
        },
        signed_transaction::SignedTransaction,
        tokens::OutputValue,
        Destination, OutputPurpose, Transaction, TransactionCreationError, TxInput, TxOutput,
    },
    primitives::{amount::UnsignedIntType, Amount, Id, H256},
};

// This is required because we can't access private fields of the Transaction class
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutableTransaction {
    pub flags: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u32,
    pub witness: Vec<InputWitness>,
}

impl From<&SignedTransaction> for MutableTransaction {
    fn from(tx: &SignedTransaction) -> Self {
        Self {
            flags: tx.transaction().flags(),
            inputs: tx.transaction().inputs().clone(),
            outputs: tx.transaction().outputs().clone(),
            lock_time: tx.transaction().lock_time(),
            witness: tx.signatures().to_vec(),
        }
    }
}

impl MutableTransaction {
    pub fn generate_tx(&self) -> Result<SignedTransaction, TransactionCreationError> {
        Ok(SignedTransaction::new(
            Transaction::new(
                self.flags,
                self.inputs.clone(),
                self.outputs.clone(),
                self.lock_time,
            )
            .unwrap(),
            self.witness.clone(),
        ))
    }
}

pub fn generate_unsigned_tx(
    destination: &Destination,
    inputs_count: usize,
    outputs_count: usize,
) -> Result<Transaction, TransactionCreationError> {
    let mut rng = rand::thread_rng();

    let inputs = std::iter::from_fn(|| {
        Some(TxInput::new(
            Id::<Transaction>::new(H256::random()).into(),
            rng.gen(),
        ))
    })
    .take(inputs_count)
    .collect();

    let outputs = std::iter::from_fn(|| {
        Some(TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(rng.gen::<UnsignedIntType>())),
            OutputPurpose::Transfer(destination.clone()),
        ))
    })
    .take(outputs_count)
    .collect();

    let tx = Transaction::new(rng.gen(), inputs, outputs, rng.gen())?;
    Ok(tx)
}

pub fn sign_whole_tx(
    tx: Transaction,
    private_key: &PrivateKey,
    sighash_type: SigHashType,
    destination: &Destination,
) -> Result<SignedTransaction, TransactionSigError> {
    let sigs: Result<Vec<StandardInputSignature>, TransactionSigError> = tx
        .inputs()
        .iter()
        .enumerate()
        .map(|(i, _input)| make_signature(&tx, i, private_key, sighash_type, destination.clone()))
        .collect();
    let witnesses = sigs?.into_iter().map(|s| InputWitness::Standard(s)).collect_vec();

    Ok(SignedTransaction::new(tx, witnesses))
}

pub fn generate_and_sign_tx(
    destination: &Destination,
    inputs: usize,
    outputs: usize,
    private_key: &PrivateKey,
    sighash_type: SigHashType,
) -> Result<SignedTransaction, TransactionCreationError> {
    let tx = generate_unsigned_tx(destination, inputs, outputs).unwrap();
    let signed_tx = sign_whole_tx(tx, private_key, sighash_type, destination).unwrap();
    assert_eq!(verify_signed_tx(&signed_tx, destination), Ok(()));
    Ok(signed_tx)
}

pub fn make_signature(
    tx: &Transaction,
    input_num: usize,
    private_key: &PrivateKey,
    sighash_type: SigHashType,
    outpoint_dest: Destination,
) -> Result<StandardInputSignature, TransactionSigError> {
    let input_sig = StandardInputSignature::produce_signature_for_input(
        private_key,
        sighash_type,
        outpoint_dest,
        tx,
        input_num,
    )?;
    Ok(input_sig)
}

pub fn verify_signed_tx(
    tx: &SignedTransaction,
    destination: &Destination,
) -> Result<(), TransactionSigError> {
    for i in 0..tx.transaction().inputs().len() {
        verify_signature(destination, tx, i)?
    }
    Ok(())
}

/// Returns an iterator over all possible signature hash types.
pub fn sig_hash_types() -> impl Iterator<Item = SigHashType> + Clone {
    [
        SigHashType::try_from(SigHashType::ALL),
        SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY),
        SigHashType::try_from(SigHashType::NONE),
        SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY),
        SigHashType::try_from(SigHashType::SINGLE),
        SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY),
    ]
    .into_iter()
    .map(Result::unwrap)
}

/// Returns an iterator over all possible destinations.
pub fn destinations(public_key: PublicKey) -> impl Iterator<Item = Destination> {
    // TODO: find a way to write this such that it loops over all possible arms instead of doing this manually
    [
        Destination::Address(PublicKeyHash::from(&public_key)),
        Destination::PublicKey(public_key),
        Destination::AnyoneCanSpend,
        Destination::ScriptHash(Id::<Script>::from(H256::random())),
    ]
    .into_iter()
}
