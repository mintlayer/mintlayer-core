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

use std::vec;

use itertools::Itertools;

use crypto::key::{KeyKind, PrivateKey};

use self::utils::*;
use super::{
    inputsig::{InputWitness, StandardInputSignature},
    sighashtype::SigHashType,
};
use crate::{
    chain::{
        signature::{verify_signature, TransactionSigError},
        signed_transaction::SignedTransaction,
        tokens::OutputValue,
        Destination, OutPointSourceId, OutputPurpose, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, Id, H256},
};

mod mixed_sighash_types;
mod sign_and_mutate;
mod sign_and_verify;

pub mod utils;

#[test]
fn sign_and_verify_different_sighash_types() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let destination = Destination::PublicKey(public_key);

    for sighash_type in sig_hash_types() {
        let tx = generate_and_sign_tx(&destination, 3, 3, &private_key, sighash_type).unwrap();
        assert_eq!(
            verify_signed_tx(&tx, &destination),
            Ok(()),
            "{sighash_type:?}"
        );
    }
}

// Trying to verify a transaction without signature should produce the corresponding error.
#[test]
fn verify_no_signature() {
    let (_, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);

    for destination in destinations(public_key).filter(|d| d != &Destination::AnyoneCanSpend) {
        let tx = generate_unsigned_tx(&destination, 3, 3).unwrap();
        let witnesses = (0..tx.inputs().len())
            .into_iter()
            .map(|_| InputWitness::NoSignature(Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9])))
            .collect_vec();
        let signed_tx = tx.with_signatures(witnesses).unwrap();
        assert_eq!(
            verify_signature(&destination, &signed_tx, 0),
            Err(TransactionSigError::SignatureNotFound),
            "{destination:?}"
        );
    }
}

// Try to verify empty and wrong (arbitrary bytes) signatures.
#[test]
fn verify_invalid_signature() {
    let (_, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let destination = Destination::PublicKey(public_key);
    let empty_signature = vec![];
    let invalid_signature = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];

    for (sighash_type, raw_signature) in
        sig_hash_types().cartesian_product([empty_signature, invalid_signature])
    {
        let tx = generate_unsigned_tx(&destination, 3, 3).unwrap();
        let witnesses = (0..tx.inputs().len())
            .into_iter()
            .map(|_| {
                InputWitness::Standard(StandardInputSignature::new(
                    sighash_type,
                    raw_signature.clone(),
                ))
            })
            .collect_vec();
        let signed_tx = tx.with_signatures(witnesses).unwrap();

        assert_eq!(
            verify_signature(&destination, &signed_tx, 0),
            Err(TransactionSigError::InvalidSignatureEncoding),
            "{sighash_type:?}, signature = {raw_signature:?}"
        );
    }
}

#[test]
fn verify_signature_invalid_signature_index() {
    const INVALID_SIGNATURE_INDEX: usize = 1234567890;

    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let destination = Destination::PublicKey(public_key);

    for sighash_type in sig_hash_types() {
        let tx = generate_and_sign_tx(&destination, 3, 3, &private_key, sighash_type).unwrap();
        assert_eq!(
            verify_signature(&destination, &tx, INVALID_SIGNATURE_INDEX),
            Err(TransactionSigError::InvalidSignatureIndex(
                INVALID_SIGNATURE_INDEX,
                3
            )),
            "{sighash_type:?}"
        );
    }
}

#[test]
fn verify_signature_wrong_destination() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint = Destination::PublicKey(public_key);

    let (_, public_key_2) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let different_outpoint = Destination::PublicKey(public_key_2);

    for sighash_type in sig_hash_types() {
        let tx = generate_and_sign_tx(&outpoint, 3, 3, &private_key, sighash_type).unwrap();
        assert_eq!(
            verify_signature(&different_outpoint, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed),
            "{sighash_type:?}"
        );
    }
}

// ALL applies to all inputs and outputs, so changing or adding anything makes it invalid.
#[test]
fn mutate_all() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
    let original_tx = sign_mutate_then_verify(&private_key, sighash_type, &outpoint_dest);

    check_insert_input(&original_tx, &outpoint_dest, true);
    check_mutate_input(&original_tx, &outpoint_dest, true);
    check_insert_output(&original_tx, &outpoint_dest, true);
    check_mutate_output(&original_tx, &outpoint_dest, true);
}

// ALL|ANYONECANPAY applies to one input and all outputs, so adding input is ok, but anything else isn't.
#[test]
fn mutate_all_anyonecanpay() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
    let original_tx = sign_mutate_then_verify(&private_key, sighash_type, &outpoint_dest);

    check_insert_input(&original_tx, &outpoint_dest, false);
    check_mutate_input(&original_tx, &outpoint_dest, true);
    check_insert_output(&original_tx, &outpoint_dest, true);
    check_mutate_output(&original_tx, &outpoint_dest, true);
}

// NONE is applied to all inputs and none of the outputs, so the latter can be changed in any way.
#[test]
fn mutate_none() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
    let original_tx = sign_mutate_then_verify(&private_key, sighash_type, &outpoint_dest);

    check_insert_input(&original_tx, &outpoint_dest, true);
    check_mutate_input(&original_tx, &outpoint_dest, true);
    check_insert_output(&original_tx, &outpoint_dest, false);
    check_mutate_output(&original_tx, &outpoint_dest, false);
}

// NONE|ANYONECANPAY is applied to only one input, so changing everything else is OK.
#[test]
fn mutate_none_anyonecanpay() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let sighash_type =
        SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
    let original_tx = sign_mutate_then_verify(&private_key, sighash_type, &outpoint_dest);

    check_insert_input(&original_tx, &outpoint_dest, false);
    check_mutate_input(&original_tx, &outpoint_dest, true);
    check_insert_output(&original_tx, &outpoint_dest, false);
    check_mutate_output(&original_tx, &outpoint_dest, false);
}

// SINGLE is applied to all inputs and one output, so only adding an output is OK.
#[test]
fn mutate_single() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
    let original_tx = sign_mutate_then_verify(&private_key, sighash_type, &outpoint_dest);

    check_insert_input(&original_tx, &outpoint_dest, true);
    check_mutate_input(&original_tx, &outpoint_dest, true);
    check_insert_output(&original_tx, &outpoint_dest, false);
    check_mutate_output(&original_tx, &outpoint_dest, true);
}

// SINGLE|ANYONECANPAY is applied to one input and one output so adding inputs and outputs is OK.
#[test]
fn mutate_single_anyonecanpay() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let sighash_type =
        SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
    let original_tx = sign_mutate_then_verify(&private_key, sighash_type, &outpoint_dest);

    check_insert_input(&original_tx, &outpoint_dest, false);
    check_mutate_input(&original_tx, &outpoint_dest, true);
    check_insert_output(&original_tx, &outpoint_dest, false);
    check_mutate_output(&original_tx, &outpoint_dest, true);
}

fn sign_mutate_then_verify(
    private_key: &PrivateKey,
    sighash_type: SigHashType,
    destination: &Destination,
) -> SignedTransaction {
    // Create and sign tx, and then modify and verify it.
    let original_tx = generate_and_sign_tx(destination, 3, 3, private_key, sighash_type).unwrap();
    assert_eq!(verify_signed_tx(&original_tx, destination), Ok(()));

    check_change_flags(&original_tx, destination);
    check_change_locktime(&original_tx, destination);
    check_mutate_witness(&original_tx, destination);
    original_tx
}

fn check_change_flags(original_tx: &SignedTransaction, destination: &Destination) {
    let mut tx_updater = MutableTransaction::from(original_tx);
    tx_updater.flags = tx_updater.flags.wrapping_add(1234567890);
    let tx = tx_updater.generate_tx().unwrap();
    for (input_num, _) in tx.inputs().iter().enumerate() {
        assert_eq!(
            verify_signature(destination, &tx, input_num),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }
}

fn check_change_locktime(original_tx: &SignedTransaction, outpoint_dest: &Destination) {
    let mut tx_updater = MutableTransaction::from(original_tx);
    tx_updater.lock_time = tx_updater.lock_time.wrapping_add(1234567890);
    let tx = tx_updater.generate_tx().unwrap();
    for (input_num, _) in tx.inputs().iter().enumerate() {
        assert_eq!(
            verify_signature(outpoint_dest, &tx, input_num),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }
}

fn check_insert_input(
    original_tx: &SignedTransaction,
    destination: &Destination,
    should_fail: bool,
) {
    let mut tx_updater = MutableTransaction::from(original_tx);
    let outpoint_source_id = OutPointSourceId::Transaction(Id::<Transaction>::new(H256::random()));
    tx_updater.inputs.push(TxInput::new(outpoint_source_id, 1));
    tx_updater.witness.push(InputWitness::NoSignature(Some(vec![1, 2, 3])));
    let tx = tx_updater.generate_tx().unwrap();
    let res = verify_signature(destination, &tx, 0);
    if should_fail {
        assert_eq!(res, Err(TransactionSigError::SignatureVerificationFailed));
    } else {
        res.unwrap();
    }
}

// A witness mutation should result in signature verification error.
fn check_mutate_witness(original_tx: &SignedTransaction, outpoint_dest: &Destination) {
    let mut tx_updater = MutableTransaction::from(original_tx);
    for input in 0..original_tx.inputs().len() {
        let signature = match &tx_updater.witness[0] {
            InputWitness::Standard(signature) => signature,
            InputWitness::NoSignature(_) => panic!("Unexpected InputWitness::NoSignature"),
        };

        let raw_signature = signature.raw_signature().iter().map(|b| b.wrapping_add(1)).collect();
        let signature = StandardInputSignature::new(signature.sighash_type(), raw_signature);
        tx_updater.witness[input] = InputWitness::Standard(signature);
        let tx = tx_updater.generate_tx().unwrap();

        assert!(matches!(
            verify_signature(outpoint_dest, &tx, input),
            Err(TransactionSigError::SignatureVerificationFailed
                | TransactionSigError::InvalidSignatureEncoding)
        ));
    }
}

fn check_insert_output(
    original_tx: &SignedTransaction,
    destination: &Destination,
    should_fail: bool,
) {
    let mut tx_updater = MutableTransaction::from(original_tx);
    let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    tx_updater.outputs.push(TxOutput::new(
        OutputValue::Coin(Amount::from_atoms(1234567890)),
        OutputPurpose::Transfer(Destination::PublicKey(pub_key)),
    ));
    let tx = tx_updater.generate_tx().unwrap();
    let res = verify_signature(destination, &tx, 0);
    if should_fail {
        assert_eq!(res, Err(TransactionSigError::SignatureVerificationFailed));
    } else {
        res.unwrap();
    }
}

fn check_mutate_output(
    original_tx: &SignedTransaction,
    destination: &Destination,
    should_fail: bool,
) {
    // Should failed due to change in output value
    let mut tx_updater = MutableTransaction::from(original_tx);
    tx_updater.outputs[0] = TxOutput::new(
        match tx_updater.outputs[0].value() {
            OutputValue::Coin(coin) => {
                OutputValue::Coin((*coin + Amount::from_atoms(100)).unwrap())
            }
            OutputValue::Token(asset) => OutputValue::Token(asset.clone()),
        },
        tx_updater.outputs[0].purpose().clone(),
    );
    let tx = tx_updater.generate_tx().unwrap();
    let res = verify_signature(destination, &tx, 0);
    if should_fail {
        assert_eq!(res, Err(TransactionSigError::SignatureVerificationFailed));
    } else {
        res.unwrap();
    }
}

fn check_mutate_input(
    original_tx: &SignedTransaction,
    destination: &Destination,
    should_fail: bool,
) {
    // Should failed due to change in output value
    let mut tx_updater = MutableTransaction::from(original_tx);
    tx_updater.inputs[0] = TxInput::new(
        OutPointSourceId::Transaction(Id::<Transaction>::from(H256::random())),
        9999,
    );
    let tx = tx_updater.generate_tx().unwrap();
    let res = verify_signature(destination, &tx, 0);
    if should_fail {
        assert_eq!(res, Err(TransactionSigError::SignatureVerificationFailed));
    } else {
        res.unwrap();
    }
}
