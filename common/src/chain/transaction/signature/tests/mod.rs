use std::vec;

use itertools::Itertools;

use crypto::key::{KeyKind, PrivateKey};

use super::{
    inputsig::{InputWitness, StandardInputSignature},
    sighashtype::SigHashType,
};
use crate::{
    chain::{
        signature::{verify_signature, TransactionSigError},
        Destination, OutPointSourceId, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, Id, H256},
};
use utils::*;

mod mixed_sighash_types;
mod sign_and_mutate;
mod sign_and_verify;

pub mod utils;

#[test]
fn sign_and_verify_different_sighash_types() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);

    for sighash_type in sig_hash_types() {
        let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3, 3).unwrap();
        sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
        assert_eq!(
            verify_signed_tx(&tx, &outpoint_dest),
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
        let mut tx = generate_unsigned_tx(destination.clone(), 3, 3).unwrap();
        tx.update_witness(
            0,
            InputWitness::NoSignature(Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9])),
        )
        .unwrap();
        assert_eq!(
            verify_signature(&destination, &tx, 0),
            Err(TransactionSigError::SignatureNotFound),
            "{destination:?}"
        );
    }
}

// Try to verify empty and invalid signatures.
#[test]
fn verify_invalid_signature() {
    let (_, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);

    for (sighash_type, raw_signature) in
        sig_hash_types().cartesian_product([vec![], vec![1, 2, 3, 4, 5, 6, 7, 8, 9]])
    {
        let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3, 3).unwrap();
        tx.update_witness(
            0,
            InputWitness::Standard(StandardInputSignature::new(
                sighash_type,
                raw_signature.clone(),
            )),
        )
        .unwrap();

        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::InvalidSignatureEncoding),
            "{sighash_type:?}, signature = {raw_signature:?}"
        );
    }
}

#[test]
fn verify_signature_invalid_input_index() {
    const INVALID_INPUT_INDEX: usize = 1234567890;

    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);

    for sighash_type in sig_hash_types() {
        let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3, 3).unwrap();
        sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();

        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INVALID_INPUT_INDEX),
            Err(TransactionSigError::InvalidInputIndex(
                INVALID_INPUT_INDEX,
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
        let mut tx = generate_unsigned_tx(outpoint.clone(), 3, 3).unwrap();
        sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint.clone()).unwrap();

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
    let original_tx = sign_modify_then_verify(&private_key, sighash_type, &outpoint_dest);

    check_insert_input(&original_tx, &outpoint_dest, true);
    check_change_input(&original_tx, &outpoint_dest, true);
    check_insert_output(&original_tx, &outpoint_dest, true);
    check_change_output(&original_tx, &outpoint_dest, true);
}

// ALL|ANYONECANPAY applies to one input and all outputs, so adding input is ok, but anything else isn't.
#[test]
fn mutate_all_anyonecanpay() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
    let original_tx = sign_modify_then_verify(&private_key, sighash_type, &outpoint_dest);

    check_insert_input(&original_tx, &outpoint_dest, false);
    check_change_input(&original_tx, &outpoint_dest, true);
    check_insert_output(&original_tx, &outpoint_dest, true);
    check_change_output(&original_tx, &outpoint_dest, true);
}

// NONE is applied to all inputs and none of the outputs, so the latter can be changed in any way.
#[test]
fn mutate_none() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
    let original_tx = sign_modify_then_verify(&private_key, sighash_type, &outpoint_dest);

    check_insert_input(&original_tx, &outpoint_dest, true);
    check_change_input(&original_tx, &outpoint_dest, true);
    check_insert_output(&original_tx, &outpoint_dest, false);
    check_change_output(&original_tx, &outpoint_dest, false);
}

// NONE|ANYONECANPAY is applied to only one input, so changing everything else is OK.
#[test]
fn mutate_none_anyonecanpay() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let sighash_type =
        SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
    let original_tx = sign_modify_then_verify(&private_key, sighash_type, &outpoint_dest);

    check_insert_input(&original_tx, &outpoint_dest, false);
    check_change_input(&original_tx, &outpoint_dest, true);
    check_insert_output(&original_tx, &outpoint_dest, false);
    check_change_output(&original_tx, &outpoint_dest, false);
}

// SINGLE is applied to all inputs and one output, so only adding an output is OK.
#[test]
fn mutate_single() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
    let original_tx = sign_modify_then_verify(&private_key, sighash_type, &outpoint_dest);

    check_insert_input(&original_tx, &outpoint_dest, true);
    check_change_input(&original_tx, &outpoint_dest, true);
    check_insert_output(&original_tx, &outpoint_dest, false);
    check_change_output(&original_tx, &outpoint_dest, true);
}

// SINGLE|ANYONECANPAY is applied to one input and one output so adding inputs and outputs is OK.
#[test]
fn mutate_single_anyonecanpay() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let sighash_type =
        SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
    let original_tx = sign_modify_then_verify(&private_key, sighash_type, &outpoint_dest);

    check_insert_input(&original_tx, &outpoint_dest, false);
    check_change_input(&original_tx, &outpoint_dest, true);
    check_insert_output(&original_tx, &outpoint_dest, false);
    check_change_output(&original_tx, &outpoint_dest, true);
}

fn sign_modify_then_verify(
    private_key: &PrivateKey,
    sighash_type: SigHashType,
    outpoint_dest: &Destination,
) -> Transaction {
    // Create and sign tx, and then modify and verify it.
    let mut original_tx = generate_unsigned_tx(outpoint_dest.clone(), 3, 3).unwrap();
    sign_whole_tx(
        &mut original_tx,
        private_key,
        sighash_type,
        outpoint_dest.clone(),
    )
    .unwrap();
    assert_eq!(verify_signed_tx(&original_tx, outpoint_dest), Ok(()));

    check_change_flags(&original_tx, outpoint_dest);
    check_change_locktime(&original_tx, outpoint_dest);
    check_change_witness(&original_tx, outpoint_dest);
    original_tx
}

fn check_change_flags(original_tx: &Transaction, outpoint_dest: &Destination) {
    let mut tx_updater = MutableTransaction::from(original_tx);
    tx_updater.flags = 1234567890;
    let tx = tx_updater.generate_tx().unwrap();
    for (input_num, _) in tx.get_inputs().iter().enumerate() {
        assert_eq!(
            verify_signature(outpoint_dest, &tx, input_num),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }
}

fn check_change_locktime(original_tx: &Transaction, outpoint_dest: &Destination) {
    let mut tx_updater = MutableTransaction::from(original_tx);
    tx_updater.lock_time = 1234567890;
    let tx = tx_updater.generate_tx().unwrap();
    for (input_num, _) in tx.get_inputs().iter().enumerate() {
        assert_eq!(
            verify_signature(outpoint_dest, &tx, input_num),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }
}

fn check_insert_input(original_tx: &Transaction, outpoint_dest: &Destination, should_fail: bool) {
    let mut tx_updater = MutableTransaction::from(original_tx);
    let outpoinr_source_id = OutPointSourceId::Transaction(Id::<Transaction>::new(&H256::random()));
    tx_updater.inputs.push(TxInput::new(
        outpoinr_source_id,
        1,
        InputWitness::NoSignature(None),
    ));
    let tx = tx_updater.generate_tx().unwrap();
    assert_verify_signature(outpoint_dest, &tx, should_fail);
}

fn check_change_witness(original_tx: &Transaction, outpoint_dest: &Destination) {
    // Should failed due to change in witness
    let mut tx_updater = MutableTransaction::from(original_tx);
    for (input_num, _) in original_tx.get_inputs().iter().enumerate() {
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
        tx_updater.inputs[input_num].update_witness(InputWitness::Standard(signature));
        let tx = tx_updater.generate_tx().unwrap();
        assert_eq!(
            verify_signature(outpoint_dest, &tx, input_num),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }
}

fn check_insert_output(original_tx: &Transaction, outpoint_dest: &Destination, should_fail: bool) {
    let mut tx_updater = MutableTransaction::from(original_tx);
    let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    tx_updater.outputs.push(TxOutput::new(
        Amount::from_atoms(1234567890),
        Destination::PublicKey(pub_key),
    ));
    let tx = tx_updater.generate_tx().unwrap();
    assert_verify_signature(outpoint_dest, &tx, should_fail);
}

fn check_change_output(original_tx: &Transaction, outpoint_dest: &Destination, should_fail: bool) {
    // Should failed due to change in output value
    let mut tx_updater = MutableTransaction::from(original_tx);
    tx_updater.outputs[0] = TxOutput::new(
        (tx_updater.outputs[0].get_value() + Amount::from_atoms(100)).unwrap(),
        tx_updater.outputs[0].get_destination().clone(),
    );
    let tx = tx_updater.generate_tx().unwrap();
    assert_verify_signature(outpoint_dest, &tx, should_fail);
}

fn check_change_input(original_tx: &Transaction, outpoint_dest: &Destination, should_fail: bool) {
    // Should failed due to change in output value
    let mut tx_updater = MutableTransaction::from(original_tx);
    tx_updater.inputs[0] = TxInput::new(
        OutPointSourceId::Transaction(Id::<Transaction>::from(H256::random())),
        9999,
        tx_updater.inputs[0].get_witness().clone(),
    );
    let tx = tx_updater.generate_tx().unwrap();
    assert_verify_signature(outpoint_dest, &tx, should_fail);
}

fn assert_verify_signature(outpoint: &Destination, tx: &Transaction, should_fail: bool) {
    let res = verify_signature(outpoint, tx, 0);
    if should_fail {
        assert_eq!(res, Err(TransactionSigError::SignatureVerificationFailed));
    } else {
        res.unwrap();
    }
}
