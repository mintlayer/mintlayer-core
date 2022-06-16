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
use crypto::key::{KeyKind, PrivateKey};
use std::vec;
use utils::*;

type TestData = Vec<(
    Destination,
    SigHashType,
    u32,
    u32,
    Result<(), TransactionSigError>,
)>;

#[cfg(test)]
mod sign_and_mutate;
#[cfg(test)]
mod sign_and_verify;
pub mod utils;

#[test]
fn sign_and_verify_different_sighash_types() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    {
        // ALL
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3, 3).unwrap();
        sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
        assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
    }
    {
        let sighash_type =
            SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
        let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3, 3).unwrap();
        sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
        assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
    }
    {
        // NONE
        let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
        let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3, 3).unwrap();
        sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
        assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
    }
    {
        let sighash_type =
            SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
        let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3, 3).unwrap();
        sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
        assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
    }
    {
        // SINGLE
        let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
        let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3, 3).unwrap();
        sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
        assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
    }
    {
        let sighash_type =
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
        let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3, 3).unwrap();
        sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
        assert_eq!(verify_signed_tx(&tx, &outpoint_dest), Ok(()));
    }
}

#[test]
fn check_verify_fails_different_sighash_types() {
    let (_, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3, 3).unwrap();
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
fn check_invalid_input_index_for_verify_signature() {
    const INVALID_INPUT_INDEX: usize = 1234567890;
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    {
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3, 3).unwrap();
        sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
        // input index out of range
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INVALID_INPUT_INDEX),
            Err(TransactionSigError::InvalidInputIndex(
                INVALID_INPUT_INDEX,
                3
            ))
        );
    }
    {
        // ALL | ANYONECANPAY
        let sighash_type =
            SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
        let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3, 3).unwrap();
        sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INVALID_INPUT_INDEX),
            Err(TransactionSigError::InvalidInputIndex(
                INVALID_INPUT_INDEX,
                3
            ))
        );
    }
    {
        // SINGLE
        let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
        let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3, 3).unwrap();
        sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INVALID_INPUT_INDEX),
            Err(TransactionSigError::InvalidInputIndex(
                INVALID_INPUT_INDEX,
                3
            ))
        );
    }
    {
        // SINGLE | ANYONECANPAY
        let sighash_type =
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
        let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3, 3).unwrap();
        sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INVALID_INPUT_INDEX),
            Err(TransactionSigError::InvalidInputIndex(
                INVALID_INPUT_INDEX,
                3
            ))
        );
    }
    {
        // NONE
        let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
        let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3, 3).unwrap();
        sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INVALID_INPUT_INDEX),
            Err(TransactionSigError::InvalidInputIndex(
                INVALID_INPUT_INDEX,
                3
            ))
        );
    }
    {
        // NONE | ANYONECANPAY
        let sighash_type =
            SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
        let mut tx = generate_unsigned_tx(outpoint_dest.clone(), 3, 3).unwrap();
        sign_whole_tx(&mut tx, &private_key, sighash_type, outpoint_dest.clone()).unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INVALID_INPUT_INDEX),
            Err(TransactionSigError::InvalidInputIndex(
                INVALID_INPUT_INDEX,
                3
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
    let mut tx_updater = MutableTransaction::try_from(original_tx).unwrap();
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
    let mut tx_updater = MutableTransaction::try_from(original_tx).unwrap();
    tx_updater.lock_time = 1234567890;
    let tx = tx_updater.generate_tx().unwrap();
    for (input_num, _) in tx.get_inputs().iter().enumerate() {
        assert_eq!(
            verify_signature(outpoint_dest, &tx, input_num),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }
}

fn check_insert_input(original_tx: &Transaction, outpoint_dest: &Destination) {
    let mut tx_updater = MutableTransaction::try_from(original_tx).unwrap();
    let outpoinr_source_id = OutPointSourceId::Transaction(Id::<Transaction>::new(&H256::random()));
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
fn test_sign_mutate_then_verify() {
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
