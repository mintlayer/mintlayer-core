use crypto::key::{KeyKind, PrivateKey};

use super::utils::*;
use crate::{
    chain::{
        signature::{
            sighashtype::{OutputsMode, SigHashType},
            tests::{
                check_change_input, check_change_output, check_insert_input, check_insert_output,
                sign_modify_then_verify,
            },
            verify_signature, TransactionSigError,
        },
        Destination, OutPointSourceId, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, Id, H256},
};

use itertools::Itertools;

#[test]
fn test_mutate_tx_internal_data() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);

    let test_data = [
        (0, 31, Ok(())),
        (31, 0, Err(TransactionSigError::SignatureVerificationFailed)),
        (
            31,
            31,
            Err(TransactionSigError::SignatureVerificationFailed),
        ),
    ];

    for ((destination, sighash_type), (inputs, outputs, expected)) in destinations(public_key)
        .cartesian_product(sig_hash_types())
        .cartesian_product(test_data)
    {
        let mut tx = generate_unsigned_tx(destination.clone(), inputs, outputs).unwrap();
        match sign_whole_tx(&mut tx, &private_key, sighash_type, destination.clone()) {
            Ok(()) => {
                // Test flags change.
                let updated_tx = change_flags(&tx, 1234567890);
                assert_eq!(verify_signed_tx(&updated_tx, &destination), expected);
                // Test locktime change.
                let updated_tx = change_locktime(&tx, 1234567890);
                assert_eq!(verify_signed_tx(&updated_tx, &destination), expected)
            }
            Err(err) => {
                match err {
                    // Not implemented.
                    TransactionSigError::Unsupported => {
                        assert!(matches!(destination, Destination::ScriptHash(_)))
                    }
                    TransactionSigError::AttemptedToProduceSignatureForAnyoneCanSpend => {
                        assert_eq!(destination, Destination::AnyoneCanSpend)
                    }
                    TransactionSigError::InvalidInputIndex(0, 0) => {
                        assert_eq!(sighash_type.outputs_mode(), OutputsMode::Single)
                    }
                    e => assert_eq!(Err(e), expected),
                }
            }
        }
    }
}

// Add a new input into a signed transaction.
#[test]
fn sign_mutate_add_inputs() {
    const INPUTS: usize = 15;
    const OUTPUTS: usize = 15;
    const INVALID_INPUT: usize = 1235466;

    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);

    // ALL.
    {
        let original_tx = create_tx(
            INPUTS,
            OUTPUTS,
            SigHashType::try_from(SigHashType::ALL).unwrap(),
            &outpoint_dest,
            &private_key,
        );
        let mut tx_updater = MutableTransaction::from(&original_tx);
        tx_updater.inputs.push(tx_updater.inputs[0].clone());
        let tx = tx_updater.generate_tx().unwrap();

        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INVALID_INPUT),
            Err(TransactionSigError::InvalidInputIndex(
                INVALID_INPUT,
                INPUTS + 1
            ))
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INPUTS),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 10),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }

    // ALL | ANYONECANPAY is applied to one input only, so signature verification should pass for
    // any input except the invalid one.
    {
        let original_tx = create_tx(
            INPUTS,
            OUTPUTS,
            SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap(),
            &outpoint_dest,
            &private_key,
        );
        let mut tx_updater = MutableTransaction::from(&original_tx);
        tx_updater.inputs.push(tx_updater.inputs[0].clone());
        let tx = tx_updater.generate_tx().unwrap();

        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INVALID_INPUT),
            Err(TransactionSigError::InvalidInputIndex(
                INVALID_INPUT,
                INPUTS + 1
            ))
        );
        assert_eq!(verify_signature(&outpoint_dest, &tx, INPUTS), Ok(()));
        assert_eq!(verify_signature(&outpoint_dest, &tx, 0), Ok(()));
        assert_eq!(verify_signature(&outpoint_dest, &tx, 10), Ok(()));
    }

    // SINGLE.
    {
        let original_tx = create_tx(
            INPUTS,
            OUTPUTS,
            SigHashType::try_from(SigHashType::SINGLE).unwrap(),
            &outpoint_dest,
            &private_key,
        );
        let mut tx_updater = MutableTransaction::from(&original_tx);
        tx_updater.inputs.push(tx_updater.inputs[0].clone());
        let tx = tx_updater.generate_tx().unwrap();

        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INVALID_INPUT),
            Err(TransactionSigError::InvalidInputIndex(
                INVALID_INPUT,
                INPUTS + 1
            ))
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INPUTS),
            Err(TransactionSigError::InvalidInputIndex(INPUTS, INPUTS))
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 10),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }

    // SINGLE | ANYONECANPAY.
    {
        let original_tx = create_tx(
            INPUTS,
            OUTPUTS,
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap(),
            &outpoint_dest,
            &private_key,
        );
        let mut tx_updater = MutableTransaction::from(&original_tx);
        tx_updater.inputs.push(tx_updater.inputs[0].clone());
        let tx = tx_updater.generate_tx().unwrap();

        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INVALID_INPUT),
            Err(TransactionSigError::InvalidInputIndex(
                INVALID_INPUT,
                INPUTS + 1
            ))
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INPUTS),
            Err(TransactionSigError::InvalidInputIndex(INPUTS, INPUTS))
        );
        assert_eq!(verify_signature(&outpoint_dest, &tx, 0), Ok(()));
        assert_eq!(verify_signature(&outpoint_dest, &tx, 10), Ok(()));
    }

    // NONE.
    {
        let original_tx = create_tx(
            INPUTS,
            OUTPUTS,
            SigHashType::try_from(SigHashType::NONE).unwrap(),
            &outpoint_dest,
            &private_key,
        );
        let mut tx_updater = MutableTransaction::from(&original_tx);
        tx_updater.inputs.push(tx_updater.inputs[0].clone());
        let tx = tx_updater.generate_tx().unwrap();

        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INVALID_INPUT),
            Err(TransactionSigError::InvalidInputIndex(
                INVALID_INPUT,
                INPUTS + 1
            ))
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INPUTS),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 10),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }

    // NONE | ANYONECANPAY.
    {
        let original_tx = create_tx(
            INPUTS,
            OUTPUTS,
            SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap(),
            &outpoint_dest,
            &private_key,
        );
        let mut tx_updater = MutableTransaction::from(&original_tx);
        tx_updater.inputs.push(tx_updater.inputs[0].clone());
        let tx = tx_updater.generate_tx().unwrap();

        assert_eq!(
            verify_signature(&outpoint_dest, &tx, INVALID_INPUT),
            Err(TransactionSigError::InvalidInputIndex(
                INVALID_INPUT,
                INPUTS + 1
            ))
        );
        assert_eq!(verify_signature(&outpoint_dest, &tx, INPUTS), Ok(()));
        assert_eq!(verify_signature(&outpoint_dest, &tx, 0), Ok(()));
        assert_eq!(verify_signature(&outpoint_dest, &tx, 10), Ok(()));
    }
}

// TODO: FIXME:
#[test]
fn sign_mutate_then_verify_all() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);

    {
        // SigHashType::ALL - Can we add output?
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let mut original_tx = generate_unsigned_tx(outpoint_dest.clone(), 15, 15).unwrap();
        sign_whole_tx(
            &mut original_tx,
            &private_key,
            sighash_type,
            outpoint_dest.clone(),
        )
        .unwrap();
        assert_eq!(verify_signed_tx(&original_tx, &outpoint_dest), Ok(()));
        // Add the new input and then verify
        let mut tx_updater = MutableTransaction::from(&original_tx);
        tx_updater.outputs.push(tx_updater.outputs[0].clone());
        let tx = tx_updater.generate_tx().unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 1235466),
            Err(TransactionSigError::InvalidInputIndex(1235466, 15))
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 14),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 7),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }
    {
        // SigHashType::ALL - Can we remove input?
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let mut original_tx = generate_unsigned_tx(outpoint_dest.clone(), 15, 15).unwrap();
        sign_whole_tx(
            &mut original_tx,
            &private_key,
            sighash_type,
            outpoint_dest.clone(),
        )
        .unwrap();
        assert_eq!(verify_signed_tx(&original_tx, &outpoint_dest), Ok(()));
        // Add the new input and then verify

        {
            // Remove the first input
            let mut tx_updater = MutableTransaction::from(&original_tx);
            tx_updater.inputs.remove(0);
            let tx = tx_updater.generate_tx().unwrap();
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 1235466),
                Err(TransactionSigError::InvalidInputIndex(1235466, 14))
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 13),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 0),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 5),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
        }
        {
            // Remove the input in the middle
            let mut tx_updater = MutableTransaction::from(&original_tx);
            tx_updater.inputs.remove(7);
            let tx = tx_updater.generate_tx().unwrap();
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 1235466),
                Err(TransactionSigError::InvalidInputIndex(1235466, 14))
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 13),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 0),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 5),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
        }
        {
            // Remove the last input
            let mut tx_updater = MutableTransaction::from(&original_tx);
            tx_updater.inputs.remove(13);
            let tx = tx_updater.generate_tx().unwrap();
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 1235466),
                Err(TransactionSigError::InvalidInputIndex(1235466, 14))
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 13),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 0),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 5),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
        }
    }
    {
        // SigHashType::ALL - Can we remove output?
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let mut original_tx = generate_unsigned_tx(outpoint_dest.clone(), 15, 15).unwrap();
        sign_whole_tx(
            &mut original_tx,
            &private_key,
            sighash_type,
            outpoint_dest.clone(),
        )
        .unwrap();
        assert_eq!(verify_signed_tx(&original_tx, &outpoint_dest), Ok(()));
        // Add the new input and then verify
        {
            // Remove the first output
            let mut tx_updater = MutableTransaction::from(&original_tx);
            tx_updater.outputs.remove(0);
            let tx = tx_updater.generate_tx().unwrap();
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 1235466),
                Err(TransactionSigError::InvalidInputIndex(1235466, 15))
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 13),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 0),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 5),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
        }
        {
            // Remove output in the middle
            let mut tx_updater = MutableTransaction::from(&original_tx);
            tx_updater.outputs.remove(7);
            let tx = tx_updater.generate_tx().unwrap();
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 1235466),
                Err(TransactionSigError::InvalidInputIndex(1235466, 15))
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 13),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 0),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 5),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
        }
        {
            // Remove the last output
            let mut tx_updater = MutableTransaction::from(&original_tx);
            tx_updater.outputs.remove(13);
            let tx = tx_updater.generate_tx().unwrap();
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 1235466),
                Err(TransactionSigError::InvalidInputIndex(1235466, 15))
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 13),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 0),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 5),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
        }
    }
    {
        // SigHashType::ALL - Can we update input?
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let mut original_tx = generate_unsigned_tx(outpoint_dest.clone(), 15, 15).unwrap();
        sign_whole_tx(
            &mut original_tx,
            &private_key,
            sighash_type,
            outpoint_dest.clone(),
        )
        .unwrap();
        assert_eq!(verify_signed_tx(&original_tx, &outpoint_dest), Ok(()));
        // Add the new input and then verify
        let mut tx_updater = MutableTransaction::from(&original_tx);
        tx_updater.inputs[0] = TxInput::new(
            OutPointSourceId::Transaction(Id::<Transaction>::from(H256::random())),
            9999,
            tx_updater.inputs[0].get_witness().clone(),
        );
        let tx = tx_updater.generate_tx().unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 1235466),
            Err(TransactionSigError::InvalidInputIndex(1235466, 15))
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 13),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 5),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }
    {
        // SigHashType::ALL - Can we update output?
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let mut original_tx = generate_unsigned_tx(outpoint_dest.clone(), 15, 15).unwrap();
        sign_whole_tx(
            &mut original_tx,
            &private_key,
            sighash_type,
            outpoint_dest.clone(),
        )
        .unwrap();
        assert_eq!(verify_signed_tx(&original_tx, &outpoint_dest), Ok(()));
        // Add the new input and then verify
        let mut tx_updater = MutableTransaction::from(&original_tx);
        tx_updater.outputs[0] = TxOutput::new(
            (tx_updater.outputs[0].get_value() + Amount::from_atoms(100)).unwrap(),
            tx_updater.outputs[0].get_destination().clone(),
        );
        let tx = tx_updater.generate_tx().unwrap();
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 1235466),
            Err(TransactionSigError::InvalidInputIndex(1235466, 15))
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 13),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
        assert_eq!(
            verify_signature(&outpoint_dest, &tx, 5),
            Err(TransactionSigError::SignatureVerificationFailed)
        );
    }
    { // SigHashType::ALL - Can we sign each input with different sighash_type?
    }
    {
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        // ALL - It signs every input and output, and any change to the transaction will render the signature invalid.
        let original_tx = sign_modify_then_verify(&private_key, sighash_type, &outpoint_dest);
        check_insert_input(&original_tx, &outpoint_dest, true);
        check_insert_output(&original_tx, &outpoint_dest, true);
        check_change_output(&original_tx, &outpoint_dest, true);
        check_change_input(&original_tx, &outpoint_dest, true);
    }
    {
        // ALL | ANYONECANPAY
        let sighash_type =
            SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
        let original_tx = sign_modify_then_verify(&private_key, sighash_type, &outpoint_dest);
        check_insert_output(&original_tx, &outpoint_dest, true);
        check_change_output(&original_tx, &outpoint_dest, true);
        check_change_input(&original_tx, &outpoint_dest, true);
    }
}

fn change_flags(original_tx: &Transaction, new_flags: u32) -> Transaction {
    let mut tx_updater = MutableTransaction::from(original_tx);
    tx_updater.flags = new_flags;
    tx_updater.generate_tx().unwrap()
}

fn change_locktime(original_tx: &Transaction, new_lock_time: u32) -> Transaction {
    let mut tx_updater = MutableTransaction::from(original_tx);
    tx_updater.lock_time = new_lock_time;
    tx_updater.generate_tx().unwrap()
}

fn create_tx(
    input_count: usize,
    output_count: usize,
    sighash_type: SigHashType,
    outpoint_dest: &Destination,
    private_key: &PrivateKey,
) -> Transaction {
    let mut original_tx =
        generate_unsigned_tx(outpoint_dest.clone(), input_count, output_count).unwrap();
    sign_whole_tx(
        &mut original_tx,
        private_key,
        sighash_type,
        outpoint_dest.clone(),
    )
    .unwrap();
    assert_eq!(verify_signed_tx(&original_tx, outpoint_dest), Ok(()));
    original_tx
}
