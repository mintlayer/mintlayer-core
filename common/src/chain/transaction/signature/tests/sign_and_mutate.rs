use super::super::sighashtype::SigHashType;
use super::utils::*;
use crate::chain::signature::sighashtype::OutputsMode;
use crate::chain::signature::tests::check_change_input;
use crate::chain::signature::tests::check_change_output;
use crate::chain::signature::tests::check_insert_input;
use crate::chain::signature::tests::check_insert_output;
use crate::chain::signature::tests::sign_modify_then_verify;
use crate::chain::signature::verify_signature;
use crate::chain::OutPointSourceId;
use crate::chain::Transaction;
use crate::chain::TxInput;
use crate::chain::TxOutput;
use crate::primitives::Amount;
use crate::{
    address::pubkeyhash::PublicKeyHash,
    chain::{signature::TransactionSigError, Destination},
    primitives::{Id, H256},
};
use crypto::key::{KeyKind, PrivateKey};
use script::Script;

fn change_flags(original_tx: &Transaction, new_flags: u32) -> Transaction {
    let mut tx_updater = MutableTransaction::try_from(original_tx).unwrap();
    tx_updater.flags = new_flags;
    tx_updater.generate_tx().unwrap()
}

fn change_locktime(original_tx: &Transaction, new_lock_time: u32) -> Transaction {
    let mut tx_updater = MutableTransaction::try_from(original_tx).unwrap();
    tx_updater.lock_time = new_lock_time;
    tx_updater.generate_tx().unwrap()
}

#[test]
fn test_mutate_tx_internal_data() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);

    let destinations = vec![
        Destination::PublicKey(public_key.clone()),
        Destination::Address(PublicKeyHash::from(&public_key)),
        Destination::AnyoneCanSpend,
        Destination::ScriptHash(Id::<Script>::from(H256::random())),
    ];
    let sighash_types = vec![
        SigHashType::try_from(SigHashType::ALL).unwrap(),
        SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap(),
        SigHashType::try_from(SigHashType::NONE).unwrap(),
        SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap(),
        SigHashType::try_from(SigHashType::SINGLE).unwrap(),
        SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap(),
    ];

    let test_data = vec![
        (0u32, 31u32, Ok(())),
        (
            31u32,
            0u32,
            Err(TransactionSigError::SignatureVerificationFailed),
        ),
        (
            31u32,
            31u32,
            Err(TransactionSigError::SignatureVerificationFailed),
        ),
    ];

    // Multiply variants in nested loops - destinations * sighash_types * test_data
    for outpoint_dest in destinations {
        for sighash_type in &sighash_types {
            test_data.iter().for_each(|(inputs_count, outputs_count, expected_result)| {
                let mut tx =
                    generate_unsigned_tx(outpoint_dest.clone(), *inputs_count, *outputs_count)
                        .unwrap();
                match sign_whole_tx(&mut tx, &private_key, *sighash_type, outpoint_dest.clone()) {
                    Ok(_) => {
                        // Test flags change
                        let updated_tx = change_flags(&tx, 1234567890);
                        assert_eq!(
                            verify_signed_tx(&updated_tx, &outpoint_dest),
                            *expected_result
                        );
                        // Test locktime change
                        let updated_tx = change_locktime(&tx, 1234567890);
                        assert_eq!(
                            verify_signed_tx(&updated_tx, &outpoint_dest),
                            *expected_result
                        )
                    }
                    Err(err) => {
                        let mut skip = false;
                        if matches!(
                            err,
                            TransactionSigError::AttemptedToProduceSignatureForAnyoneCanSpend
                                | TransactionSigError::Unsupported
                        ) {
                            // TODO: Add tests for AnyoneCanSpend and ScriptHash
                            skip = true;
                        }
                        if matches!(sighash_type.outputs_mode(), OutputsMode::Single)
                            && err == TransactionSigError::InvalidInputIndex(0, 0)
                        {
                            skip = true;
                        }

                        if !skip {
                            assert_eq!(Err(err), *expected_result)
                        }
                    }
                }
            });
        }
    }
}

#[test]
fn test_sign_mutate_then_verify_all() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint_dest = Destination::PublicKey(public_key);
    {
        // SigHashType::ALL - Can we add input?
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
        let mut tx_updater = MutableTransaction::try_from(&original_tx).unwrap();
        {
            let tx = &mut tx_updater;
            tx.inputs.push(tx.inputs[0].clone());
            let tx = tx.generate_tx().unwrap();
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 1235466),
                Err(TransactionSigError::InvalidInputIndex(1235466, 16))
            );
            assert_eq!(
                verify_signature(&outpoint_dest, &tx, 15),
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
    }
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
        let mut tx_updater = MutableTransaction::try_from(&original_tx).unwrap();
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
            let mut tx_updater = MutableTransaction::try_from(&original_tx).unwrap();
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
            let mut tx_updater = MutableTransaction::try_from(&original_tx).unwrap();
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
            let mut tx_updater = MutableTransaction::try_from(&original_tx).unwrap();
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
            let mut tx_updater = MutableTransaction::try_from(&original_tx).unwrap();
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
            let mut tx_updater = MutableTransaction::try_from(&original_tx).unwrap();
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
            let mut tx_updater = MutableTransaction::try_from(&original_tx).unwrap();
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
        let mut tx_updater = MutableTransaction::try_from(&original_tx).unwrap();
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
        let mut tx_updater = MutableTransaction::try_from(&original_tx).unwrap();
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
}
