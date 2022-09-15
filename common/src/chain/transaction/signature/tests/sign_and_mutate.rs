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

use crypto::key::{KeyKind, PrivateKey};

use super::utils::*;
use crate::{
    chain::{
        signature::{
            sighashtype::{OutputsMode, SigHashType},
            tests::{
                check_insert_input, check_insert_output, check_mutate_input, check_mutate_output,
                sign_mutate_then_verify,
            },
            verify_signature, TransactionSigError,
        },
        tokens::OutputValue,
        Destination, OutPointSourceId, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, Id, H256},
};

const INPUTS: usize = 15;
const OUTPUTS: usize = 15;
const INVALID_INPUT: usize = 1235466;

// Create a transaction, sign it, modify and try to verify the signature. Modifications include
// changing flags and lock time.
#[test]
fn test_mutate_tx_internal_data() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);

    let test_data = [
        (0, 31, Ok(())),
        (31, 0, Err(TransactionSigError::SignatureVerificationFailed)),
        (
            INPUTS,
            OUTPUTS,
            Err(TransactionSigError::SignatureVerificationFailed),
        ),
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
        let mut tx = generate_unsigned_tx(&destination, inputs, outputs).unwrap();
        match sign_whole_tx(&mut tx, &private_key, sighash_type, &destination) {
            Ok(()) => {
                // Test flags change.
                let updated_tx = change_flags(&tx, 1234567890);
                assert_eq!(verify_signed_tx(&updated_tx, &destination), expected);
                // Test locktime change.
                let updated_tx = change_locktime(&tx, 1234567890);
                assert_eq!(verify_signed_tx(&updated_tx, &destination), expected)
            }
            // Not implemented.
            Err(TransactionSigError::Unsupported) => {
                assert!(matches!(destination, Destination::ScriptHash(_)))
            }
            Err(TransactionSigError::AttemptedToProduceSignatureForAnyoneCanSpend) => {
                assert_eq!(destination, Destination::AnyoneCanSpend)
            }
            Err(TransactionSigError::InvalidInputIndex(0, 0)) => {
                assert_eq!(sighash_type.outputs_mode(), OutputsMode::Single)
            }
            e => assert_eq!(e, expected),
        }
    }
}

#[test]
fn modify_and_verify() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let destination = Destination::PublicKey(public_key);

    {
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let tx = sign_mutate_then_verify(&private_key, sighash_type, &destination);
        check_insert_input(&tx, &destination, true);
        check_mutate_input(&tx, &destination, true);
        check_insert_output(&tx, &destination, true);
        check_mutate_output(&tx, &destination, true);
    }

    {
        let sighash_type =
            SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
        let tx = sign_mutate_then_verify(&private_key, sighash_type, &destination);
        check_insert_input(&tx, &destination, false);
        check_mutate_input(&tx, &destination, true);
        check_insert_output(&tx, &destination, true);
        check_mutate_output(&tx, &destination, true);
    }

    {
        let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
        let tx = sign_mutate_then_verify(&private_key, sighash_type, &destination);
        check_insert_input(&tx, &destination, true);
        check_mutate_input(&tx, &destination, true);
        check_insert_output(&tx, &destination, false);
        check_mutate_output(&tx, &destination, false);
    }

    {
        let sighash_type =
            SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
        let tx = sign_mutate_then_verify(&private_key, sighash_type, &destination);
        check_insert_input(&tx, &destination, false);
        check_mutate_input(&tx, &destination, true);
        check_insert_output(&tx, &destination, false);
        check_mutate_output(&tx, &destination, false);
    }

    {
        let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
        let tx = sign_mutate_then_verify(&private_key, sighash_type, &destination);
        check_insert_input(&tx, &destination, true);
        check_mutate_input(&tx, &destination, true);
        check_insert_output(&tx, &destination, false);
        check_mutate_output(&tx, &destination, true);
    }

    {
        let sighash_type =
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
        let tx = sign_mutate_then_verify(&private_key, sighash_type, &destination);
        check_insert_input(&tx, &destination, false);
        check_mutate_input(&tx, &destination, true);
        check_insert_output(&tx, &destination, false);
        check_mutate_output(&tx, &destination, true);
    }
}

// The `ALL` signature hash type is applied to all inputs and all outputs, so any change must result
// in the signature verification error.
#[test]
fn mutate_all() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let destination = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
    let tx =
        generate_and_sign_tx(&destination, INPUTS, OUTPUTS, &private_key, sighash_type).unwrap();

    let mutations = [
        add_input,
        mutate_input,
        remove_first_input,
        remove_middle_input,
        remove_last_input,
        add_output,
        mutate_output,
        remove_first_output,
        remove_middle_output,
        remove_last_output,
    ];
    check_mutations(
        &tx,
        &destination,
        mutations,
        Err(TransactionSigError::SignatureVerificationFailed),
    );
}

// `ALL | ANYONECANPAY` is applied to all outputs and one input only.
#[test]
fn mutate_all_anyonecanpay() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let destination = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
    let tx =
        generate_and_sign_tx(&destination, INPUTS, OUTPUTS, &private_key, sighash_type).unwrap();

    let mutations = [
        add_output,
        mutate_output,
        remove_first_output,
        remove_middle_output,
        remove_last_output,
    ];
    check_mutations(
        &tx,
        &destination,
        mutations,
        Err(TransactionSigError::SignatureVerificationFailed),
    );

    {
        let tx = mutate_input(&tx);
        assert_eq!(
            verify_signature(&destination, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed),
        );
    }

    let mutations = [add_input, remove_first_input, remove_middle_input, remove_last_input];
    check_mutations(&tx, &destination, mutations, Ok(()));
}

#[test]
fn mutate_none() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let destination = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
    let tx =
        generate_and_sign_tx(&destination, INPUTS, OUTPUTS, &private_key, sighash_type).unwrap();

    let mutations = [
        add_input,
        mutate_input,
        remove_first_input,
        remove_middle_input,
        remove_last_input,
    ];
    check_mutations(
        &tx,
        &destination,
        mutations,
        Err(TransactionSigError::SignatureVerificationFailed),
    );

    let mutations = [
        add_output,
        mutate_output,
        remove_first_output,
        remove_middle_output,
        remove_last_output,
    ];
    check_mutations(&tx, &destination, mutations, Ok(()));
}

#[test]
fn mutate_none_anyonecanpay() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let destination = Destination::PublicKey(public_key);
    let sighash_type =
        SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
    let tx =
        generate_and_sign_tx(&destination, INPUTS, OUTPUTS, &private_key, sighash_type).unwrap();

    {
        let tx = mutate_input(&tx);
        let inputs = tx.inputs().len();

        assert_eq!(
            verify_signature(&destination, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed),
        );
        for input in 1..inputs {
            assert_eq!(verify_signature(&destination, &tx, input), Ok(()));
        }
    }

    let mutations = [
        add_input,
        remove_first_input,
        remove_middle_input,
        remove_last_input,
        add_output,
        mutate_output,
        remove_first_output,
        remove_middle_output,
        remove_last_output,
    ];
    check_mutations(&tx, &destination, mutations, Ok(()));
}

#[test]
fn mutate_single() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let destination = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
    let tx =
        generate_and_sign_tx(&destination, INPUTS, OUTPUTS, &private_key, sighash_type).unwrap();

    let mutations = [
        add_input,
        mutate_input,
        remove_first_input,
        remove_middle_input,
        remove_last_input,
        remove_first_output,
    ];
    for mutate in mutations.into_iter() {
        let tx = mutate(&tx);
        let inputs = tx.inputs().len();

        // Mutations make the last input number invalid, so verifying the signature for it should
        // result in the different error.
        for input in 0..inputs - 1 {
            assert_eq!(
                verify_signature(&destination, &tx, input),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
        }
        assert_eq!(
            verify_signature(&destination, &tx, inputs),
            Err(TransactionSigError::InvalidInputIndex(inputs, inputs)),
        );
    }

    let mutations = [add_output, remove_last_output];
    for mutate in mutations.into_iter() {
        let tx = mutate(&tx);
        let inputs = tx.inputs().len();

        // Mutations make the last input number invalid, so verifying the signature for it should
        // result in the `InvalidInputIndex` error.
        for input in 0..inputs - 1 {
            assert_eq!(verify_signature(&destination, &tx, input), Ok(()));
        }
        assert_eq!(
            verify_signature(&destination, &tx, inputs),
            Err(TransactionSigError::InvalidInputIndex(inputs, inputs)),
        );
    }

    {
        let tx = mutate_output(&tx);
        let inputs = tx.inputs().len();

        // Mutation of the first output makes signature invalid.
        assert_eq!(
            verify_signature(&destination, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed),
        );
        for input in 1..inputs - 1 {
            assert_eq!(verify_signature(&destination, &tx, input), Ok(()));
        }
        assert_eq!(
            verify_signature(&destination, &tx, inputs),
            Err(TransactionSigError::InvalidInputIndex(inputs, inputs)),
        );
    }
}

#[test]
fn mutate_single_anyonecanpay() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let destination = Destination::PublicKey(public_key);
    let sighash_type =
        SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
    let tx =
        generate_and_sign_tx(&destination, INPUTS, OUTPUTS, &private_key, sighash_type).unwrap();

    let mutations = [add_input, remove_last_input, add_output, remove_last_output];
    for mutate in mutations.into_iter() {
        let tx = mutate(&tx);
        let inputs = tx.inputs().len();

        // Mutations make the last input number invalid, so verifying the signature for it should
        // result in the `InvalidInputIndex` error.
        for input in 0..inputs - 1 {
            assert_eq!(
                verify_signature(&destination, &tx, input),
                Ok(()),
                "{input}"
            );
        }
        assert_eq!(
            verify_signature(&destination, &tx, inputs),
            Err(TransactionSigError::InvalidInputIndex(inputs, inputs))
        );
    }

    let mutations = [mutate_input, mutate_output];
    for mutate in mutations.into_iter() {
        let tx = mutate(&tx);
        let inputs = tx.inputs().len();

        assert_eq!(
            verify_signature(&destination, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed),
        );
        for input in 1..inputs - 1 {
            assert_eq!(
                verify_signature(&destination, &tx, input),
                Ok(()),
                "## {input}"
            );
        }
        assert_eq!(
            verify_signature(&destination, &tx, inputs),
            Err(TransactionSigError::InvalidInputIndex(inputs, inputs)),
        );
    }

    let mutations = [remove_first_input, remove_first_output];
    for mutate in mutations.into_iter() {
        let tx = mutate(&tx);
        let inputs = tx.inputs().len();

        // Mutations make the last input number invalid, so verifying the signature for it should
        // result in the `InvalidInputIndex` error.
        for input in 0..inputs - 1 {
            assert_eq!(
                verify_signature(&destination, &tx, input),
                Err(TransactionSigError::SignatureVerificationFailed),
                "{input}"
            );
        }
        assert_eq!(
            verify_signature(&destination, &tx, inputs),
            Err(TransactionSigError::InvalidInputIndex(inputs, inputs)),
        );
    }
}

fn check_mutations<M>(
    tx: &Transaction,
    destination: &Destination,
    mutations: M,
    expected: Result<(), TransactionSigError>,
) where
    M: IntoIterator<Item = fn(&Transaction) -> Transaction>,
{
    for mutate in mutations.into_iter() {
        let tx = mutate(tx);
        // The number of inputs can be changed by the `mutate` function.
        let inputs = tx.inputs().len();

        assert_eq!(
            verify_signature(destination, &tx, INVALID_INPUT),
            Err(TransactionSigError::InvalidInputIndex(
                INVALID_INPUT,
                inputs
            ))
        );
        for input in 0..inputs {
            assert_eq!(verify_signature(destination, &tx, input), expected);
        }
    }
}

fn add_input(tx: &Transaction) -> Transaction {
    let mut updater = MutableTransaction::from(tx);
    updater.inputs.push(updater.inputs[0].clone());
    updater.generate_tx().unwrap()
}

fn mutate_input(tx: &Transaction) -> Transaction {
    let mut updater = MutableTransaction::from(tx);
    updater.inputs[0] = TxInput::new(
        OutPointSourceId::Transaction(Id::<Transaction>::from(H256::random())),
        9999,
        updater.inputs[0].witness().clone(),
    );
    updater.generate_tx().unwrap()
}

fn remove_first_input(tx: &Transaction) -> Transaction {
    let mut updater = MutableTransaction::from(tx);
    updater.inputs.remove(0);
    updater.generate_tx().unwrap()
}

fn remove_middle_input(tx: &Transaction) -> Transaction {
    let mut updater = MutableTransaction::from(tx);
    assert!(updater.inputs.len() > 8);
    updater.inputs.remove(7);
    updater.generate_tx().unwrap()
}

fn remove_last_input(tx: &Transaction) -> Transaction {
    let mut updater = MutableTransaction::from(tx);
    updater.inputs.pop().expect("Unexpected empty inputs");
    updater.generate_tx().unwrap()
}

fn add_output(tx: &Transaction) -> Transaction {
    let mut updater = MutableTransaction::from(tx);
    updater.outputs.push(updater.outputs[0].clone());
    updater.generate_tx().unwrap()
}

fn mutate_output(tx: &Transaction) -> Transaction {
    let mut updater = MutableTransaction::from(tx);
    updater.outputs[0] = TxOutput::new(
        match updater.outputs[0].value() {
            OutputValue::Coin(coin) => {
                OutputValue::Coin((*coin + Amount::from_atoms(100)).unwrap())
            }
            OutputValue::Token(asset) => OutputValue::Token(asset.clone()),
        },
        updater.outputs[0].purpose().clone(),
    );
    updater.generate_tx().unwrap()
}

fn remove_first_output(tx: &Transaction) -> Transaction {
    let mut updater = MutableTransaction::from(tx);
    updater.outputs.remove(0);
    updater.generate_tx().unwrap()
}

fn remove_middle_output(tx: &Transaction) -> Transaction {
    let mut updater = MutableTransaction::from(tx);
    assert!(updater.outputs.len() > 8);
    updater.outputs.remove(7);
    updater.generate_tx().unwrap()
}

fn remove_last_output(tx: &Transaction) -> Transaction {
    let mut updater = MutableTransaction::from(tx);
    updater.outputs.pop().expect("Unexpected empty outputs");
    updater.generate_tx().unwrap()
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
