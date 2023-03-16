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
use rstest::rstest;
use test_utils::random::Seed;

use super::utils::*;
use crate::{
    chain::{
        config::create_mainnet,
        signature::{
            sighashtype::{OutputsMode, SigHashType},
            tests::{
                check_insert_input, check_insert_output, check_mutate_input, check_mutate_output,
                sign_mutate_then_verify,
            },
            verify_signature, TransactionSigError,
        },
        signed_transaction::SignedTransaction,
        tokens::OutputValue,
        ChainConfig, Destination, OutPointSourceId, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, Id, H256},
};
use crypto::key::{KeyKind, PrivateKey};
use crypto::random::Rng;

const INPUTS: usize = 15;
const OUTPUTS: usize = 15;
const INVALID_INPUT: usize = 1235466;

// Create a transaction, sign it, modify and try to verify the signature. Modifications include
// changing flags and lock time.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_mutate_tx_internal_data(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

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

    for ((destination, sighash_type), (inputs, outputs, expected)) in
        destinations(&mut rng, public_key)
            .cartesian_product(sig_hash_types())
            .cartesian_product(test_data)
    {
        let tx = generate_unsigned_tx(&mut rng, &destination, inputs, outputs).unwrap();
        match sign_whole_tx(tx, &private_key, sighash_type, &destination) {
            Ok(signed_tx) => {
                // Test flags change.
                let updated_tx = change_flags(&mut rng, &signed_tx, 1234567890);
                assert_eq!(
                    verify_signed_tx(&chain_config, &updated_tx, &destination),
                    expected
                );
                // Test locktime change.
                let updated_tx = change_locktime(&mut rng, &signed_tx, 1234567890);
                assert_eq!(
                    verify_signed_tx(&chain_config, &updated_tx, &destination),
                    expected
                )
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
            e => assert_eq!(e.unwrap_err(), expected.unwrap_err()),
        }
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn modify_and_verify(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let destination = Destination::PublicKey(public_key);

    {
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        let tx = sign_mutate_then_verify(
            &chain_config,
            &mut rng,
            &private_key,
            sighash_type,
            &destination,
        );
        check_insert_input(&chain_config, &mut rng, &tx, &destination, true);
        check_mutate_input(&chain_config, &mut rng, &tx, &destination, true);
        check_insert_output(&chain_config, &mut rng, &tx, &destination, true);
        check_mutate_output(&chain_config, &tx, &destination, true);
    }

    {
        let sighash_type =
            SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
        let tx = sign_mutate_then_verify(
            &chain_config,
            &mut rng,
            &private_key,
            sighash_type,
            &destination,
        );
        check_insert_input(&chain_config, &mut rng, &tx, &destination, false);
        check_mutate_input(&chain_config, &mut rng, &tx, &destination, true);
        check_insert_output(&chain_config, &mut rng, &tx, &destination, true);
        check_mutate_output(&chain_config, &tx, &destination, true);
    }

    {
        let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
        let tx = sign_mutate_then_verify(
            &chain_config,
            &mut rng,
            &private_key,
            sighash_type,
            &destination,
        );
        check_insert_input(&chain_config, &mut rng, &tx, &destination, true);
        check_mutate_input(&chain_config, &mut rng, &tx, &destination, true);
        check_insert_output(&chain_config, &mut rng, &tx, &destination, false);
        check_mutate_output(&chain_config, &tx, &destination, false);
    }

    {
        let sighash_type =
            SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
        let tx = sign_mutate_then_verify(
            &chain_config,
            &mut rng,
            &private_key,
            sighash_type,
            &destination,
        );
        check_insert_input(&chain_config, &mut rng, &tx, &destination, false);
        check_mutate_input(&chain_config, &mut rng, &tx, &destination, true);
        check_insert_output(&chain_config, &mut rng, &tx, &destination, false);
        check_mutate_output(&chain_config, &tx, &destination, false);
    }

    {
        let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
        let tx = sign_mutate_then_verify(
            &chain_config,
            &mut rng,
            &private_key,
            sighash_type,
            &destination,
        );
        check_insert_input(&chain_config, &mut rng, &tx, &destination, true);
        check_mutate_input(&chain_config, &mut rng, &tx, &destination, true);
        check_insert_output(&chain_config, &mut rng, &tx, &destination, false);
        check_mutate_output(&chain_config, &tx, &destination, true);
    }

    {
        let sighash_type =
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
        let tx = sign_mutate_then_verify(
            &chain_config,
            &mut rng,
            &private_key,
            sighash_type,
            &destination,
        );
        check_insert_input(&chain_config, &mut rng, &tx, &destination, false);
        check_mutate_input(&chain_config, &mut rng, &tx, &destination, true);
        check_insert_output(&chain_config, &mut rng, &tx, &destination, false);
        check_mutate_output(&chain_config, &tx, &destination, true);
    }
}

// The `ALL` signature hash type is applied to all inputs and all outputs, so any change must result
// in the signature verification error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mutate_all(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let destination = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
    let tx = generate_and_sign_tx(
        &chain_config,
        &mut rng,
        &destination,
        INPUTS,
        OUTPUTS,
        &private_key,
        sighash_type,
    )
    .unwrap();

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
        &chain_config,
        &mut rng,
        &tx,
        &destination,
        mutations,
        Err(TransactionSigError::SignatureVerificationFailed),
    );
}

// `ALL | ANYONECANPAY` is applied to all outputs and one input only.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mutate_all_anyonecanpay(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let destination = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
    let tx = generate_and_sign_tx(
        &chain_config,
        &mut rng,
        &destination,
        INPUTS,
        OUTPUTS,
        &private_key,
        sighash_type,
    )
    .unwrap();

    let mutations = [
        add_output,
        mutate_output,
        remove_first_output,
        remove_middle_output,
        remove_last_output,
    ];
    check_mutations(
        &chain_config,
        &mut rng,
        &tx,
        &destination,
        mutations,
        Err(TransactionSigError::SignatureVerificationFailed),
    );

    {
        let tx = mutate_input(&mut rng, &tx);
        assert_eq!(
            verify_signature(&chain_config, &destination, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed),
        );
    }

    let mutations = [add_input, remove_first_input, remove_middle_input, remove_last_input];
    check_mutations(
        &chain_config,
        &mut rng,
        &tx,
        &destination,
        mutations,
        Ok(()),
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mutate_none(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let destination = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
    let tx = generate_and_sign_tx(
        &chain_config,
        &mut rng,
        &destination,
        INPUTS,
        OUTPUTS,
        &private_key,
        sighash_type,
    )
    .unwrap();

    let mutations = [
        add_input,
        mutate_input,
        remove_first_input,
        remove_middle_input,
        remove_last_input,
    ];
    check_mutations(
        &chain_config,
        &mut rng,
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
    check_mutations(
        &chain_config,
        &mut rng,
        &tx,
        &destination,
        mutations,
        Ok(()),
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mutate_none_anyonecanpay(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let destination = Destination::PublicKey(public_key);
    let sighash_type =
        SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
    let tx = generate_and_sign_tx(
        &chain_config,
        &mut rng,
        &destination,
        INPUTS,
        OUTPUTS,
        &private_key,
        sighash_type,
    )
    .unwrap();

    {
        let tx = mutate_input(&mut rng, &tx);
        let inputs = tx.inputs().len();

        assert_eq!(
            verify_signature(&chain_config, &destination, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed),
        );
        for input in 1..inputs {
            assert_eq!(
                verify_signature(&chain_config, &destination, &tx, input),
                Ok(())
            );
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
    check_mutations(
        &chain_config,
        &mut rng,
        &tx,
        &destination,
        mutations,
        Ok(()),
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mutate_single(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let destination = Destination::PublicKey(public_key);
    let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
    let tx = generate_and_sign_tx(
        &chain_config,
        &mut rng,
        &destination,
        INPUTS,
        OUTPUTS,
        &private_key,
        sighash_type,
    )
    .unwrap();

    let mutations = [
        add_input,
        mutate_input,
        remove_first_input,
        remove_middle_input,
        remove_last_input,
        remove_first_output,
    ];
    for mutate in mutations.into_iter() {
        let tx = mutate(&mut rng, &tx);
        let inputs = tx.inputs().len();

        // Mutations make the last input number invalid, so verifying the signature for it should
        // result in the different error.
        for input in 0..inputs - 1 {
            assert_eq!(
                verify_signature(&chain_config, &destination, &tx, input),
                Err(TransactionSigError::SignatureVerificationFailed)
            );
        }
        assert_eq!(
            verify_signature(&chain_config, &destination, &tx, inputs),
            Err(TransactionSigError::InvalidSignatureIndex(inputs, inputs)),
        );
    }

    let mutations = [add_output, remove_last_output];
    for mutate in mutations.into_iter() {
        let tx = mutate(&mut rng, &tx);
        let inputs = tx.inputs().len();

        // Mutations make the last input number invalid, so verifying the signature for it should
        // result in the `InvalidInputIndex` error.
        for input in 0..inputs - 1 {
            assert_eq!(
                verify_signature(&chain_config, &destination, &tx, input),
                Ok(())
            );
        }
        assert_eq!(
            verify_signature(&chain_config, &destination, &tx, inputs),
            Err(TransactionSigError::InvalidSignatureIndex(inputs, inputs)),
        );
    }

    {
        let tx = mutate_output(&mut rng, &tx);
        let inputs = tx.inputs().len();

        // Mutation of the first output makes signature invalid.
        assert_eq!(
            verify_signature(&chain_config, &destination, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed),
        );
        for input in 1..inputs - 1 {
            assert_eq!(
                verify_signature(&chain_config, &destination, &tx, input),
                Ok(())
            );
        }
        assert_eq!(
            verify_signature(&chain_config, &destination, &tx, inputs),
            Err(TransactionSigError::InvalidSignatureIndex(inputs, inputs)),
        );
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mutate_single_anyonecanpay(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let destination = Destination::PublicKey(public_key);
    let sighash_type =
        SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
    let tx = generate_and_sign_tx(
        &chain_config,
        &mut rng,
        &destination,
        INPUTS,
        OUTPUTS,
        &private_key,
        sighash_type,
    )
    .unwrap();

    let mutations = [add_input, remove_last_input, add_output, remove_last_output];
    for mutate in mutations.into_iter() {
        let tx = mutate(&mut rng, &tx);
        let inputs = tx.inputs().len();

        // Mutations make the last input number invalid, so verifying the signature for it should
        // result in the `InvalidInputIndex` error.
        for input in 0..inputs - 1 {
            assert_eq!(
                verify_signature(&chain_config, &destination, &tx, input),
                Ok(()),
                "{input}"
            );
        }
        assert_eq!(
            verify_signature(&chain_config, &destination, &tx, inputs),
            Err(TransactionSigError::InvalidSignatureIndex(inputs, inputs))
        );
    }

    let mutations = [mutate_input, mutate_output];
    for mutate in mutations.into_iter() {
        let tx = mutate(&mut rng, &tx);
        let inputs = tx.inputs().len();

        assert_eq!(
            verify_signature(&chain_config, &destination, &tx, 0),
            Err(TransactionSigError::SignatureVerificationFailed),
        );
        for input in 1..inputs - 1 {
            assert_eq!(
                verify_signature(&chain_config, &destination, &tx, input),
                Ok(()),
                "## {input}"
            );
        }
        assert_eq!(
            verify_signature(&chain_config, &destination, &tx, inputs),
            Err(TransactionSigError::InvalidSignatureIndex(inputs, inputs)),
        );
    }

    let mutations = [remove_first_input, remove_first_output];
    for mutate in mutations.into_iter() {
        let tx = mutate(&mut rng, &tx);
        let inputs = tx.inputs().len();

        // Mutations make the last input number invalid, so verifying the signature for it should
        // result in the `InvalidInputIndex` error.
        for input in 0..inputs - 1 {
            assert_eq!(
                verify_signature(&chain_config, &destination, &tx, input),
                Err(TransactionSigError::SignatureVerificationFailed),
                "{input}"
            );
        }
        assert_eq!(
            verify_signature(&chain_config, &destination, &tx, inputs),
            Err(TransactionSigError::InvalidSignatureIndex(inputs, inputs)),
        );
    }
}

fn check_mutations<M, R>(
    chain_config: &ChainConfig,
    rng: &mut R,
    tx: &SignedTransaction,
    destination: &Destination,
    mutations: M,
    expected: Result<(), TransactionSigError>,
) where
    R: Rng,
    M: IntoIterator<Item = fn(&mut R, &SignedTransaction) -> SignedTransaction>,
{
    for mutate in mutations.into_iter() {
        let tx = mutate(rng, tx);
        // The number of inputs can be changed by the `mutate` function.
        let inputs = tx.inputs().len();

        assert_eq!(
            verify_signature(chain_config, destination, &tx, INVALID_INPUT),
            Err(TransactionSigError::InvalidSignatureIndex(
                INVALID_INPUT,
                inputs
            ))
        );
        for input in 0..inputs {
            assert_eq!(
                verify_signature(chain_config, destination, &tx, input),
                expected
            );
        }
    }
}

fn add_input(_rng: &mut impl Rng, tx: &SignedTransaction) -> SignedTransaction {
    let mut updater = MutableTransaction::from(tx);
    updater.inputs.push(updater.inputs[0].clone());
    updater.witness.push(updater.witness[0].clone());
    updater.generate_tx().unwrap()
}

fn mutate_input(rng: &mut impl Rng, tx: &SignedTransaction) -> SignedTransaction {
    let mut updater = MutableTransaction::from(tx);
    updater.inputs[0] = TxInput::new(
        OutPointSourceId::Transaction(Id::<Transaction>::from(H256::random_using(rng))),
        9999,
    );
    updater.generate_tx().unwrap()
}

fn remove_first_input(_rng: &mut impl Rng, tx: &SignedTransaction) -> SignedTransaction {
    let mut updater = MutableTransaction::from(tx);
    updater.inputs.remove(0);
    updater.witness.remove(0);
    updater.generate_tx().unwrap()
}

fn remove_middle_input(_rng: &mut impl Rng, tx: &SignedTransaction) -> SignedTransaction {
    let mut updater = MutableTransaction::from(tx);
    assert!(updater.inputs.len() > 8);
    updater.inputs.remove(7);
    updater.witness.remove(7);
    updater.generate_tx().unwrap()
}

fn remove_last_input(_rng: &mut impl Rng, tx: &SignedTransaction) -> SignedTransaction {
    let mut updater = MutableTransaction::from(tx);
    updater.inputs.pop().expect("Unexpected empty inputs");
    updater.witness.pop().expect("Unexpected empty witness");
    updater.generate_tx().unwrap()
}

fn add_output(_rng: &mut impl Rng, tx: &SignedTransaction) -> SignedTransaction {
    let mut updater = MutableTransaction::from(tx);
    updater.outputs.push(updater.outputs[0].clone());
    updater.generate_tx().unwrap()
}

fn mutate_output(_rng: &mut impl Rng, tx: &SignedTransaction) -> SignedTransaction {
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

fn remove_first_output(_rng: &mut impl Rng, tx: &SignedTransaction) -> SignedTransaction {
    let mut updater = MutableTransaction::from(tx);
    updater.outputs.remove(0);
    updater.generate_tx().unwrap()
}

fn remove_middle_output(_rng: &mut impl Rng, tx: &SignedTransaction) -> SignedTransaction {
    let mut updater = MutableTransaction::from(tx);
    assert!(updater.outputs.len() > 8);
    updater.outputs.remove(7);
    updater.generate_tx().unwrap()
}

fn remove_last_output(_rng: &mut impl Rng, tx: &SignedTransaction) -> SignedTransaction {
    let mut updater = MutableTransaction::from(tx);
    updater.outputs.pop().expect("Unexpected empty outputs");
    updater.generate_tx().unwrap()
}

fn change_flags(
    _rng: &mut impl Rng,
    original_tx: &SignedTransaction,
    new_flags: u32,
) -> SignedTransaction {
    let mut tx_updater = MutableTransaction::from(original_tx);
    tx_updater.flags = new_flags;
    tx_updater.generate_tx().unwrap()
}

fn change_locktime(
    _rng: &mut impl Rng,
    original_tx: &SignedTransaction,
    new_lock_time: u32,
) -> SignedTransaction {
    let mut tx_updater = MutableTransaction::from(original_tx);
    tx_updater.lock_time = new_lock_time;
    tx_updater.generate_tx().unwrap()
}
