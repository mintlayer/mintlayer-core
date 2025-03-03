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

use super::{add_value, utils::*};
use crate::{
    chain::{
        config::create_mainnet,
        signature::{
            sighash::sighashtype::{OutputsMode, SigHashType},
            tests::{
                check_insert_input, check_insert_output, check_mutate_input, check_mutate_output,
                sign_mutate_then_verify,
            },
            DestinationSigError,
        },
        signed_transaction::SignedTransaction,
        tokens::TokenId,
        AccountCommand, AccountOutPoint, AccountSpending, ChainConfig, DelegationId, Destination,
        OrderAccountCommand, OutPointSourceId, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, Id, H256},
};
use crypto::key::{KeyKind, PrivateKey};
use randomness::Rng;

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
        (31, 0, Err(DestinationSigError::SignatureVerificationFailed)),
        (
            INPUTS,
            OUTPUTS,
            Err(DestinationSigError::SignatureVerificationFailed),
        ),
        (
            31,
            31,
            Err(DestinationSigError::SignatureVerificationFailed),
        ),
    ];

    for ((destination, sighash_type), (inputs, outputs, expected)) in
        destinations(&mut rng, public_key)
            .cartesian_product(sig_hash_types())
            .cartesian_product(test_data)
    {
        let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, inputs);
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

        let tx = generate_unsigned_tx(&mut rng, &destination, &inputs_utxos, outputs).unwrap();
        match sign_whole_tx(
            &mut rng,
            tx,
            &inputs_utxos_refs,
            &private_key,
            sighash_type,
            &destination,
        ) {
            Ok(signed_tx) => {
                // Test flags change.
                let updated_tx = change_flags(&mut rng, &signed_tx, 1234567890);
                assert_eq!(
                    verify_signed_tx(&chain_config, &updated_tx, &inputs_utxos_refs, &destination),
                    expected
                );
            }
            // Not implemented.
            Err(DestinationSigError::Unsupported) => {
                assert!(matches!(destination, Destination::ScriptHash(_)))
            }
            Err(DestinationSigError::AttemptedToProduceSignatureForAnyoneCanSpend) => {
                assert_eq!(destination, Destination::AnyoneCanSpend)
            }
            Err(DestinationSigError::InvalidInputIndex(0, 0)) => {
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
        let sighash_type = SigHashType::all();
        let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 3);
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
        let tx = sign_mutate_then_verify(
            &chain_config,
            &mut rng,
            &inputs_utxos,
            &private_key,
            sighash_type,
            &destination,
        );
        check_insert_input(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            true,
        );
        check_mutate_input(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            true,
        );
        check_insert_output(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            true,
        );
        check_mutate_output(&chain_config, &tx, &inputs_utxos_refs, &destination, true);
    }

    {
        let sighash_type =
            SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
        let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 3);
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
        let tx = sign_mutate_then_verify(
            &chain_config,
            &mut rng,
            &inputs_utxos,
            &private_key,
            sighash_type,
            &destination,
        );
        check_insert_input(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            false,
        );
        check_mutate_input(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            true,
        );
        check_insert_output(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            true,
        );
        check_mutate_output(&chain_config, &tx, &inputs_utxos_refs, &destination, true);
    }

    {
        let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
        let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 3);
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
        let tx = sign_mutate_then_verify(
            &chain_config,
            &mut rng,
            &inputs_utxos,
            &private_key,
            sighash_type,
            &destination,
        );
        check_insert_input(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            true,
        );
        check_mutate_input(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            true,
        );
        check_insert_output(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            false,
        );
        check_mutate_output(&chain_config, &tx, &inputs_utxos_refs, &destination, false);
    }

    {
        let sighash_type =
            SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
        let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 3);
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
        let tx = sign_mutate_then_verify(
            &chain_config,
            &mut rng,
            &inputs_utxos,
            &private_key,
            sighash_type,
            &destination,
        );
        check_insert_input(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            false,
        );
        check_mutate_input(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            true,
        );
        check_insert_output(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            false,
        );
        check_mutate_output(&chain_config, &tx, &inputs_utxos_refs, &destination, false);
    }

    {
        let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
        let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 3);
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
        let tx = sign_mutate_then_verify(
            &chain_config,
            &mut rng,
            &inputs_utxos,
            &private_key,
            sighash_type,
            &destination,
        );
        check_insert_input(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            true,
        );
        check_mutate_input(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            true,
        );
        check_insert_output(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            false,
        );
        check_mutate_output(&chain_config, &tx, &inputs_utxos_refs, &destination, true);
    }

    {
        let sighash_type =
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
        let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, 3);
        let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
        let tx = sign_mutate_then_verify(
            &chain_config,
            &mut rng,
            &inputs_utxos,
            &private_key,
            sighash_type,
            &destination,
        );
        check_insert_input(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            false,
        );
        check_mutate_input(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            true,
        );
        check_insert_output(
            &chain_config,
            &mut rng,
            &tx,
            &inputs_utxos_refs,
            &destination,
            false,
        );
        check_mutate_output(&chain_config, &tx, &inputs_utxos_refs, &destination, true);
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
    let sighash_type = SigHashType::all();
    let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, INPUTS);
    let tx = generate_and_sign_tx(
        &chain_config,
        &mut rng,
        &destination,
        &inputs_utxos,
        OUTPUTS,
        &private_key,
        sighash_type,
    )
    .unwrap();

    let mutations = [
        add_input,
        mutate_first_input,
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
        &inputs_utxos,
        &destination,
        mutations,
        Err(DestinationSigError::SignatureVerificationFailed),
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
    let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, INPUTS);
    let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
    let tx = generate_and_sign_tx(
        &chain_config,
        &mut rng,
        &destination,
        &inputs_utxos,
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
        &inputs_utxos,
        &destination,
        mutations,
        Err(DestinationSigError::SignatureVerificationFailed),
    );

    {
        let tx = SignedTransactionWithUtxo {
            tx: tx.clone(),
            inputs_utxos: inputs_utxos.clone(),
        };
        let tx = mutate_first_input(&mut rng, &tx);
        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &inputs_utxos_refs,
                0
            ),
            Err(DestinationSigError::SignatureVerificationFailed),
        );
    }

    let mutations = [add_input, remove_first_input, remove_middle_input, remove_last_input];
    check_mutations(
        &chain_config,
        &mut rng,
        &tx,
        &inputs_utxos,
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
    let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, INPUTS);

    let tx = generate_and_sign_tx(
        &chain_config,
        &mut rng,
        &destination,
        &inputs_utxos,
        OUTPUTS,
        &private_key,
        sighash_type,
    )
    .unwrap();

    let mutations = [
        add_input,
        mutate_first_input,
        remove_first_input,
        remove_middle_input,
        remove_last_input,
    ];
    check_mutations(
        &chain_config,
        &mut rng,
        &tx,
        &inputs_utxos,
        &destination,
        mutations,
        Err(DestinationSigError::SignatureVerificationFailed),
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
        &inputs_utxos,
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
    let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, INPUTS);
    let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
    let tx = generate_and_sign_tx(
        &chain_config,
        &mut rng,
        &destination,
        &inputs_utxos,
        OUTPUTS,
        &private_key,
        sighash_type,
    )
    .unwrap();

    {
        let tx = SignedTransactionWithUtxo {
            tx: tx.clone(),
            inputs_utxos: inputs_utxos.clone(),
        };
        let tx = mutate_first_input(&mut rng, &tx);
        let inputs = tx.tx.inputs().len();

        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &inputs_utxos_refs,
                0
            ),
            Err(DestinationSigError::SignatureVerificationFailed),
        );
        for input in 1..inputs {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input],
                    &inputs_utxos_refs,
                    input
                ),
                Ok(())
            );
        }
    }

    let mutations = [];
    check_mutations(
        &chain_config,
        &mut rng,
        &tx,
        &inputs_utxos,
        &destination,
        mutations,
        Err(DestinationSigError::SignatureVerificationFailed),
    );

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
        &inputs_utxos,
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
    let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, INPUTS);
    let inputs_utxos_refs = inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();
    let tx = generate_and_sign_tx(
        &chain_config,
        &mut rng,
        &destination,
        &inputs_utxos,
        OUTPUTS,
        &private_key,
        sighash_type,
    )
    .unwrap();

    let mutations = [
        add_input,
        mutate_first_input,
        remove_first_input,
        remove_middle_input,
        remove_last_input,
        remove_first_output,
    ];
    let tx = SignedTransactionWithUtxo {
        tx,
        inputs_utxos: inputs_utxos.clone(),
    };
    for mutate in mutations.into_iter() {
        let tx = mutate(&mut rng, &tx);
        let total_inputs = tx.tx.inputs().len();
        let inputs_utxos_refs =
            tx.inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

        // Mutations make the last input number invalid, so verifying the signature for it should
        // result in the different error.
        for input in 0..total_inputs - 1 {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input],
                    &inputs_utxos_refs,
                    input
                ),
                Err(DestinationSigError::SignatureVerificationFailed)
            );
        }
        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &inputs_utxos_refs,
                total_inputs
            ),
            Err(DestinationSigError::InvalidSignatureIndex(
                total_inputs,
                total_inputs
            )),
        );
    }

    let mutations = [add_output, remove_last_output];
    for mutate in mutations.into_iter() {
        let tx = mutate(&mut rng, &tx);
        let inputs = tx.tx.inputs().len();

        // Mutations make the last input number invalid, so verifying the signature for it should
        // result in the `InvalidInputIndex` error.
        for input in 0..inputs - 1 {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input],
                    &inputs_utxos_refs,
                    input
                ),
                Ok(())
            );
        }
        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &inputs_utxos_refs,
                inputs
            ),
            Err(DestinationSigError::InvalidSignatureIndex(inputs, inputs)),
        );
    }

    {
        let tx = mutate_output(&mut rng, &tx);
        let total_inputs = tx.tx.inputs().len();
        let inputs_utxos_refs =
            tx.inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

        // Mutation of the first output makes signature invalid.
        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &inputs_utxos_refs,
                0
            ),
            Err(DestinationSigError::SignatureVerificationFailed),
        );
        for input in 1..total_inputs - 1 {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input],
                    &inputs_utxos_refs,
                    input
                ),
                Ok(())
            );
        }
        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &inputs_utxos_refs,
                total_inputs
            ),
            Err(DestinationSigError::InvalidSignatureIndex(
                total_inputs,
                total_inputs
            )),
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
    let (inputs_utxos, _priv_keys) = generate_inputs_utxos(&mut rng, INPUTS);
    let tx = generate_and_sign_tx(
        &chain_config,
        &mut rng,
        &destination,
        &inputs_utxos,
        OUTPUTS,
        &private_key,
        sighash_type,
    )
    .unwrap();

    let mutations = [add_input, remove_last_input, add_output, remove_last_output];
    let tx = SignedTransactionWithUtxo {
        tx,
        inputs_utxos: inputs_utxos.clone(),
    };
    for mutate in mutations.into_iter() {
        let tx = mutate(&mut rng, &tx);
        let total_inputs = tx.tx.inputs().len();
        let inputs_utxos_refs =
            tx.inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

        // Mutations make the last input number invalid, so verifying the signature for it should
        // result in the `InvalidInputIndex` error.
        for input in 0..total_inputs - 1 {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input],
                    &inputs_utxos_refs,
                    input
                ),
                Ok(()),
                "{input}"
            );
        }
        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &inputs_utxos_refs,
                total_inputs
            ),
            Err(DestinationSigError::InvalidSignatureIndex(
                total_inputs,
                total_inputs
            ))
        );
    }

    let mutations = [mutate_first_input, mutate_output];
    for mutate in mutations.into_iter() {
        let tx = mutate(&mut rng, &tx);
        let total_inputs = tx.tx.inputs().len();
        let inputs_utxos_refs =
            tx.inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &inputs_utxos_refs,
                0
            ),
            Err(DestinationSigError::SignatureVerificationFailed),
        );
        for input in 1..total_inputs - 1 {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input],
                    &inputs_utxos_refs,
                    input
                ),
                Ok(()),
                "## {input}"
            );
        }
        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &inputs_utxos_refs,
                total_inputs
            ),
            Err(DestinationSigError::InvalidSignatureIndex(
                total_inputs,
                total_inputs
            )),
        );
    }

    let mutations = [remove_first_input, remove_first_output];
    for mutate in mutations.into_iter() {
        let tx = mutate(&mut rng, &tx);
        let total_inputs = tx.tx.inputs().len();
        let inputs_utxos_refs =
            tx.inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

        // Mutations make the last input number invalid, so verifying the signature for it should
        // result in the `InvalidInputIndex` error.
        for input in 0..total_inputs - 1 {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input],
                    &inputs_utxos_refs,
                    input
                ),
                Err(DestinationSigError::SignatureVerificationFailed),
                "{input}"
            );
        }
        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &inputs_utxos_refs,
                total_inputs
            ),
            Err(DestinationSigError::InvalidSignatureIndex(
                total_inputs,
                total_inputs
            )),
        );
    }
}

#[track_caller]
fn check_mutations<M, R>(
    chain_config: &ChainConfig,
    rng: &mut R,
    tx: &SignedTransaction,
    inputs_utxos: &[Option<TxOutput>],
    destination: &Destination,
    mutations: M,
    expected: Result<(), DestinationSigError>,
) where
    R: Rng,
    M: IntoIterator<Item = fn(&mut R, &SignedTransactionWithUtxo) -> SignedTransactionWithUtxo>,
{
    let tx = SignedTransactionWithUtxo {
        tx: tx.clone(),
        inputs_utxos: inputs_utxos.to_vec(),
    };
    for mutate in mutations.into_iter() {
        let tx = mutate(rng, &tx);
        // The number of inputs can be changed by the `mutate` function.
        let inputs = tx.tx.inputs().len();
        let inputs_utxos_refs =
            tx.inputs_utxos.iter().map(|utxo| utxo.as_ref()).collect::<Vec<_>>();

        assert_eq!(
            verify_signature(
                chain_config,
                destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &inputs_utxos_refs,
                INVALID_INPUT
            ),
            Err(DestinationSigError::InvalidSignatureIndex(
                INVALID_INPUT,
                inputs
            ))
        );
        for input in 0..inputs {
            assert_eq!(
                verify_signature(
                    chain_config,
                    destination,
                    &tx.tx,
                    &tx.tx.signatures()[input],
                    &inputs_utxos_refs,
                    input
                ),
                expected
            );
        }
    }
}

struct SignedTransactionWithUtxo {
    tx: SignedTransaction,
    inputs_utxos: Vec<Option<TxOutput>>,
}

fn add_input(_rng: &mut impl Rng, tx: &SignedTransactionWithUtxo) -> SignedTransactionWithUtxo {
    let mut updater = MutableTransaction::from(&tx.tx);
    updater.inputs.push(updater.inputs[0].clone());
    updater.witness.push(updater.witness[0].clone());
    let mut inputs_utxos = tx.inputs_utxos.clone();
    inputs_utxos.push(inputs_utxos[0].clone());
    SignedTransactionWithUtxo {
        tx: updater.generate_tx().unwrap(),
        inputs_utxos,
    }
}

fn mutate_first_input(
    rng: &mut impl Rng,
    tx: &SignedTransactionWithUtxo,
) -> SignedTransactionWithUtxo {
    let mut updater = MutableTransaction::from(&tx.tx);

    let mutated_input = match updater.inputs.first().unwrap() {
        TxInput::Utxo(outpoint) => {
            if rng.gen::<bool>() {
                TxInput::Utxo(UtxoOutPoint::new(outpoint.source_id(), rng.gen()))
            } else {
                TxInput::Utxo(UtxoOutPoint::new(
                    OutPointSourceId::Transaction(Id::<Transaction>::from(H256::random_using(rng))),
                    outpoint.output_index(),
                ))
            }
        }
        TxInput::Account(outpoint) => {
            if rng.gen::<bool>() {
                TxInput::Account(AccountOutPoint::new(
                    outpoint.nonce(),
                    AccountSpending::DelegationBalance(
                        DelegationId::new(H256::random_using(rng)),
                        Amount::from_atoms(rng.gen()),
                    ),
                ))
            } else {
                let new_nonce = outpoint
                    .nonce()
                    .increment()
                    .unwrap_or_else(|| outpoint.nonce().decrement().unwrap());
                TxInput::Account(AccountOutPoint::new(new_nonce, outpoint.account().clone()))
            }
        }
        TxInput::AccountCommand(nonce, op) => {
            if rng.gen::<bool>() {
                TxInput::AccountCommand(
                    *nonce,
                    AccountCommand::ChangeTokenAuthority(
                        TokenId::new(H256::random_using(rng)),
                        Destination::AnyoneCanSpend,
                    ),
                )
            } else {
                let new_nonce = nonce.increment().unwrap_or_else(|| nonce.decrement().unwrap());
                TxInput::AccountCommand(new_nonce, op.clone())
            }
        }
        TxInput::OrderAccountCommand(cmd) => match cmd {
            OrderAccountCommand::FillOrder(id, amount, destination) => {
                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                    *id,
                    Amount::from_atoms(amount.into_atoms() + 1),
                    destination.clone(),
                ))
            }
            OrderAccountCommand::ConcludeOrder {
                order_id,
                ask_balance,
                give_balance,
            } => TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder {
                order_id: *order_id,
                ask_balance: Amount::from_atoms(ask_balance.into_atoms() + 1),
                give_balance: *give_balance,
            }),
        },
    };
    updater.inputs[0] = mutated_input;

    SignedTransactionWithUtxo {
        tx: updater.generate_tx().unwrap(),
        inputs_utxos: tx.inputs_utxos.clone(),
    }
}

fn remove_first_input(
    _rng: &mut impl Rng,
    tx: &SignedTransactionWithUtxo,
) -> SignedTransactionWithUtxo {
    let mut updater = MutableTransaction::from(&tx.tx);
    updater.inputs.remove(0);
    updater.witness.remove(0);
    let mut inputs_utxos = tx.inputs_utxos.clone();
    inputs_utxos.remove(0);
    SignedTransactionWithUtxo {
        tx: updater.generate_tx().unwrap(),
        inputs_utxos,
    }
}

fn remove_middle_input(
    _rng: &mut impl Rng,
    tx: &SignedTransactionWithUtxo,
) -> SignedTransactionWithUtxo {
    let mut updater = MutableTransaction::from(&tx.tx);
    assert!(updater.inputs.len() > 8);
    updater.inputs.remove(7);
    updater.witness.remove(7);
    let mut inputs_utxos = tx.inputs_utxos.clone();
    inputs_utxos.remove(7);
    SignedTransactionWithUtxo {
        tx: updater.generate_tx().unwrap(),
        inputs_utxos,
    }
}

fn remove_last_input(
    _rng: &mut impl Rng,
    tx: &SignedTransactionWithUtxo,
) -> SignedTransactionWithUtxo {
    let mut updater = MutableTransaction::from(&tx.tx);
    updater.inputs.pop().expect("Unexpected empty inputs");
    updater.witness.pop().expect("Unexpected empty witness");
    let mut inputs_utxos = tx.inputs_utxos.clone();
    inputs_utxos.pop().expect("Unexpected empty witness");
    SignedTransactionWithUtxo {
        tx: updater.generate_tx().unwrap(),
        inputs_utxos,
    }
}

fn add_output(_rng: &mut impl Rng, tx: &SignedTransactionWithUtxo) -> SignedTransactionWithUtxo {
    let mut updater = MutableTransaction::from(&tx.tx);
    updater.outputs.push(updater.outputs[0].clone());
    SignedTransactionWithUtxo {
        tx: updater.generate_tx().unwrap(),
        inputs_utxos: tx.inputs_utxos.clone(),
    }
}

fn mutate_output(_rng: &mut impl Rng, tx: &SignedTransactionWithUtxo) -> SignedTransactionWithUtxo {
    let mut updater = MutableTransaction::from(&tx.tx);
    // Should fail due to change in output value
    updater.outputs[0] = match updater.outputs[0].clone() {
        TxOutput::Transfer(v, d) => TxOutput::Transfer(add_value(v), d),
        TxOutput::LockThenTransfer(v, d, l) => TxOutput::LockThenTransfer(add_value(v), d, l),
        TxOutput::Burn(v) => TxOutput::Burn(add_value(v)),
        TxOutput::CreateStakePool(_, _) => unreachable!(), // TODO: come back to this later
        TxOutput::ProduceBlockFromStake(_, _) => unreachable!(), // TODO: come back to this later
        TxOutput::CreateDelegationId(_, _) => unreachable!(), // TODO: come back to this later
        TxOutput::DelegateStaking(_, _) => unreachable!(), // TODO: come back to this later
        TxOutput::IssueFungibleToken(_) => unreachable!(), // TODO: come back to this later
        TxOutput::IssueNft(_, _, _) => unreachable!(),     // TODO: come back to this later
        TxOutput::DataDeposit(_) => unreachable!(),
        TxOutput::Htlc(_, _) => unreachable!(),
        TxOutput::CreateOrder(_) => unreachable!(),
    };
    SignedTransactionWithUtxo {
        tx: updater.generate_tx().unwrap(),
        inputs_utxos: tx.inputs_utxos.clone(),
    }
}

fn remove_first_output(
    _rng: &mut impl Rng,
    tx: &SignedTransactionWithUtxo,
) -> SignedTransactionWithUtxo {
    let mut updater = MutableTransaction::from(&tx.tx);
    updater.outputs.remove(0);
    SignedTransactionWithUtxo {
        tx: updater.generate_tx().unwrap(),
        inputs_utxos: tx.inputs_utxos.clone(),
    }
}

fn remove_middle_output(
    _rng: &mut impl Rng,
    tx: &SignedTransactionWithUtxo,
) -> SignedTransactionWithUtxo {
    let mut updater = MutableTransaction::from(&tx.tx);
    assert!(updater.outputs.len() > 8);
    updater.outputs.remove(7);
    SignedTransactionWithUtxo {
        tx: updater.generate_tx().unwrap(),
        inputs_utxos: tx.inputs_utxos.clone(),
    }
}

fn remove_last_output(
    _rng: &mut impl Rng,
    tx: &SignedTransactionWithUtxo,
) -> SignedTransactionWithUtxo {
    let mut updater = MutableTransaction::from(&tx.tx);
    updater.outputs.pop().expect("Unexpected empty outputs");
    SignedTransactionWithUtxo {
        tx: updater.generate_tx().unwrap(),
        inputs_utxos: tx.inputs_utxos.clone(),
    }
}

fn change_flags(
    _rng: &mut impl Rng,
    original_tx: &SignedTransaction,
    new_flags: u128,
) -> SignedTransaction {
    let mut tx_updater = MutableTransaction::from(original_tx);
    tx_updater.flags = new_flags;
    tx_updater.generate_tx().unwrap()
}
