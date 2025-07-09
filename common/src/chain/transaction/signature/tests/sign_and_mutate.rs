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

use crate::{
    chain::{
        config::create_mainnet,
        signature::{
            sighash::sighashtype::{OutputsMode, SigHashType},
            DestinationSigError,
        },
        signed_transaction::SignedTransaction,
        tokens::TokenId,
        AccountCommand, AccountOutPoint, AccountSpending, ChainConfig, DelegationId, Destination,
        OrderAccountCommand, OrderId, OutPointSourceId, Transaction, TxInput, TxOutput,
        UtxoOutPoint,
    },
    primitives::{Amount, Id, H256},
};
use crypto::key::{KeyKind, PrivateKey};
use randomness::{CryptoRng, Rng};
use test_utils::gen_different_value;

use super::{add_value, utils::*};

const INPUTS_COUNT: usize = 15;
const OUTPUTS_COUNT: usize = 15;
const INVALID_INPUT_INDEX: usize = 1235466;

// Create a transaction, sign it, modify its flags and try to verify the signature.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_mutate_tx_flags(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = create_mainnet();

    let (private_key, public_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    let test_data = [
        (0, 31, Ok(())),
        (31, 0, Err(DestinationSigError::SignatureVerificationFailed)),
        (
            INPUTS_COUNT,
            OUTPUTS_COUNT,
            Err(DestinationSigError::SignatureVerificationFailed),
        ),
        (
            31,
            31,
            Err(DestinationSigError::SignatureVerificationFailed),
        ),
    ];

    for ((destination, sighash_type), (inputs_count, outputs_count, expected)) in
        destinations(&mut rng, public_key)
            .cartesian_product(sig_hash_types())
            .cartesian_product(test_data)
    {
        let input_commitments = generate_input_commitments(&mut rng, inputs_count);

        let tx = generate_unsigned_tx(
            &mut rng,
            &destination,
            input_commitments.len(),
            outputs_count,
        )
        .unwrap();
        match sign_whole_tx(
            &mut rng,
            tx,
            &input_commitments,
            &private_key,
            sighash_type,
            &destination,
        ) {
            Ok(signed_tx) => {
                // Test flags change.
                let updated_tx = change_flags(&mut rng, &signed_tx, 1234567890);
                assert_eq!(
                    verify_signed_tx(&chain_config, &updated_tx, &input_commitments, &destination),
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
    let tx = generate_signed_tx_with_input_commitments(
        &chain_config,
        &mut rng,
        &destination,
        INPUTS_COUNT,
        OUTPUTS_COUNT,
        &private_key,
        sighash_type,
    )
    .unwrap();

    let mutations = [
        append_input,
        mutate_first_input,
        mutate_first_input_commitment,
        remove_first_input,
        remove_middle_input,
        remove_last_input,
        append_output,
        mutate_first_output,
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
    let tx = generate_signed_tx_with_input_commitments(
        &chain_config,
        &mut rng,
        &destination,
        INPUTS_COUNT,
        OUTPUTS_COUNT,
        &private_key,
        sighash_type,
    )
    .unwrap();

    let mutations = [
        append_output,
        mutate_first_output,
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
        Err(DestinationSigError::SignatureVerificationFailed),
    );

    {
        let tx = mutate_first_input(&mut rng, &tx);
        let inputs_count = tx.tx.inputs().len();

        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &tx.input_commitments,
                0
            ),
            Err(DestinationSigError::SignatureVerificationFailed),
        );
        for input_idx in 1..inputs_count {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input_idx],
                    &tx.input_commitments,
                    input_idx
                ),
                Ok(())
            );
        }
    }

    {
        let tx = mutate_first_input_commitment(&mut rng, &tx);
        let inputs_count = tx.tx.inputs().len();

        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &tx.input_commitments,
                0
            ),
            Err(DestinationSigError::SignatureVerificationFailed),
        );
        for input_idx in 1..inputs_count {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input_idx],
                    &tx.input_commitments,
                    input_idx
                ),
                Ok(())
            );
        }
    }

    let mutations = [append_input, remove_first_input, remove_middle_input, remove_last_input];
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
    let tx = generate_signed_tx_with_input_commitments(
        &chain_config,
        &mut rng,
        &destination,
        INPUTS_COUNT,
        OUTPUTS_COUNT,
        &private_key,
        sighash_type,
    )
    .unwrap();

    let mutations = [
        append_input,
        mutate_first_input,
        mutate_first_input_commitment,
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
        Err(DestinationSigError::SignatureVerificationFailed),
    );

    let mutations = [
        append_output,
        mutate_first_output,
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
    let tx = generate_signed_tx_with_input_commitments(
        &chain_config,
        &mut rng,
        &destination,
        INPUTS_COUNT,
        OUTPUTS_COUNT,
        &private_key,
        sighash_type,
    )
    .unwrap();

    {
        let tx = mutate_first_input(&mut rng, &tx);
        let inputs_count = tx.tx.inputs().len();

        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &tx.input_commitments,
                0
            ),
            Err(DestinationSigError::SignatureVerificationFailed),
        );
        for input_idx in 1..inputs_count {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input_idx],
                    &tx.input_commitments,
                    input_idx
                ),
                Ok(())
            );
        }
    }

    {
        let tx = mutate_first_input_commitment(&mut rng, &tx);
        let inputs_count = tx.tx.inputs().len();

        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &tx.input_commitments,
                0
            ),
            Err(DestinationSigError::SignatureVerificationFailed),
        );
        for input_idx in 1..inputs_count {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input_idx],
                    &tx.input_commitments,
                    input_idx
                ),
                Ok(())
            );
        }
    }

    let mutations = [
        append_input,
        remove_first_input,
        remove_middle_input,
        remove_last_input,
        append_output,
        mutate_first_output,
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
    let tx = generate_signed_tx_with_input_commitments(
        &chain_config,
        &mut rng,
        &destination,
        INPUTS_COUNT,
        OUTPUTS_COUNT,
        &private_key,
        sighash_type,
    )
    .unwrap();

    let mutations = [
        append_input,
        mutate_first_input,
        mutate_first_input_commitment,
        remove_first_input,
        remove_middle_input,
        remove_last_input,
        remove_first_output,
    ];
    for mutate in mutations.into_iter() {
        let tx = mutate(&mut rng, &tx);
        let inputs_count = tx.tx.inputs().len();
        let outputs_count = tx.tx.outputs().len();

        // If a mutation makes the number of outputs smaller than the number of inputs,
        // verifying the "extra" inputs will produce a different error.
        for input_idx in 0..std::cmp::min(inputs_count, outputs_count) {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input_idx],
                    &tx.input_commitments,
                    input_idx
                ),
                Err(DestinationSigError::SignatureVerificationFailed)
            );
        }

        // Check the extra inputs, if any.
        for input_idx in outputs_count..inputs_count {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input_idx],
                    &tx.input_commitments,
                    input_idx
                ),
                Err(DestinationSigError::InvalidInputIndex(
                    input_idx,
                    outputs_count
                ))
            );
        }

        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &tx.input_commitments,
                inputs_count
            ),
            Err(DestinationSigError::InvalidSignatureIndex(
                inputs_count,
                inputs_count
            )),
        );
    }

    let mutations = [append_output, remove_last_output];
    for mutate in mutations.into_iter() {
        let tx = mutate(&mut rng, &tx);
        let inputs_count = tx.tx.inputs().len();
        let outputs_count = tx.tx.outputs().len();

        // If a mutation makes the number of outputs smaller than the number of inputs,
        // verifying the "extra" inputs will produce a different error.
        for input_idx in 0..std::cmp::min(inputs_count, outputs_count) {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input_idx],
                    &tx.input_commitments,
                    input_idx
                ),
                Ok(())
            );
        }

        // Check the extra inputs, if any.
        for input_idx in outputs_count..inputs_count {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input_idx],
                    &tx.input_commitments,
                    input_idx
                ),
                Err(DestinationSigError::InvalidInputIndex(
                    input_idx,
                    outputs_count
                ))
            );
        }

        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &tx.input_commitments,
                inputs_count
            ),
            Err(DestinationSigError::InvalidSignatureIndex(
                inputs_count,
                inputs_count
            )),
        );
    }

    {
        let tx = mutate_first_output(&mut rng, &tx);
        let inputs_count = tx.tx.inputs().len();

        // Mutation of the first output makes signature invalid.
        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &tx.input_commitments,
                0
            ),
            Err(DestinationSigError::SignatureVerificationFailed),
        );

        for input_idx in 1..inputs_count {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input_idx],
                    &tx.input_commitments,
                    input_idx
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
                &tx.input_commitments,
                inputs_count
            ),
            Err(DestinationSigError::InvalidSignatureIndex(
                inputs_count,
                inputs_count
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
    let tx = generate_signed_tx_with_input_commitments(
        &chain_config,
        &mut rng,
        &destination,
        INPUTS_COUNT,
        OUTPUTS_COUNT,
        &private_key,
        sighash_type,
    )
    .unwrap();

    let mutations = [append_input, remove_last_input, append_output, remove_last_output];
    for mutate in mutations.into_iter() {
        let tx = mutate(&mut rng, &tx);
        let inputs_count = tx.tx.inputs().len();
        let outputs_count = tx.tx.outputs().len();

        // If a mutation makes the number of outputs smaller than the number of inputs,
        // verifying the "extra" inputs will produce a different error.
        for input_idx in 0..std::cmp::min(inputs_count, outputs_count) {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input_idx],
                    &tx.input_commitments,
                    input_idx
                ),
                Ok(()),
                "{input_idx}"
            );
        }

        // Check the extra inputs, if any.
        for input_idx in outputs_count..inputs_count {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input_idx],
                    &tx.input_commitments,
                    input_idx
                ),
                Err(DestinationSigError::InvalidInputIndex(
                    input_idx,
                    outputs_count
                ))
            );
        }

        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &tx.input_commitments,
                inputs_count
            ),
            Err(DestinationSigError::InvalidSignatureIndex(
                inputs_count,
                inputs_count
            ))
        );
    }

    let mutations = [mutate_first_input, mutate_first_input_commitment, mutate_first_output];
    for (mutation_idx, mutate) in mutations.into_iter().enumerate() {
        let tx = mutate(&mut rng, &tx);
        let inputs_count = tx.tx.inputs().len();

        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &tx.input_commitments,
                0
            ),
            Err(DestinationSigError::SignatureVerificationFailed),
            "mutation_idx = {mutation_idx}"
        );

        for input_idx in 1..inputs_count {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input_idx],
                    &tx.input_commitments,
                    input_idx
                ),
                Ok(()),
                "## {input_idx}"
            );
        }

        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &tx.input_commitments,
                inputs_count
            ),
            Err(DestinationSigError::InvalidSignatureIndex(
                inputs_count,
                inputs_count
            )),
        );
    }

    let mutations = [remove_first_input, remove_first_output];
    for mutate in mutations.into_iter() {
        let tx = mutate(&mut rng, &tx);
        let inputs_count = tx.tx.inputs().len();
        let outputs_count = tx.tx.outputs().len();

        // If a mutation makes the number of outputs smaller than the number of inputs,
        // verifying the "extra" inputs will produce a different error.
        for input_idx in 0..std::cmp::min(inputs_count, outputs_count) {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input_idx],
                    &tx.input_commitments,
                    input_idx
                ),
                Err(DestinationSigError::SignatureVerificationFailed),
                "{input_idx}"
            );
        }

        // Check the extra inputs, if any.
        for input_idx in outputs_count..inputs_count {
            assert_eq!(
                verify_signature(
                    &chain_config,
                    &destination,
                    &tx.tx,
                    &tx.tx.signatures()[input_idx],
                    &tx.input_commitments,
                    input_idx
                ),
                Err(DestinationSigError::InvalidInputIndex(
                    input_idx,
                    outputs_count
                ))
            );
        }

        assert_eq!(
            verify_signature(
                &chain_config,
                &destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &tx.input_commitments,
                inputs_count
            ),
            Err(DestinationSigError::InvalidSignatureIndex(
                inputs_count,
                inputs_count
            )),
        );
    }
}

#[track_caller]
fn check_mutations<M, R>(
    chain_config: &ChainConfig,
    rng: &mut R,
    tx: &SignedTransactionWithInputCommitments,
    destination: &Destination,
    mutations: M,
    expected: Result<(), DestinationSigError>,
) where
    R: Rng,
    M: IntoIterator<
        Item = fn(
            &mut R,
            &SignedTransactionWithInputCommitments,
        ) -> SignedTransactionWithInputCommitments,
    >,
{
    for mutate in mutations.into_iter() {
        let tx = mutate(rng, tx);
        // The number of inputs can be changed by the `mutate` function.
        let inputs_count = tx.tx.inputs().len();

        assert_eq!(
            verify_signature(
                chain_config,
                destination,
                &tx.tx,
                &tx.tx.signatures()[0],
                &tx.input_commitments,
                INVALID_INPUT_INDEX
            ),
            Err(DestinationSigError::InvalidSignatureIndex(
                INVALID_INPUT_INDEX,
                inputs_count
            ))
        );
        for input in 0..inputs_count {
            assert_eq!(
                verify_signature(
                    chain_config,
                    destination,
                    &tx.tx,
                    &tx.tx.signatures()[input],
                    &tx.input_commitments,
                    input
                ),
                expected
            );
        }
    }
}

fn append_input(
    _rng: &mut impl Rng,
    tx: &SignedTransactionWithInputCommitments,
) -> SignedTransactionWithInputCommitments {
    let mut updater = MutableTransaction::from(&tx.tx);
    updater.inputs.push(updater.inputs[0].clone());
    updater.witness.push(updater.witness[0].clone());

    let mut input_commitments = tx.input_commitments.clone();
    input_commitments.push(input_commitments[0].clone());

    SignedTransactionWithInputCommitments {
        tx: updater.generate_tx().unwrap(),
        input_commitments,
    }
}

fn mutate_first_input(
    rng: &mut impl Rng,
    tx: &SignedTransactionWithInputCommitments,
) -> SignedTransactionWithInputCommitments {
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
            OrderAccountCommand::FillOrder(id, amount) => TxInput::OrderAccountCommand(
                OrderAccountCommand::FillOrder(*id, Amount::from_atoms(amount.into_atoms() + 1)),
            ),
            OrderAccountCommand::ConcludeOrder(order_id) => {
                TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(*order_id))
            }
            OrderAccountCommand::FreezeOrder(_) => TxInput::OrderAccountCommand(
                OrderAccountCommand::FreezeOrder(OrderId::new(H256::random_using(rng))),
            ),
        },
    };
    updater.inputs[0] = mutated_input;

    SignedTransactionWithInputCommitments {
        tx: updater.generate_tx().unwrap(),
        input_commitments: tx.input_commitments.clone(),
    }
}

fn mutate_first_input_commitment(
    rng: &mut (impl Rng + CryptoRng),
    tx: &SignedTransactionWithInputCommitments,
) -> SignedTransactionWithInputCommitments {
    let mut input_commitments = tx.input_commitments.clone();
    input_commitments[0] =
        gen_different_value(&tx.input_commitments[0], || generate_input_commitment(rng));

    SignedTransactionWithInputCommitments {
        tx: tx.tx.clone(),
        input_commitments,
    }
}

fn remove_first_input(
    _rng: &mut impl Rng,
    tx: &SignedTransactionWithInputCommitments,
) -> SignedTransactionWithInputCommitments {
    let mut updater = MutableTransaction::from(&tx.tx);
    updater.inputs.remove(0);
    updater.witness.remove(0);

    let mut input_commitments = tx.input_commitments.clone();
    input_commitments.remove(0);

    SignedTransactionWithInputCommitments {
        tx: updater.generate_tx().unwrap(),
        input_commitments,
    }
}

fn remove_middle_input(
    _rng: &mut impl Rng,
    tx: &SignedTransactionWithInputCommitments,
) -> SignedTransactionWithInputCommitments {
    let mut updater = MutableTransaction::from(&tx.tx);
    assert!(updater.inputs.len() > 8);
    updater.inputs.remove(7);
    updater.witness.remove(7);

    let mut input_commitments = tx.input_commitments.clone();
    input_commitments.remove(7);

    SignedTransactionWithInputCommitments {
        tx: updater.generate_tx().unwrap(),
        input_commitments,
    }
}

fn remove_last_input(
    _rng: &mut impl Rng,
    tx: &SignedTransactionWithInputCommitments,
) -> SignedTransactionWithInputCommitments {
    let mut updater = MutableTransaction::from(&tx.tx);
    updater.inputs.pop().expect("Unexpected empty inputs");
    updater.witness.pop().expect("Unexpected empty witness");

    let mut input_commitments = tx.input_commitments.clone();
    input_commitments.pop().expect("Unexpected empty witness");

    SignedTransactionWithInputCommitments {
        tx: updater.generate_tx().unwrap(),
        input_commitments,
    }
}

fn append_output(
    _rng: &mut impl Rng,
    tx: &SignedTransactionWithInputCommitments,
) -> SignedTransactionWithInputCommitments {
    let mut updater = MutableTransaction::from(&tx.tx);
    updater.outputs.push(updater.outputs[0].clone());
    SignedTransactionWithInputCommitments {
        tx: updater.generate_tx().unwrap(),
        input_commitments: tx.input_commitments.clone(),
    }
}

// Note: this function is only called on the outcome of generate_unsigned_tx, which currently always
// produces TxOutput::Transfer outputs.
fn mutate_first_output(
    _rng: &mut impl Rng,
    tx: &SignedTransactionWithInputCommitments,
) -> SignedTransactionWithInputCommitments {
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
    SignedTransactionWithInputCommitments {
        tx: updater.generate_tx().unwrap(),
        input_commitments: tx.input_commitments.clone(),
    }
}

fn remove_first_output(
    _rng: &mut impl Rng,
    tx: &SignedTransactionWithInputCommitments,
) -> SignedTransactionWithInputCommitments {
    let mut updater = MutableTransaction::from(&tx.tx);
    updater.outputs.remove(0);
    SignedTransactionWithInputCommitments {
        tx: updater.generate_tx().unwrap(),
        input_commitments: tx.input_commitments.clone(),
    }
}

fn remove_middle_output(
    _rng: &mut impl Rng,
    tx: &SignedTransactionWithInputCommitments,
) -> SignedTransactionWithInputCommitments {
    let mut updater = MutableTransaction::from(&tx.tx);
    assert!(updater.outputs.len() > 8);
    updater.outputs.remove(7);
    SignedTransactionWithInputCommitments {
        tx: updater.generate_tx().unwrap(),
        input_commitments: tx.input_commitments.clone(),
    }
}

fn remove_last_output(
    _rng: &mut impl Rng,
    tx: &SignedTransactionWithInputCommitments,
) -> SignedTransactionWithInputCommitments {
    let mut updater = MutableTransaction::from(&tx.tx);
    updater.outputs.pop().expect("Unexpected empty outputs");
    SignedTransactionWithInputCommitments {
        tx: updater.generate_tx().unwrap(),
        input_commitments: tx.input_commitments.clone(),
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
