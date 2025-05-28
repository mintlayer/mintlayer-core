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

use std::{borrow::Cow, num::NonZeroU8};

use rstest::rstest;

use chainstate::ConnectTransactionError;
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestFramework, TransactionBuilder,
};
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        self,
        classic_multisig::ClassicMultisigChallenge,
        config::ChainType,
        output_value::OutputValue,
        signature::{
            inputsig::{
                classical_multisig::authorize_classical_multisig::AuthorizedClassicalMultisigSpend,
                standard_signature::StandardInputSignature, InputWitness,
            },
            sighash::{
                input_commitments::SighashInputCommitment, sighashtype::SigHashType, signature_hash,
            },
            DestinationSigError,
        },
        signed_transaction::SignedTransaction,
        ConsensusUpgrade, Destination, NetUpgrades, OutPointSourceId, TxInput, TxOutput,
    },
    primitives::{Amount, BlockHeight, Idable},
};
use crypto::key::{KeyKind, PrivateKey};
use randomness::{Rng, SliceRandom};
use serialization::Encode;
use test_utils::random::{gen_random_bytes, Seed};
use tx_verifier::error::{InputCheckError, ScriptError};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn signed_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (private_key, public_key) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        // The first transaction uses the `AnyoneCanSpend` output of the transaction from the
        // genesis block.
        let tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(
                        tf.chainstate.get_chain_config().genesis_block_id(),
                    ),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(100)),
                Destination::PublicKey(public_key.clone()),
            ))
            .build();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::Transaction(tx_1.transaction().get_id()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(100)),
                Destination::PublicKey(public_key.clone()),
            ))
            .build()
            .transaction()
            .clone();

        // Attempt to spend with NoSignature signature
        {
            // The second transaction has the signed input.
            let tx_2 = {
                SignedTransaction::new(tx.clone(), vec![InputWitness::NoSignature(None)])
                    .expect("invalid witness count")
            };

            let res = tf
                .make_block_builder()
                .with_transactions(vec![tx_1.clone(), tx_2])
                .build_and_process(&mut rng);

            assert_eq!(
                res.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::StateUpdateFailed(ConnectTransactionError::InputCheck(
                        InputCheckError::new(
                            0,
                            ScriptError::Signature(DestinationSigError::SignatureNotFound)
                        )
                    ))
                )
            );
        }
        // Attempt to spend with garbage signature
        {
            // The second transaction has the signed input.
            let tx_2 = {
                SignedTransaction::new(
                    tx.clone(),
                    vec![InputWitness::Standard(StandardInputSignature::new(
                        SigHashType::all(),
                        gen_random_bytes(&mut rng, 100, 200),
                    ))],
                )
                .expect("invalid witness count")
            };

            let res = tf
                .make_block_builder()
                .with_transactions(vec![tx_1.clone(), tx_2])
                .build_and_process(&mut rng);

            assert_eq!(
                res.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::StateUpdateFailed(ConnectTransactionError::InputCheck(
                        InputCheckError::new(
                            0,
                            ScriptError::Signature(DestinationSigError::InvalidSignatureEncoding)
                        )
                    ))
                )
            );
        }
        // Spend it properly with proper signature
        {
            // The second transaction has the signed input.
            let tx_2 = {
                let input_sign = StandardInputSignature::produce_uniparty_signature_for_input(
                    &private_key,
                    SigHashType::all(),
                    Destination::PublicKey(public_key),
                    &tx,
                    &[SighashInputCommitment::Utxo(Cow::Borrowed(
                        &tx_1.transaction().outputs()[0],
                    ))],
                    0,
                    &mut rng,
                )
                .unwrap();
                SignedTransaction::new(tx, vec![InputWitness::Standard(input_sign)])
                    .expect("invalid witness count")
            };

            tf.make_block_builder()
                .with_transactions(vec![tx_1, tx_2])
                .build_and_process(&mut rng)
                .unwrap();
        }
    });
}

// TODO: add more tests for signatures with errors (for all kinds of output purposes)

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn signed_classical_multisig_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let chain_config = tf.chainstate.get_chain_config().clone();

        let min_required_signatures = (rng.gen::<u8>() % 10) + 1;
        let min_required_signatures: NonZeroU8 = min_required_signatures.try_into().unwrap();
        let total_parties: u8 = (rng.gen::<u8>() % 5) + min_required_signatures.get();
        let (priv_keys, pub_keys): (Vec<_>, Vec<_>) = (0..total_parties)
            .map(|_| PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr))
            .unzip();
        let challenge =
            ClassicMultisigChallenge::new(&chain_config, min_required_signatures, pub_keys)
                .unwrap();
        challenge.is_valid(&chain_config).unwrap();

        let destination_multisig: PublicKeyHash = (&challenge).into();
        let destination = Destination::ClassicMultisig(destination_multisig);

        let key_indexes = {
            let mut key_indexes = (0..total_parties).collect::<Vec<_>>();
            key_indexes.shuffle(&mut rng);
            key_indexes
        };

        // The first transaction uses the `AnyoneCanSpend` output of the transaction from the
        // genesis block.
        let tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(100)),
                destination,
            ))
            .build();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::Transaction(tx_1.transaction().get_id()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(100)),
                Destination::AnyoneCanSpend,
            ))
            .build()
            .transaction()
            .clone();

        let authorization = {
            let mut authorization = AuthorizedClassicalMultisigSpend::new_empty(challenge);

            let sighash = signature_hash(
                SigHashType::all(),
                &tx,
                &[SighashInputCommitment::Utxo(Cow::Borrowed(&tx_1.transaction().outputs()[0]))],
                0,
            )
            .unwrap();
            let sighash = sighash.encode();

            for key_index in key_indexes.iter().take(min_required_signatures.get() as usize) {
                let signature =
                    priv_keys[*key_index as usize].sign_message(&sighash, &mut rng).unwrap();
                authorization.add_signature(*key_index, signature);
            }

            authorization
        };

        // Attempt to spend with NoSignature signature
        {
            // The second transaction has the signed input.
            let tx_2 = {
                SignedTransaction::new(tx.clone(), vec![InputWitness::NoSignature(None)])
                    .expect("invalid witness count")
            };

            let res = tf
                .make_block_builder()
                .with_transactions(vec![tx_1.clone(), tx_2])
                .build_and_process(&mut rng);

            assert_eq!(
                res.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::StateUpdateFailed(ConnectTransactionError::InputCheck(
                        InputCheckError::new(
                            0,
                            ScriptError::Signature(DestinationSigError::SignatureNotFound)
                        )
                    ))
                )
            );
        }
        // Attempt to spend with garbage signature
        {
            // The second transaction has the signed input.
            let tx_2 = {
                SignedTransaction::new(
                    tx.clone(),
                    vec![InputWitness::Standard(StandardInputSignature::new(
                        SigHashType::all(),
                        gen_random_bytes(&mut rng, 100, 200),
                    ))],
                )
                .expect("invalid witness count")
            };

            let res = tf
                .make_block_builder()
                .with_transactions(vec![tx_1.clone(), tx_2])
                .build_and_process(&mut rng);

            assert_eq!(
                res.unwrap_err(),
                chainstate::ChainstateError::ProcessBlockError(
                    chainstate::BlockError::StateUpdateFailed(ConnectTransactionError::InputCheck(
                        InputCheckError::new(
                            0,
                            ScriptError::Signature(DestinationSigError::InvalidSignatureEncoding)
                        )
                    ))
                )
            );
        }
        {
            // The second transaction has the signed input.
            let tx_2 = {
                let input_sign =
                    StandardInputSignature::produce_classical_multisig_signature_for_input(
                        &chain_config,
                        &authorization,
                        SigHashType::all(),
                        &tx,
                        &[SighashInputCommitment::Utxo(Cow::Borrowed(
                            &tx_1.transaction().outputs()[0],
                        ))],
                        0,
                    )
                    .unwrap();
                SignedTransaction::new(tx, vec![InputWitness::Standard(input_sign)])
                    .expect("invalid witness count")
            };

            tf.make_block_builder()
                .with_transactions(vec![tx_1, tx_2])
                .build_and_process(&mut rng)
                .unwrap();
        }
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn signed_classical_multisig_tx_missing_sigs(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let chain_config = tf.chainstate.get_chain_config().clone();

        let min_required_signatures = (rng.gen::<u8>() % 10) + 1;
        let min_required_signatures: NonZeroU8 = min_required_signatures.try_into().unwrap();
        let total_parties: u8 = (rng.gen::<u8>() % 5) + min_required_signatures.get();
        let (priv_keys, pub_keys): (Vec<_>, Vec<_>) = (0..total_parties)
            .map(|_| PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr))
            .unzip();
        let challenge =
            ClassicMultisigChallenge::new(&chain_config, min_required_signatures, pub_keys)
                .unwrap();
        challenge.is_valid(&chain_config).unwrap();

        let destination_multisig: PublicKeyHash = (&challenge).into();
        let destination = Destination::ClassicMultisig(destination_multisig);

        let key_indexes = {
            let mut key_indexes = (0..total_parties).collect::<Vec<_>>();
            key_indexes.shuffle(&mut rng);
            key_indexes
        };

        // The first transaction uses the `AnyoneCanSpend` output of the transaction from the
        // genesis block.
        let tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(100)),
                destination,
            ))
            .build();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::Transaction(tx_1.transaction().get_id()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(100)),
                Destination::AnyoneCanSpend,
            ))
            .build()
            .transaction()
            .clone();

        let mut authorization = AuthorizedClassicalMultisigSpend::new_empty(challenge);

        // Put all authorizations in this vector (starting from the empty one),
        // then take the last two where the last one is fully signed,
        // and the one before has a missing signature
        // So: Element number N has N signatures
        let mut authrorizations = vec![authorization.clone()];

        let sighash = signature_hash(
            SigHashType::all(),
            &tx,
            &[SighashInputCommitment::Utxo(Cow::Borrowed(&tx_1.transaction().outputs()[0]))],
            0,
        )
        .unwrap();
        let sighash = sighash.encode();

        for key_index in key_indexes.iter().take(min_required_signatures.get() as usize) {
            let signature =
                priv_keys[*key_index as usize].sign_message(&sighash, &mut rng).unwrap();
            authorization.add_signature(*key_index, signature);
            authrorizations.push(authorization.clone());
        }

        for authorization_potentially_missing_sigs in authrorizations {
            // The second transaction has the signed input.
            let tx_2 = {
                let input_sign =
                    StandardInputSignature::produce_classical_multisig_signature_for_input(
                        &chain_config,
                        &authorization,
                        SigHashType::all(),
                        &tx,
                        &[SighashInputCommitment::Utxo(Cow::Borrowed(
                            &tx_1.transaction().outputs()[0],
                        ))],
                        0,
                    )
                    .unwrap();

                // Manually construct a StandardInputSignature with the (potentially) missing signature from the authorization
                let input_sign_with_missing_sig = StandardInputSignature::new(
                    input_sign.sighash_type(),
                    authorization_potentially_missing_sigs.encode(),
                );

                SignedTransaction::new(
                    tx.clone(),
                    vec![InputWitness::Standard(input_sign_with_missing_sig)],
                )
                .expect("invalid witness count")
            };

            let process_result = tf
                .make_block_builder()
                .with_transactions(vec![tx_1.clone(), tx_2.clone()])
                .build_and_process(&mut rng);

            if authorization_potentially_missing_sigs.available_signatures_count()
                < min_required_signatures.get() as usize
            {
                let process_error = process_result.unwrap_err();

                // If a signature is missing, we get an error
                assert_eq!(
                    process_error,
                    chainstate::ChainstateError::ProcessBlockError(
                        chainstate::BlockError::StateUpdateFailed(
                            ConnectTransactionError::InputCheck(InputCheckError::new(
                                0,
                                ScriptError::Signature(
                                    DestinationSigError::IncompleteClassicalMultisigSignature(
                                        min_required_signatures.get(),
                                        authorization_potentially_missing_sigs
                                            .available_signatures_count()
                                            as u8
                                    )
                                )
                            ))
                        )
                    )
                );
            } else {
                // if signatures are complete, we get no error
                process_result.unwrap();
            }
        }
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), true)]
#[case(Seed::from_entropy(), false)]
fn too_large_no_sig_data(#[case] seed: Seed, #[case] valid_size: bool) {
    utils::concurrency::model(move || {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let chain_config = tf.chainstate.get_chain_config().clone();

        let max_no_sig_data_size =
            tf.chainstate.get_chain_config().data_in_no_signature_witness_max_size();

        let data_size = if valid_size {
            max_no_sig_data_size
        } else {
            max_no_sig_data_size + 1
        };

        {
            let data: Vec<u8> = (0..data_size).map(|_| rng.gen::<u8>()).collect();

            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(
                        OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                        0,
                    ),
                    InputWitness::NoSignature(Some(data)),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(100)),
                    anyonecanspend_address(),
                ))
                .build();
            let tx_id = tx.transaction().get_id();

            if valid_size {
                let process_result =
                    tf.make_block_builder().with_transactions(vec![tx]).build_and_process(&mut rng);

                process_result.unwrap().unwrap();
            } else {
                let process_result =
                    tf.make_block_builder().with_transactions(vec![tx]).build_and_process(&mut rng);

                assert_eq!(
                    process_result.unwrap_err(),
                    chainstate::ChainstateError::ProcessBlockError(
                        chainstate::BlockError::CheckBlockFailed(
                            chainstate::CheckBlockError::CheckTransactionFailed(
                                chainstate::CheckBlockTransactionsError::CheckTransactionError(
                                    tx_verifier::CheckTransactionError::NoSignatureDataSizeTooLarge(
                                        max_no_sig_data_size + 1,
                                        max_no_sig_data_size,
                                        tx_id
                                    )
                                )
                            )
                        )
                    )
                );
            }
        }
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), true, true)]
#[case(Seed::from_entropy(), true, false)]
#[case(Seed::from_entropy(), false, true)]
#[case(Seed::from_entropy(), false, false)]
fn no_sig_data_not_allowed(
    #[case] seed: Seed,
    #[case] data_allowed: bool,
    #[case] data_provided: bool,
) {
    utils::concurrency::model(move || {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let chain_config = chain::config::Builder::new(ChainType::Regtest)
            .data_in_no_signature_witness_allowed(data_allowed)
            .consensus_upgrades(
                NetUpgrades::initialize(vec![(
                    BlockHeight::zero(),
                    ConsensusUpgrade::IgnoreConsensus,
                )])
                .unwrap(),
            )
            .genesis_unittest(Destination::AnyoneCanSpend)
            .build();

        let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

        let chain_config = tf.chainstate.get_chain_config().clone();

        let max_no_sig_data_size =
            tf.chainstate.get_chain_config().data_in_no_signature_witness_max_size();

        let data: Vec<u8> = (0..max_no_sig_data_size).map(|_| rng.gen::<u8>()).collect();
        let data = if data_provided { Some(data) } else { None };

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                    0,
                ),
                InputWitness::NoSignature(data),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(100)),
                anyonecanspend_address(),
            ))
            .build();

        let block = tf.make_block_builder().with_transactions(vec![tx.clone()]).build(&mut rng);
        let process_result = tf.process_block(block, chainstate::BlockSource::Local);

        match (data_allowed, data_provided) {
            (true, true | false) | (false, false) => {
                assert!(process_result.is_ok())
            }
            (false, true) => {
                // it's only an error if data is not allowed but was actually provided
                assert_eq!(
                    process_result.unwrap_err(),
                    chainstate::ChainstateError::ProcessBlockError(
                        chainstate::BlockError::CheckBlockFailed(
                            chainstate::CheckBlockError::CheckTransactionFailed(
                                chainstate::CheckBlockTransactionsError::CheckTransactionError(
                                    tx_verifier::CheckTransactionError::NoSignatureDataNotAllowed(
                                        tx.transaction().get_id(),
                                    )
                                )
                            )
                        )
                    )
                );
            }
        };
    });
}

// Genesis on Mainnet is signed. Try to spend it with no signature.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_to_spend_with_no_signature_on_mainnet(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let chain_config = chain::config::Builder::new(ChainType::Mainnet)
            .consensus_upgrades(
                NetUpgrades::initialize(vec![(
                    BlockHeight::zero(),
                    ConsensusUpgrade::IgnoreConsensus,
                )])
                .unwrap(),
            )
            .build();

        let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

        let chain_config = tf.chainstate.get_chain_config().clone().clone();

        // no signature
        let block = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(
                            OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                            0,
                        ),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(100)),
                        anyonecanspend_address(),
                    ))
                    .build(),
            )
            .build(&mut rng);

        let process_result = tf.process_block(block.clone(), chainstate::BlockSource::Local);

        assert_eq!(
            process_result.unwrap_err(),
            chainstate::ChainstateError::ProcessBlockError(
                chainstate::BlockError::StateUpdateFailed(ConnectTransactionError::InputCheck(
                    InputCheckError::new(
                        0,
                        ScriptError::Signature(DestinationSigError::SignatureNotFound)
                    )
                ))
            )
        );

        // no signature with data
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(100)),
                anyonecanspend_address(),
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let block = tf.make_block_builder().add_transaction(tx).build(&mut rng);

        let process_result = tf.process_block(block.clone(), chainstate::BlockSource::Local);

        assert_eq!(
            process_result.unwrap_err(),
            chainstate::ChainstateError::ProcessBlockError(
                chainstate::BlockError::CheckBlockFailed(
                    chainstate::CheckBlockError::CheckTransactionFailed(
                        chainstate::CheckBlockTransactionsError::CheckTransactionError(
                            tx_verifier::CheckTransactionError::NoSignatureDataNotAllowed(tx_id)
                        )
                    )
                )
            )
        );
    });
}
