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

use common::address::pubkeyhash::PublicKeyHash;
use common::chain::classic_multisig::ClassicMultisigChallenge;
use common::chain::signature::inputsig::classical_multisig::authorize_classical_multisig::AuthorizedClassicalMultisigSpend;
use common::chain::signed_transaction::SignedTransaction;
use common::primitives::Idable;
use common::{
    chain::{
        signature::{inputsig::InputWitness, sighashtype::SigHashType},
        tokens::OutputValue,
        Destination, OutPointSourceId, OutputPurpose, TxInput, TxOutput,
    },
    primitives::Amount,
};
use crypto::key::{KeyKind, PrivateKey};

use chainstate_test_framework::TestFramework;
use chainstate_test_framework::TransactionBuilder;
use common::chain::signature::inputsig::standard_signature::StandardInputSignature;
use common::chain::signature::signature_hash;
use crypto::random::{Rng, SliceRandom};
use rstest::rstest;
use serialization::Encode;
use std::num::NonZeroU8;
use test_utils::random::Seed;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn signed_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (private_key, public_key) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);

        // The first transaction uses the `AnyoneCanSpend` output of the transaction from the
        // genesis block.
        let tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(
                        tf.chainstate.get_chain_config().genesis_block_id(),
                    ),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(100)),
                OutputPurpose::Transfer(Destination::PublicKey(public_key.clone())),
            ))
            .build();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::Transaction(tx_1.transaction().get_id()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(100)),
                OutputPurpose::Transfer(Destination::PublicKey(public_key.clone())),
            ))
            .build()
            .transaction()
            .clone();

        // The second transaction has the signed input.
        let tx_2 = {
            let input_sign = StandardInputSignature::produce_uniparty_signature_for_input(
                &private_key,
                SigHashType::try_from(SigHashType::ALL).unwrap(),
                Destination::PublicKey(public_key),
                &tx,
                0,
            )
            .unwrap();
            SignedTransaction::new(tx, vec![InputWitness::Standard(input_sign)])
                .expect("invalid witness count")
        };

        tf.make_block_builder()
            .with_transactions(vec![tx_1, tx_2])
            .build_and_process()
            .unwrap();
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
            .into_iter()
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
                TxInput::new(
                    OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(100)),
                OutputPurpose::Transfer(destination),
            ))
            .build();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::Transaction(tx_1.transaction().get_id()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(100)),
                OutputPurpose::Transfer(Destination::AnyoneCanSpend),
            ))
            .build()
            .transaction()
            .clone();

        let authorization = {
            let mut authorization = AuthorizedClassicalMultisigSpend::new_empty(challenge);

            let sighash =
                signature_hash(SigHashType::try_from(SigHashType::ALL).unwrap(), &tx, 0).unwrap();
            let sighash = sighash.encode();

            for key_index in key_indexes.iter().take(min_required_signatures.get() as usize) {
                let signature = priv_keys[*key_index as usize].sign_message(&sighash).unwrap();
                authorization.add_signature(*key_index, signature);
            }

            authorization
        };

        // The second transaction has the signed input.
        let tx_2 = {
            let input_sign =
                StandardInputSignature::produce_classical_multisig_signature_for_input(
                    &chain_config,
                    &authorization,
                    SigHashType::try_from(SigHashType::ALL).unwrap(),
                    &tx,
                    0,
                )
                .unwrap();
            SignedTransaction::new(tx, vec![InputWitness::Standard(input_sign)])
                .expect("invalid witness count")
        };

        tf.make_block_builder()
            .with_transactions(vec![tx_1, tx_2])
            .build_and_process()
            .unwrap();
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
            .into_iter()
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
                TxInput::new(
                    OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(100)),
                OutputPurpose::Transfer(destination),
            ))
            .build();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::Transaction(tx_1.transaction().get_id()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(100)),
                OutputPurpose::Transfer(Destination::AnyoneCanSpend),
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

        let sighash =
            signature_hash(SigHashType::try_from(SigHashType::ALL).unwrap(), &tx, 0).unwrap();
        let sighash = sighash.encode();

        for key_index in key_indexes.iter().take(min_required_signatures.get() as usize) {
            let signature = priv_keys[*key_index as usize].sign_message(&sighash).unwrap();
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
                        SigHashType::try_from(SigHashType::ALL).unwrap(),
                        &tx,
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
                .build_and_process();

            if authorization_potentially_missing_sigs.available_signatures_count()
                < min_required_signatures.get() as usize
            {
                let process_error = process_result.unwrap_err();

                // If a signature is missing, we get an error
                assert_eq!(
                    process_error,
                    chainstate::ChainstateError::ProcessBlockError(
                        chainstate::BlockError::StateUpdateFailed(
                            chainstate::ConnectTransactionError::SignatureVerificationFailed(
                                common::chain::signature::TransactionSigError::IncompleteClassicalMultisigSignature
                            )
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
