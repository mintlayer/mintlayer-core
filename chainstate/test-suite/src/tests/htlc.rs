// Copyright (c) 2024 RBB S.r.l
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

use std::borrow::Cow;

use chainstate::{BlockError, ChainstateError, ConnectTransactionError};
use chainstate_test_framework::{TestFramework, TransactionBuilder};
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        classic_multisig::ClassicMultisigChallenge,
        htlc::{HashedTimelockContract, HtlcSecret, HtlcSecretHash},
        make_token_id,
        output_value::OutputValue,
        signature::{
            inputsig::{
                authorize_hashed_timelock_contract_spend::AuthorizedHashedTimelockContractSpend,
                classical_multisig::authorize_classical_multisig::AuthorizedClassicalMultisigSpend,
                htlc::{
                    produce_classical_multisig_signature_for_htlc_input,
                    produce_uniparty_signature_for_htlc_input,
                },
                standard_signature::StandardInputSignature,
            },
            sighash::{
                input_commitments::SighashInputCommitment, sighashtype::SigHashType, signature_hash,
            },
            DestinationSigError,
        },
        signed_transaction::SignedTransaction,
        timelock::OutputTimeLock,
        tokens::{TokenData, TokenIssuance, TokenTransfer},
        AccountCommand, AccountNonce, ChainConfig, ChainstateUpgradeBuilder, Destination,
        HtlcActivated, TokenIssuanceVersion, TxInput, TxOutput,
    },
    primitives::{Amount, Idable},
};
use crypto::key::{KeyKind, PrivateKey, PublicKey};
use randomness::CryptoRng;
use serialization::Encode;
use test_utils::nft_utils::{random_token_issuance, random_token_issuance_v1};
use tx_verifier::{
    error::{InputCheckError, TranslationError},
    input_check::HashlockError,
};

use super::*;

struct TestFixture {
    alice_sk: PrivateKey,
    bob_sk: PrivateKey,
    secret: HtlcSecret,
}

impl TestFixture {
    fn new(rng: &mut (impl Rng + CryptoRng)) -> Self {
        let secret = HtlcSecret::new_from_rng(rng);

        let (alice_sk, _) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
        let (bob_sk, _) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);

        Self {
            alice_sk,
            bob_sk,
            secret,
        }
    }

    fn create_htlc(
        &self,
        chain_config: &ChainConfig,
    ) -> (HashedTimelockContract, ClassicMultisigChallenge) {
        let alice_pk = PublicKey::from_private_key(&self.alice_sk);
        let bob_pk = PublicKey::from_private_key(&self.bob_sk);

        let refund_challenge = ClassicMultisigChallenge::new(
            chain_config,
            utils::const_nz_u8!(2),
            vec![alice_pk.clone(), bob_pk.clone()],
        )
        .unwrap();
        let destination_multisig: PublicKeyHash = (&refund_challenge).into();

        let htlc = HashedTimelockContract {
            secret_hash: self.secret.hash(),
            spend_key: Destination::PublicKeyHash((&bob_pk).into()),
            refund_timelock: OutputTimeLock::ForSeconds(200),
            refund_key: Destination::ClassicMultisig(destination_multisig),
        };
        (htlc, refund_challenge)
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_htlc_with_secret(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let chain_config = tf.chainstate.get_chain_config().clone();

        let test_fixture = TestFixture::new(&mut rng);

        let (htlc, _) = test_fixture.create_htlc(&chain_config);
        let tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(chain_config.genesis_block_id().into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Htlc(
                OutputValue::Coin(Amount::from_atoms(100)),
                Box::new(htlc),
            ))
            .build();
        let tx_1_id = tx_1.transaction().get_id();

        tf.make_block_builder()
            .add_transaction(tx_1.clone())
            .build_and_process(&mut rng)
            .unwrap();

        // Alice can't spend the output even though she knows the secret
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(tx_1_id.into(), 0),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(100)),
                    Destination::AnyoneCanSpend,
                ))
                .build()
                .take_transaction();

            let input_sign = produce_uniparty_signature_for_htlc_input(
                &test_fixture.alice_sk,
                SigHashType::all(),
                Destination::PublicKeyHash(
                    (&PublicKey::from_private_key(&test_fixture.alice_sk)).into(),
                ),
                &tx,
                &[SighashInputCommitment::Utxo(Cow::Borrowed(&tx_1.transaction().outputs()[0]))],
                0,
                test_fixture.secret.clone(),
                &mut rng,
            )
            .unwrap();

            let result = tf
                .make_block_builder()
                .add_transaction(
                    SignedTransaction::new(tx, vec![InputWitness::Standard(input_sign)]).unwrap(),
                )
                .build_and_process(&mut rng);
            assert_eq!(
                result.unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::InputCheck(InputCheckError::new(
                        0,
                        tx_verifier::error::ScriptError::Signature(
                            DestinationSigError::PublicKeyToHashMismatch
                        )
                    ))
                ))
            );
        }

        // Bob can't spend the output without the secret
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(tx_1_id.into(), 0),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(100)),
                    Destination::AnyoneCanSpend,
                ))
                .build()
                .take_transaction();

            let input_sign = StandardInputSignature::produce_uniparty_signature_for_input(
                &test_fixture.bob_sk,
                SigHashType::all(),
                Destination::PublicKeyHash(
                    (&PublicKey::from_private_key(&test_fixture.bob_sk)).into(),
                ),
                &tx,
                &[SighashInputCommitment::Utxo(Cow::Borrowed(&tx_1.transaction().outputs()[0]))],
                0,
                &mut rng,
            )
            .unwrap();

            let result = tf
                .make_block_builder()
                .add_transaction(
                    SignedTransaction::new(tx, vec![InputWitness::Standard(input_sign)]).unwrap(),
                )
                .build_and_process(&mut rng);
            assert_eq!(
                result.unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::InputCheck(InputCheckError::new(
                        0,
                        TranslationError::SignatureError(
                            DestinationSigError::InvalidSignatureEncoding
                        )
                    ))
                ))
            );
        }

        // Bob can't spend the output with random secret
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(tx_1_id.into(), 0),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(100)),
                    Destination::AnyoneCanSpend,
                ))
                .build()
                .take_transaction();

            let random_secret = HtlcSecret::new_from_rng(&mut rng);

            let input_sign = produce_uniparty_signature_for_htlc_input(
                &test_fixture.bob_sk,
                SigHashType::all(),
                Destination::PublicKeyHash(
                    (&PublicKey::from_private_key(&test_fixture.bob_sk)).into(),
                ),
                &tx,
                &[SighashInputCommitment::Utxo(Cow::Borrowed(&tx_1.transaction().outputs()[0]))],
                0,
                random_secret,
                &mut rng,
            )
            .unwrap();

            let result = tf
                .make_block_builder()
                .add_transaction(
                    SignedTransaction::new(tx, vec![InputWitness::Standard(input_sign)]).unwrap(),
                )
                .build_and_process(&mut rng);
            assert_eq!(
                result.unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::InputCheck(InputCheckError::new(
                        0,
                        tx_verifier::error::ScriptError::Hashlock(HashlockError::HashMismatch)
                    ))
                ))
            );
        }

        // Success case
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tx_1_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(100)),
                Destination::AnyoneCanSpend,
            ))
            .build()
            .take_transaction();

        let input_sign = produce_uniparty_signature_for_htlc_input(
            &test_fixture.bob_sk,
            SigHashType::all(),
            Destination::PublicKeyHash((&PublicKey::from_private_key(&test_fixture.bob_sk)).into()),
            &tx,
            &[SighashInputCommitment::Utxo(Cow::Borrowed(&tx_1.transaction().outputs()[0]))],
            0,
            test_fixture.secret,
            &mut rng,
        )
        .unwrap();

        tf.make_block_builder()
            .add_transaction(
                SignedTransaction::new(tx, vec![InputWitness::Standard(input_sign)]).unwrap(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn refund_htlc(#[case] seed: Seed) {
    use tx_verifier::error::TimelockError;

    utils::concurrency::model(move || {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let chain_config = tf.chainstate.get_chain_config().clone();

        let test_fixture = TestFixture::new(&mut rng);

        let (htlc, refund_challenge) = test_fixture.create_htlc(&chain_config);
        let tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(chain_config.genesis_block_id().into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Htlc(
                OutputValue::Coin(Amount::from_atoms(100)),
                Box::new(htlc),
            ))
            .build();
        let tx_1_id = tx_1.transaction().get_id();

        tf.make_block_builder()
            .add_transaction(tx_1.clone())
            .build_and_process(&mut rng)
            .unwrap();

        // Refund can't be spent until timelock is passed
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(tx_1_id.into(), 0),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(100)),
                    Destination::AnyoneCanSpend,
                ))
                .build()
                .take_transaction();

            let authorization = {
                let mut authorization =
                    AuthorizedClassicalMultisigSpend::new_empty(refund_challenge.clone());

                let sighash = signature_hash(
                    SigHashType::all(),
                    &tx,
                    &[SighashInputCommitment::Utxo(Cow::Borrowed(
                        &tx_1.transaction().outputs()[0],
                    ))],
                    0,
                )
                .unwrap();
                let sighash = sighash.encode();

                let signature = test_fixture.alice_sk.sign_message(&sighash, &mut rng).unwrap();
                authorization.add_signature(0, signature);
                let signature = test_fixture.bob_sk.sign_message(&sighash, &mut rng).unwrap();
                authorization.add_signature(1, signature);

                authorization
            };

            let input_sign = produce_classical_multisig_signature_for_htlc_input(
                &chain_config,
                &authorization,
                SigHashType::all(),
                &tx,
                &[SighashInputCommitment::Utxo(Cow::Borrowed(&tx_1.transaction().outputs()[0]))],
                0,
            )
            .unwrap();

            let result = tf
                .make_block_builder()
                .add_transaction(
                    SignedTransaction::new(tx, vec![InputWitness::Standard(input_sign)]).unwrap(),
                )
                .build_and_process(&mut rng);
            let best_block_timestamp = tf.best_block_index().block_timestamp();
            assert_eq!(
                result.unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::InputCheck(InputCheckError::new(
                        0,
                        tx_verifier::error::ScriptError::Timelock(TimelockError::TimestampLocked(
                            best_block_timestamp,
                            best_block_timestamp.add_int_seconds(200).unwrap(),
                        ))
                    ))
                ))
            );
        }

        tf.progress_time_seconds_since_epoch(200);
        // Produce empty blocks to move MTP forward
        tf.make_block_builder().build_and_process(&mut rng).unwrap();
        tf.make_block_builder().build_and_process(&mut rng).unwrap();

        // Alice can't spend output alone
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(tx_1_id.into(), 0),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(100)),
                    Destination::AnyoneCanSpend,
                ))
                .build()
                .take_transaction();

            let authorization = {
                let mut authorization =
                    AuthorizedClassicalMultisigSpend::new_empty(refund_challenge.clone());

                let sighash = signature_hash(
                    SigHashType::all(),
                    &tx,
                    &[SighashInputCommitment::Utxo(Cow::Borrowed(
                        &tx_1.transaction().outputs()[0],
                    ))],
                    0,
                )
                .unwrap();
                let sighash = sighash.encode();

                let signature = test_fixture.alice_sk.sign_message(&sighash, &mut rng).unwrap();
                authorization.add_signature(0, signature);

                AuthorizedHashedTimelockContractSpend::Multisig(authorization.encode())
            };

            let input_sign =
                StandardInputSignature::new(SigHashType::all(), authorization.encode());

            let result = tf
                .make_block_builder()
                .add_transaction(
                    SignedTransaction::new(tx, vec![InputWitness::Standard(input_sign)]).unwrap(),
                )
                .build_and_process(&mut rng);
            assert_eq!(
                result.unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::InputCheck(InputCheckError::new(
                        0,
                        tx_verifier::error::ScriptError::Signature(
                            DestinationSigError::IncompleteClassicalMultisigSignature(2, 1)
                        )
                    ))
                ))
            );
        }

        // Bob can't spend output alone
        {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::from_utxo(tx_1_id.into(), 0),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(100)),
                    Destination::AnyoneCanSpend,
                ))
                .build()
                .take_transaction();

            let authorization = {
                let mut authorization =
                    AuthorizedClassicalMultisigSpend::new_empty(refund_challenge.clone());

                let sighash = signature_hash(
                    SigHashType::all(),
                    &tx,
                    &[SighashInputCommitment::Utxo(Cow::Borrowed(
                        &tx_1.transaction().outputs()[0],
                    ))],
                    0,
                )
                .unwrap();
                let sighash = sighash.encode();

                let signature = test_fixture.bob_sk.sign_message(&sighash, &mut rng).unwrap();
                authorization.add_signature(1, signature);

                AuthorizedHashedTimelockContractSpend::Multisig(authorization.encode())
            };

            let input_sign =
                StandardInputSignature::new(SigHashType::all(), authorization.encode());

            let result = tf
                .make_block_builder()
                .add_transaction(
                    SignedTransaction::new(tx, vec![InputWitness::Standard(input_sign)]).unwrap(),
                )
                .build_and_process(&mut rng);
            assert_eq!(
                result.unwrap_err(),
                ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                    ConnectTransactionError::InputCheck(InputCheckError::new(
                        0,
                        tx_verifier::error::ScriptError::Signature(
                            DestinationSigError::IncompleteClassicalMultisigSignature(2, 1)
                        )
                    ))
                ))
            );
        }

        // Success case
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tx_1_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(100)),
                Destination::AnyoneCanSpend,
            ))
            .build()
            .take_transaction();

        let authorization = {
            let mut authorization = AuthorizedClassicalMultisigSpend::new_empty(refund_challenge);

            let sighash = signature_hash(
                SigHashType::all(),
                &tx,
                &[SighashInputCommitment::Utxo(Cow::Borrowed(&tx_1.transaction().outputs()[0]))],
                0,
            )
            .unwrap();
            let sighash = sighash.encode();

            let signature = test_fixture.alice_sk.sign_message(&sighash, &mut rng).unwrap();
            authorization.add_signature(0, signature);
            let signature = test_fixture.bob_sk.sign_message(&sighash, &mut rng).unwrap();
            authorization.add_signature(1, signature);

            authorization
        };

        let input_sign = produce_classical_multisig_signature_for_htlc_input(
            &chain_config,
            &authorization,
            SigHashType::all(),
            &tx,
            &[SighashInputCommitment::Utxo(Cow::Borrowed(&tx_1.transaction().outputs()[0]))],
            0,
        )
        .unwrap();

        tf.make_block_builder()
            .add_transaction(
                SignedTransaction::new(tx, vec![InputWitness::Standard(input_sign)]).unwrap(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn fork_activation(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        // activate htlc at height 2
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![
                            (
                                BlockHeight::zero(),
                                ChainstateUpgradeBuilder::latest()
                                    .htlc_activated(HtlcActivated::No)
                                    .build(),
                            ),
                            (
                                BlockHeight::new(2),
                                ChainstateUpgradeBuilder::latest()
                                    .htlc_activated(HtlcActivated::Yes)
                                    .build(),
                            ),
                        ])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();
        let chain_config = tf.chainstate.get_chain_config().clone();

        let htlc = HashedTimelockContract {
            secret_hash: HtlcSecretHash::zero(),
            spend_key: Destination::AnyoneCanSpend,
            refund_timelock: OutputTimeLock::ForSeconds(200),
            refund_key: Destination::AnyoneCanSpend,
        };

        // Try to produce htlc output before fork activation, check an error
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(chain_config.genesis_block_id().into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Htlc(
                        OutputValue::Coin(Amount::from_atoms(100)),
                        Box::new(htlc.clone()),
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                chainstate::CheckBlockError::CheckTransactionFailed(
                    chainstate::CheckBlockTransactionsError::CheckTransactionError(
                        tx_verifier::CheckTransactionError::HtlcsAreNotActivated
                    )
                )
            ))
        );

        // produce an empty block
        tf.make_block_builder().build_and_process(&mut rng).unwrap();

        // now it should be possible to use htlc output
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(chain_config.genesis_block_id().into(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Htlc(
                        OutputValue::Coin(Amount::from_atoms(100)),
                        Box::new(htlc),
                    ))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_tokens(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        // deprecate tokens v0 at height 2
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![
                            (
                                BlockHeight::zero(),
                                ChainstateUpgradeBuilder::latest()
                                    .token_issuance_version(TokenIssuanceVersion::V0)
                                    .build(),
                            ),
                            (
                                BlockHeight::new(2),
                                ChainstateUpgradeBuilder::latest()
                                    .token_issuance_version(TokenIssuanceVersion::V1)
                                    .build(),
                            ),
                        ])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();
        let chain_config = tf.chainstate.get_chain_config().clone();
        let token_issuance_fee = tf.chainstate.get_chain_config().fungible_token_issuance_fee();
        let token_mint_fee =
            tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::new(0));

        let test_fixture = TestFixture::new(&mut rng);
        let (htlc, _) = test_fixture.create_htlc(&chain_config);

        // issue token v0
        let token_v0_issuance_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(chain_config.genesis_block_id().into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                random_token_issuance(&chain_config, &mut rng).into(),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin((token_issuance_fee + token_mint_fee).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let token_v0_id = make_token_id(
            &chain_config,
            tf.next_block_height(),
            token_v0_issuance_tx.inputs(),
        )
        .unwrap();
        let token_v0_issuance_tx_id = token_v0_issuance_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(token_v0_issuance_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // try to produce htlc output with tokens v0, check an error
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(token_v0_issuance_tx_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Htlc(
                OutputValue::TokenV0(Box::new(TokenData::TokenTransfer(TokenTransfer {
                    token_id: token_v0_id,
                    amount: Amount::from_atoms(1),
                }))),
                Box::new(htlc.clone()),
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                chainstate::CheckBlockError::CheckTransactionFailed(
                    chainstate::CheckBlockTransactionsError::CheckTransactionError(
                        tx_verifier::CheckTransactionError::DeprecatedTokenOperationVersion(
                            TokenIssuanceVersion::V0,
                            tx_id,
                        )
                    )
                )
            ))
        );

        // issue a token v1
        let token_v1_issuance_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(token_v0_issuance_tx_id.into(), 2),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
                random_token_issuance_v1(&chain_config, Destination::AnyoneCanSpend, &mut rng),
            ))))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(token_mint_fee),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let token_v1_id = make_token_id(
            &chain_config,
            tf.next_block_height(),
            token_v1_issuance_tx.inputs(),
        )
        .unwrap();
        let token_v1_issuance_tx_id = token_v1_issuance_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(token_v1_issuance_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // mint v1 tokens and lock them with htlc output
        let amount_to_mint = Amount::from_atoms(1);
        let mint_token_v1_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::MintTokens(token_v1_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(token_v1_issuance_tx_id.into(), 1),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Htlc(
                OutputValue::TokenV1(token_v1_id, amount_to_mint),
                Box::new(htlc),
            ))
            .build();
        let mint_token_v1_tx_id = mint_token_v1_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(mint_token_v1_tx.clone())
            .build_and_process(&mut rng)
            .unwrap();

        // Spend tokens from htlc
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(mint_token_v1_tx_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_v1_id, amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
            .build()
            .take_transaction();

        let input_sign = produce_uniparty_signature_for_htlc_input(
            &test_fixture.bob_sk,
            SigHashType::all(),
            Destination::PublicKeyHash((&PublicKey::from_private_key(&test_fixture.bob_sk)).into()),
            &tx,
            &[SighashInputCommitment::Utxo(Cow::Borrowed(
                &mint_token_v1_tx.transaction().outputs()[0],
            ))],
            0,
            test_fixture.secret,
            &mut rng,
        )
        .unwrap();

        tf.make_block_builder()
            .add_transaction(
                SignedTransaction::new(tx, vec![InputWitness::Standard(input_sign)]).unwrap(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    });
}
