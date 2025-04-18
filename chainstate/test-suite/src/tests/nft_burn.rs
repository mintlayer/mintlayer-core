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

use rstest::rstest;

use chainstate::{BlockError, ChainstateError, ConnectTransactionError};
use chainstate_test_framework::{TestFramework, TransactionBuilder};
use common::{
    chain::{
        output_value::OutputValue, signature::inputsig::InputWitness, tokens::make_token_id,
        ChainstateUpgradeBuilder, Destination, OutPointSourceId, TokenIssuanceVersion, TxInput,
        TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, CoinOrTokenId, Idable},
};
use randomness::Rng;
use test_utils::{
    nft_utils::random_nft_issuance,
    random::{make_seedable_rng, Seed},
};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_burn_invalid_amount(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let token_id =
            make_token_id(&[TxInput::from_utxo(genesis_outpoint_id.clone(), 0)]).unwrap();

        let chain_config = tf.chainstate.get_chain_config();
        let token_min_issuance_fee = chain_config.nft_issuance_fee(BlockHeight::zero());

        // Issuance
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_outpoint_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(random_nft_issuance(chain_config, &mut rng).into()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let token_id = make_token_id(block.transactions()[0].transaction().inputs()).unwrap();

        // Burn more NFT than we have
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(issuance_outpoint_id.clone(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Burn(OutputValue::TokenV1(
                token_id,
                Amount::from_atoms(rng.gen_range(2..123)),
            )))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::TokenId(token_id)
                    ),
                    tx_id.into()
                ))
            )
        );

        // Burn zero NFT
        let _ = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Burn(OutputValue::TokenV1(token_id, Amount::ZERO)))
                    .build(),
            )
            .build_and_process(&mut rng)
            .unwrap();
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_burn_valid_case(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let token_id =
            make_token_id(&[TxInput::from_utxo(genesis_outpoint_id.clone(), 0)]).unwrap();

        let chain_config = tf.chainstate.get_chain_config();
        let token_min_issuance_fee = chain_config.nft_issuance_fee(BlockHeight::zero());

        // Issuance
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_outpoint_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(random_nft_issuance(chain_config, &mut rng).into()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let token_id = make_token_id(block.transactions()[0].transaction().inputs()).unwrap();

        // Burn
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(issuance_outpoint_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Burn(OutputValue::TokenV1(
                token_id,
                Amount::from_atoms(1),
            )))
            .build();
        let first_burn_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();
        let block = tf.block(*block_index.block_id());
        assert!(tf
            .outputs_from_genblock(block.get_id().into())
            .contains_key(&first_burn_outpoint_id));

        // Try to transfer burned tokens
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(first_burn_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process(&mut rng);
        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent(UtxoOutPoint::new(
                    first_burn_outpoint_id,
                    0
                ))
            ))
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn no_v0_issuance_after_v1(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![(
                            BlockHeight::zero(),
                            ChainstateUpgradeBuilder::latest()
                                .token_issuance_version(TokenIssuanceVersion::V1)
                                .build(),
                        )])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();

        let token_min_issuance_fee =
            tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Burn(
                random_nft_issuance(tf.chain_config(), &mut rng).into(),
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)))
            .build();
        let tx_id = tx.transaction().get_id();

        let res = tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng);

        assert_eq!(
            res.unwrap_err(),
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
    })
}
