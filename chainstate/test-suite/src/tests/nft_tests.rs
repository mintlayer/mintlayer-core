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

use chainstate::{
    BlockError, ChainstateError, CheckBlockError, CheckBlockTransactionsError,
    ConnectTransactionError, IOPolicyError, TokenIssuanceError, TokensError,
};
use chainstate_test_framework::{TestFramework, TransactionBuilder};
use common::chain::OutPointSourceId;
use common::chain::{
    output_value::OutputValue,
    signature::inputsig::InputWitness,
    tokens::{make_token_id, Metadata, NftIssuance, NftIssuanceV0, TokenIssuanceVersion},
    ChainstateUpgrade, Destination, TxInput, TxOutput,
};
use common::primitives::{Amount, BlockHeight, Idable};
use rstest::rstest;
use serialization::extras::non_empty_vec::DataOrNoVec;
use test_utils::{
    gen_text_with_non_ascii,
    nft_utils::random_nft_issuance,
    random::{make_seedable_rng, Seed},
    random_ascii_alphanumeric_string,
};
use tx_verifier::transaction_verifier::CoinOrTokenId;

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
                            ChainstateUpgrade::new(TokenIssuanceVersion::V1),
                        )])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();

        let token_issuance_fee = tf.chainstate.get_chain_config().nft_issuance_fee();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                random_nft_issuance(tf.chain_config(), &mut rng).into(),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
            .build();
        let tx_id = tx.transaction().get_id();

        let res = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokensError(TokensError::DeprecatedTokenOperationVersion(
                    TokenIssuanceVersion::V0,
                    tx_id,
                ))
            ))
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn only_ascii_alphanumeric_after_v1(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![(
                            BlockHeight::zero(),
                            ChainstateUpgrade::new(TokenIssuanceVersion::V1),
                        )])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();
        let genesis_block_id = tf.best_block_id();

        let token_issuance_fee = tf.chainstate.get_chain_config().nft_issuance_fee();
        let max_desc_len = tf.chainstate.get_chain_config().token_max_description_len();
        let max_name_len = tf.chainstate.get_chain_config().token_max_name_len();
        let max_ticker_len = tf.chainstate.get_chain_config().token_max_ticker_len();

        // Try not ascii alphanumeric name
        let c = test_utils::get_random_non_ascii_alphanumeric_byte(&mut rng);
        let name = test_utils::gen_text_with_non_ascii(c, &mut rng, max_name_len);
        let issuance = NftIssuanceV0 {
            metadata: Metadata {
                creator: None,
                name,
                description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len)
                    .into_bytes(),
                ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: Vec::new(),
            },
        };
        let token_id = make_token_id(&[TxInput::from_utxo(genesis_block_id.into(), 0)]).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_block_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(NftIssuance::V0(issuance)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
            .build();
        let tx_id = tx.transaction().get_id();
        let block = tf.make_block_builder().add_transaction(tx).build();
        let block_id = block.get_id();
        let res = tf.process_block(block, chainstate::BlockSource::Local);

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(CheckBlockTransactionsError::TokensError(
                    TokensError::IssueError(
                        TokenIssuanceError::IssueErrorNameHasNoneAlphaNumericChar,
                        tx_id,
                        block_id
                    )
                ))
            ))
        );

        // Try not ascii alphanumeric description
        let c = test_utils::get_random_non_ascii_alphanumeric_byte(&mut rng);
        let description = gen_text_with_non_ascii(c, &mut rng, max_desc_len);
        let issuance = NftIssuanceV0 {
            metadata: Metadata {
                creator: None,
                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
                description,
                ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        };
        let token_id = make_token_id(&[TxInput::from_utxo(genesis_block_id.into(), 0)]).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_block_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(NftIssuance::V0(issuance)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
            .build();
        let tx_id = tx.transaction().get_id();
        let block = tf.make_block_builder().add_transaction(tx).build();
        let block_id = block.get_id();
        let res = tf.process_block(block, chainstate::BlockSource::Local);

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(CheckBlockTransactionsError::TokensError(
                    TokensError::IssueError(
                        TokenIssuanceError::IssueErrorDescriptionHasNoneAlphaNumericChar,
                        tx_id,
                        block_id
                    )
                ))
            ))
        );

        // Try not ascii alphanumeric ticker
        let c = test_utils::get_random_non_ascii_alphanumeric_byte(&mut rng);
        let ticker = gen_text_with_non_ascii(c, &mut rng, max_ticker_len);
        let issuance = NftIssuanceV0 {
            metadata: Metadata {
                creator: None,
                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len)
                    .into_bytes(),
                ticker,
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        };
        let token_id = make_token_id(&[TxInput::from_utxo(genesis_block_id.into(), 0)]).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_block_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(NftIssuance::V0(issuance)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
            .build();
        let tx_id = tx.transaction().get_id();
        let block = tf.make_block_builder().add_transaction(tx).build();
        let block_id = block.get_id();
        let res = tf.process_block(block, chainstate::BlockSource::Local);

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::CheckTransactionFailed(CheckBlockTransactionsError::TokensError(
                    TokensError::IssueError(
                        TokenIssuanceError::IssueErrorTickerHasNoneAlphaNumericChar,
                        tx_id,
                        block_id
                    )
                ))
            ))
        );

        // valid case
        let issuance = NftIssuanceV0 {
            metadata: Metadata {
                creator: None,
                name: random_ascii_alphanumeric_string(&mut rng, 1..max_name_len).into_bytes(),
                description: random_ascii_alphanumeric_string(&mut rng, 1..max_desc_len)
                    .into_bytes(),
                ticker: random_ascii_alphanumeric_string(&mut rng, 1..max_ticker_len).into_bytes(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            },
        };
        let token_id = make_token_id(&[TxInput::from_utxo(genesis_block_id.into(), 0)]).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_block_id.into(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(NftIssuance::V0(issuance)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
            .build();
        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn no_v0_burn_after_v1(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![(
                            BlockHeight::zero(),
                            ChainstateUpgrade::new(TokenIssuanceVersion::V1),
                        )])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();

        let token_issuance_fee = tf.chainstate.get_chain_config().nft_issuance_fee();

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
            .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
            .build();
        let tx_id = tx.transaction().get_id();

        let res = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            res.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokensError(TokensError::DeprecatedTokenOperationVersion(
                    TokenIssuanceVersion::V0,
                    tx_id,
                ))
            ))
        );
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn ensure_nft_cannot_be_printed_from_tokens_op(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![(
                            BlockHeight::zero(),
                            ChainstateUpgrade::new(TokenIssuanceVersion::V1),
                        )])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());
        let token_id =
            make_token_id(&[TxInput::from_utxo(genesis_outpoint_id.clone(), 0)]).unwrap();

        let token_issuance_fee = tf.chainstate.get_chain_config().nft_issuance_fee();

        let nft_issuance = random_nft_issuance(tf.chainstate.get_chain_config(), &mut rng);

        // Issue
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_outpoint_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(NftIssuance::V0(nft_issuance)),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
            .build();
        let issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

        // Try print Nfts on transfer
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(issuance_outpoint_id.clone(), 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::from_atoms(2)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let tx_id = tx.transaction().get_id();
        let result = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::IOPolicyError(
                    IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::TokenId(token_id)
                    ),
                    tx_id.into()
                )
            ))
        );

        // Transfer
        tf.make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::from_utxo(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                        Destination::AnyoneCanSpend,
                    ))
                    .build(),
            )
            .build_and_process()
            .unwrap();
    })
}
