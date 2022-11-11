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
    ConnectTransactionError, TokensError,
};
use chainstate_test_framework::{TestFramework, TransactionBuilder};
use common::chain::OutPointSourceId;
use common::chain::{
    signature::inputsig::InputWitness,
    tokens::{token_id, OutputValue, TokenData, TokenTransfer},
    Destination, OutputPurpose, TxInput, TxOutput,
};
use common::primitives::Amount;
use common::primitives::Idable;
use crypto::random::Rng;
use rstest::rstest;
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

        let chain_config = tf.chainstate.get_chain_config();
        let token_min_issuance_fee = chain_config.token_min_issuance_fee();

        // Issuance
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(genesis_outpoint_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::new(
                random_nft_issuance(chain_config, &mut rng).into(),
                OutputPurpose::Transfer(Destination::AnyoneCanSpend),
            ))
            .add_output(TxOutput::new(
                OutputValue::Coin(token_min_issuance_fee),
                OutputPurpose::Burn,
            ))
            .build();
        let issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let token_id = token_id(block.transactions()[0].transaction()).unwrap();

        // Burn more NFT than we have
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id.clone(), 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenTransfer {
                            token_id,
                            amount: Amount::from_atoms(rng.gen_range(2..123)),
                        }
                        .into(),
                        OutputPurpose::Burn,
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::StateUpdateFailed(ConnectTransactionError::AttemptToPrintMoney(_, _))
            ))
        ));

        // Burn zero NFT
        let result = tf
            .make_block_builder()
            .add_transaction(
                TransactionBuilder::new()
                    .add_input(
                        TxInput::new(issuance_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenTransfer {
                            token_id,
                            amount: Amount::from_atoms(0),
                        }
                        .into(),
                        OutputPurpose::Burn,
                    ))
                    .build(),
            )
            .build_and_process();

        assert!(matches!(
            result,
            Err(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::CheckTransactionFailed(
                    CheckBlockTransactionsError::TokensError(TokensError::TransferZeroTokens(_, _))
                ))
            ))
        ));
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn nft_burn_valid_case(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let mut rng = make_seedable_rng(seed);
        let genesis_outpoint_id = OutPointSourceId::BlockReward(tf.genesis().get_id().into());

        let chain_config = tf.chainstate.get_chain_config();
        let token_min_issuance_fee = chain_config.token_min_issuance_fee();

        // Issuance
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(genesis_outpoint_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::new(
                random_nft_issuance(chain_config, &mut rng).into(),
                OutputPurpose::Transfer(Destination::AnyoneCanSpend),
            ))
            .add_output(TxOutput::new(
                OutputValue::Coin(token_min_issuance_fee),
                OutputPurpose::Burn,
            ))
            .build();
        let issuance_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process()
            .unwrap()
            .unwrap();

        let block = tf.block(*block_index.block_id());
        let token_id = token_id(block.transactions()[0].transaction()).unwrap();

        // Burn
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(issuance_outpoint_id, 0),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::new(
                TokenTransfer {
                    token_id,
                    amount: Amount::from_atoms(1),
                }
                .into(),
                OutputPurpose::Burn,
            ))
            .build();
        let first_burn_outpoint_id: OutPointSourceId = tx.transaction().get_id().into();
        let block_index = tf
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process()
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
                        TxInput::new(first_burn_outpoint_id, 0),
                        InputWitness::NoSignature(None),
                    )
                    .add_output(TxOutput::new(
                        TokenData::TokenTransfer(TokenTransfer {
                            token_id,
                            amount: Amount::from_atoms(1),
                        })
                        .into(),
                        OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                    ))
                    .build(),
            )
            .build_and_process();
        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::MissingOutputOrSpent
            ))
        );
    })
}
