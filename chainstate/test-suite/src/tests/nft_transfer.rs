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
    ConnectTransactionError, IOPolicyError, TokensError,
};
use chainstate_test_framework::{get_output_value, TestFramework, TransactionBuilder};
use common::primitives::Idable;
use common::{
    chain::{
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        tokens::{
            make_token_id, Metadata, NftIssuance, NftIssuanceV0, TokenData, TokenId,
            TokenIssuanceVersion, TokenTransfer,
        },
        ChainstateUpgrade, Destination, NetUpgrades, OutPointSourceId, TxInput, TxOutput,
    },
    primitives::{Amount, BlockHeight},
};
use crypto::random::Rng;
use rstest::rstest;
use serialization::extras::non_empty_vec::DataOrNoVec;
use test_utils::nft_utils::random_nft_issuance;
use test_utils::{
    nft_utils::random_creator,
    random::{make_seedable_rng, Seed},
    random_ascii_alphanumeric_string,
};
use tx_verifier::transaction_verifier::CoinOrTokenId;

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
                        NetUpgrades::initialize(vec![(
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
