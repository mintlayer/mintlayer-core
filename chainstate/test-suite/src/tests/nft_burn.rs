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
use chainstate_test_framework::{TestFramework, TransactionBuilder};
use common::chain::{
    output_value::OutputValue,
    signature::inputsig::InputWitness,
    tokens::{make_token_id, TokenData, TokenIssuanceVersion, TokenTransfer},
    ChainstateUpgrade, Destination, TxInput, TxOutput,
};
use common::chain::{OutPointSourceId, UtxoOutPoint};
use common::primitives::{Amount, BlockHeight, Idable};
use crypto::random::Rng;
use rstest::rstest;
use test_utils::{
    nft_utils::random_nft_issuance,
    random::{make_seedable_rng, Seed},
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
