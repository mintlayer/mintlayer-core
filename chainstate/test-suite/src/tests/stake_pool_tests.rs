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

use super::*;
use chainstate::{BlockError, ChainstateError, ConnectTransactionError};
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestFramework, TransactionBuilder,
};
use common::{
    chain::{
        stakelock::StakePoolData,
        tokens::{OutputValue, TokenData, TokenTransfer},
        OutPointSourceId, TxInput, TxOutput,
    },
    primitives::{Amount, Id, Idable},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use test_utils::nft_utils::random_token_issuance;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_basic(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let (_, vrf_pub_key) = VRFPrivateKey::new(VRFKeyKind::Schnorrkel);

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000))),
                OutputPurpose::StakePool(Box::new(StakePoolData::new(
                    anyonecanspend_address(),
                    None,
                    vrf_pub_key,
                    pub_key,
                    0,
                    Amount::ZERO,
                ))),
            ))
            .build();

        let block = tf.make_block_builder().add_transaction(tx).build();
        let block_id = block.get_id();

        tf.process_block(block, BlockSource::Local).unwrap();
        assert_eq!(tf.best_block_id(), <Id<GenBlock>>::from(block_id));
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_and_spend_coin_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let (_, vrf_pub_key) = VRFPrivateKey::new(VRFKeyKind::Schnorrkel);

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000))),
                OutputPurpose::StakePool(Box::new(StakePoolData::new(
                    anyonecanspend_address(),
                    None,
                    vrf_pub_key,
                    pub_key,
                    0,
                    Amount::ZERO,
                ))),
            ))
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000))),
                OutputPurpose::Transfer(anyonecanspend_address()),
            ))
            .build();

        let block = tf.make_block_builder().add_transaction(tx).build();
        let block_id = block.get_id();

        tf.process_block(block, BlockSource::Local).unwrap();
        assert_eq!(tf.best_block_id(), <Id<GenBlock>>::from(block_id));
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_and_issue_tokens_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let (_, vrf_pub_key) = VRFPrivateKey::new(VRFKeyKind::Schnorrkel);

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000))),
                OutputPurpose::StakePool(Box::new(StakePoolData::new(
                    anyonecanspend_address(),
                    None,
                    vrf_pub_key,
                    pub_key,
                    0,
                    Amount::ZERO,
                ))),
            ))
            .add_output(TxOutput::new(
                random_token_issuance(tf.chainstate.get_chain_config(), &mut rng).into(),
                OutputPurpose::Transfer(anyonecanspend_address()),
            ))
            .add_output(TxOutput::new(
                OutputValue::Coin(tf.chainstate.get_chain_config().token_min_issuance_fee()),
                OutputPurpose::Burn,
            ))
            .build();

        let block = tf.make_block_builder().add_transaction(tx).build();
        let block_id = block.get_id();

        tf.process_block(block, BlockSource::Local).unwrap();
        assert_eq!(tf.best_block_id(), <Id<GenBlock>>::from(block_id));
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_and_transfer_tokens_same_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        // create a tx with coins utxo and token issuance utxo
        let token_issuance_data = random_token_issuance(tf.chainstate.get_chain_config(), &mut rng);
        let amount_to_issue = token_issuance_data.amount_to_issue;
        let tx0 = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::new(
                token_issuance_data.into(),
                OutputPurpose::Transfer(anyonecanspend_address()),
            ))
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000))),
                OutputPurpose::Transfer(anyonecanspend_address()),
            ))
            .add_output(TxOutput::new(
                OutputValue::Coin(tf.chainstate.get_chain_config().token_min_issuance_fee()),
                OutputPurpose::Burn,
            ))
            .build();
        let tx0_id = tx0.transaction().get_id();
        let token_id = common::chain::tokens::token_id(tx0.transaction()).unwrap();

        let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let (_, vrf_pub_key) = VRFPrivateKey::new(VRFKeyKind::Schnorrkel);

        // stake pool with coin input and transfer tokens with token input
        let tx1 = TransactionBuilder::new()
            .add_input(
                TxInput::new(OutPointSourceId::Transaction(tx0_id), 0),
                empty_witness(&mut rng),
            )
            .add_input(
                TxInput::new(OutPointSourceId::Transaction(tx0_id), 1),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::new(
                TokenData::TokenTransfer(TokenTransfer {
                    token_id,
                    amount: amount_to_issue,
                })
                .into(),
                OutputPurpose::Transfer(anyonecanspend_address()),
            ))
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100..100_000))),
                OutputPurpose::StakePool(Box::new(StakePoolData::new(
                    anyonecanspend_address(),
                    None,
                    vrf_pub_key,
                    pub_key,
                    0,
                    Amount::ZERO,
                ))),
            ))
            .build();

        let best_block_index = tf
            .make_block_builder()
            .with_transactions(vec![tx0, tx1])
            .build_and_process()
            .unwrap()
            .unwrap();

        assert_eq!(
            tf.best_block_id(),
            Id::<GenBlock>::from(*best_block_index.block_id())
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_with_tokens_as_input_value(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let token_issuance_data = random_token_issuance(tf.chainstate.get_chain_config(), &mut rng);
        let amount_to_issue = token_issuance_data.amount_to_issue;

        // create a tx with coins utxo and token issuance utxo
        let tx0 = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::new(
                token_issuance_data.into(),
                OutputPurpose::Transfer(anyonecanspend_address()),
            ))
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000))),
                OutputPurpose::Transfer(anyonecanspend_address()),
            ))
            .add_output(TxOutput::new(
                OutputValue::Coin(tf.chainstate.get_chain_config().token_min_issuance_fee()),
                OutputPurpose::Burn,
            ))
            .build();
        let tx0_id = tx0.transaction().get_id();
        let token_id = common::chain::tokens::token_id(tx0.transaction()).unwrap();

        let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let (_, vrf_pub_key) = VRFPrivateKey::new(VRFKeyKind::Schnorrkel);

        // use token input to stake pool with tokens
        let tx1 = TransactionBuilder::new()
            .add_input(
                TxInput::new(OutPointSourceId::Transaction(tx0_id), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::new(
                TokenData::TokenTransfer(TokenTransfer {
                    token_id,
                    amount: amount_to_issue,
                })
                .into(),
                OutputPurpose::StakePool(Box::new(StakePoolData::new(
                    anyonecanspend_address(),
                    None,
                    vrf_pub_key,
                    pub_key,
                    0,
                    Amount::ZERO,
                ))),
            ))
            .build();
        let tx1_id = tx1.transaction().get_id();

        let result = tf.make_block_builder().with_transactions(vec![tx0, tx1]).build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokenOutputForPoSAccountingOperation(tx1_id)
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_twice(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let (_, vrf_pub_key) = VRFPrivateKey::new(VRFKeyKind::Schnorrkel);

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000))),
                OutputPurpose::StakePool(Box::new(StakePoolData::new(
                    anyonecanspend_address(),
                    None,
                    vrf_pub_key.clone(),
                    pub_key.clone(),
                    0,
                    Amount::ZERO,
                ))),
            ))
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000))),
                OutputPurpose::StakePool(Box::new(StakePoolData::new(
                    anyonecanspend_address(),
                    None,
                    vrf_pub_key,
                    pub_key,
                    0,
                    Amount::ZERO,
                ))),
            ))
            .build();

        let result = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::PoSAccountingError(
                    pos_accounting::Error::InvariantErrorPoolBalanceAlreadyExists
                )
            ))
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_overspend(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let genesis_id = tf.genesis().get_id().into();

        let genesis_output_amount = {
            let genesis_outputs = tf.outputs_from_genblock(genesis_id);
            assert_eq!(genesis_outputs.len(), 1);
            let genesis_tx_output =
                genesis_outputs.get(&OutPointSourceId::BlockReward(genesis_id)).unwrap();
            assert_eq!(genesis_tx_output.len(), 1);
            genesis_tx_output.get(0).unwrap().value().coin_amount().unwrap()
        };
        let genesis_overspend_amount = (genesis_output_amount + Amount::from_atoms(1)).unwrap();

        let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let (_, vrf_pub_key) = VRFPrivateKey::new(VRFKeyKind::Schnorrkel);

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(OutPointSourceId::BlockReward(genesis_id), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(genesis_overspend_amount),
                OutputPurpose::StakePool(Box::new(StakePoolData::new(
                    anyonecanspend_address(),
                    None,
                    vrf_pub_key,
                    pub_key,
                    0,
                    Amount::ZERO,
                ))),
            ))
            .build();

        let result = tf.make_block_builder().add_transaction(tx).build_and_process();

        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::AttemptToPrintMoney(
                    genesis_output_amount,
                    genesis_overspend_amount
                )
            ))
        );
    });
}
