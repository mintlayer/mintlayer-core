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
    chain::{stakelock::StakePoolData, tokens::OutputValue, OutPointSourceId, TxInput, TxOutput},
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
fn stake_pool_and_spend_same_tx(#[case] seed: Seed) {
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
fn tokens_in_input(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        // create a tx with tokens in utxo
        let tx0 = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::new(
                random_token_issuance(tf.chainstate.get_chain_config(), &mut rng).into(),
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

        tf.make_block_builder()
            .add_transaction(tx0)
            .build_and_process()
            .unwrap()
            .unwrap();

        let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let (_, vrf_pub_key) = VRFPrivateKey::new(VRFKeyKind::Schnorrkel);

        // try to create a tx with tokens in inputs and StakePool output
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::new(OutPointSourceId::Transaction(tx0_id), 0),
                empty_witness(&mut rng),
            )
            .add_input(
                TxInput::new(OutPointSourceId::Transaction(tx0_id), 1),
                empty_witness(&mut rng),
            )
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
        let tx_id = tx.transaction().get_id();

        let result = tf.make_block_builder().add_transaction(tx).build_and_process();
        assert_eq!(
            result.unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::TokenInputForPoSAccountingOperation(tx_id)
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
