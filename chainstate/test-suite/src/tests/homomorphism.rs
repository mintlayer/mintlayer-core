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
use chainstate_storage::Transactional;
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestFramework, TestStore, TransactionBuilder,
    TxVerificationStrategy,
};
use common::{
    chain::{
        output_value::OutputValue,
        tokens::{make_token_id, TokenIssuance},
        AccountCommand, AccountNonce, Destination, OutPointSourceId, TxInput, TxOutput,
    },
    primitives::{Amount, Idable},
};
use test_utils::nft_utils::random_token_issuance_v1;

// These tests prove that TransactionVerifiers hierarchy has homomorphic property: f(ab) == f(a)f(b)
// Meaning that multiple operations done via a single verifier give the same result as using one
// verifier per operation and then combining the result.

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn coins_homomorphism(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let storage1 = TestStore::new_empty().unwrap();
        let mut tf = TestFramework::builder(&mut rng)
            .with_storage(storage1.clone())
            .with_tx_verification_strategy(TxVerificationStrategy::Default)
            .build();

        let chainstate_config = tf.chainstate.get_chainstate_config();

        let storage2 = TestStore::new_empty().unwrap();
        let mut tf2 = TestFramework::builder(&mut rng)
            .with_chainstate_config(chainstate_config)
            .with_storage(storage2.clone())
            .with_tx_verification_strategy(TxVerificationStrategy::Disposable)
            .build();

        let tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000))),
                anyonecanspend_address(),
            ))
            .build();

        let tx_2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::Transaction(tx_1.transaction().get_id()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(1000..2000))),
                anyonecanspend_address(),
            ))
            .build();

        let tx_3 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::Transaction(tx_2.transaction().get_id()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100..200))),
                anyonecanspend_address(),
            ))
            .build();

        tf.make_block_builder()
            .add_transaction(tx_1.clone())
            .add_transaction(tx_2.clone())
            .add_transaction(tx_3.clone())
            .build_and_process()
            .unwrap()
            .unwrap();

        tf2.make_block_builder()
            .add_transaction(tx_1)
            .add_transaction(tx_2)
            .add_transaction(tx_3)
            .build_and_process()
            .unwrap()
            .unwrap();

        assert_eq!(
            storage1.transaction_ro().unwrap().dump_raw(),
            storage2.transaction_ro().unwrap().dump_raw()
        );
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tokens_homomorphism(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let storage1 = TestStore::new_empty().unwrap();
        let mut tf = TestFramework::builder(&mut rng)
            .with_storage(storage1.clone())
            .with_tx_verification_strategy(TxVerificationStrategy::Default)
            .build();

        let chainstate_config = tf.chainstate.get_chainstate_config();

        let storage2 = TestStore::new_empty().unwrap();
        let mut tf2 = TestFramework::builder(&mut rng)
            .with_chainstate_config(chainstate_config)
            .with_storage(storage2.clone())
            .with_tx_verification_strategy(TxVerificationStrategy::Disposable)
            .build();

        let tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
                random_token_issuance_v1(tf.chain_config().as_ref(), &mut rng),
            ))))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(
                    tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero()),
                ),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let token_id = make_token_id(tx_1.transaction().inputs()).unwrap();

        let tx_2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::MintTokens(token_id, Amount::from_atoms(100)),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::from_utxo(tx_1.transaction().get_id().into(), 1),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::from_atoms(100)),
                Destination::AnyoneCanSpend,
            ))
            .build();

        tf.make_block_builder()
            .add_transaction(tx_1.clone())
            .add_transaction(tx_2.clone())
            .build_and_process()
            .unwrap()
            .unwrap();

        tf2.make_block_builder()
            .add_transaction(tx_1)
            .add_transaction(tx_2)
            .build_and_process()
            .unwrap()
            .unwrap();

        assert_eq!(
            storage1.transaction_ro().unwrap().dump_raw(),
            storage2.transaction_ro().unwrap().dump_raw()
        );
    });
}

// FIXME: add reorg tests here
