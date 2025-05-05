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
    anyonecanspend_address, create_stake_pool_data_with_all_reward_to_staker, empty_witness,
    TestFramework, TestStore, TransactionBuilder, TxVerificationStrategy,
};
use common::{
    chain::{
        make_delegation_id, make_token_id, output_value::OutputValue, timelock::OutputTimeLock,
        tokens::TokenIssuance, AccountCommand, AccountNonce, Destination, OutPointSourceId, PoolId,
        TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, Idable},
};
use crypto::vrf::{VRFKeyKind, VRFPrivateKey};
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
        let genesis_id = tf.genesis().get_id().into();

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
            .with_reward(vec![TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(100)),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(u64::MAX),
            )])
            .add_transaction(tx_1.clone())
            .add_transaction(tx_2.clone())
            .add_transaction(tx_3.clone())
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        tf2.make_block_builder()
            .with_reward(vec![TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(100)),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(u64::MAX),
            )])
            .add_transaction(tx_1)
            .add_transaction(tx_2)
            .add_transaction(tx_3)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        assert_eq!(
            storage1.transaction_ro().unwrap().dump_raw(),
            storage2.transaction_ro().unwrap().dump_raw()
        );

        // create alternative chains that triggers reorg
        let block_1 = tf.make_block_builder().with_parent(genesis_id).build(&mut rng);
        let block_1_id = block_1.get_id();
        tf.process_block(block_1, BlockSource::Local).unwrap();
        tf.make_block_builder()
            .with_parent(block_1_id.into())
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        let block_2 = tf2.make_block_builder().with_parent(genesis_id).build(&mut rng);
        let block_2_id = block_2.get_id();
        tf2.process_block(block_2, BlockSource::Local).unwrap();
        tf2.make_block_builder()
            .with_parent(block_2_id.into())
            .build_and_process(&mut rng)
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
        let genesis_id: Id<GenBlock> = tf.genesis().get_id().into();

        let storage2 = TestStore::new_empty().unwrap();
        let mut tf2 = TestFramework::builder(&mut rng)
            .with_chainstate_config(chainstate_config)
            .with_storage(storage2.clone())
            .with_tx_verification_strategy(TxVerificationStrategy::Disposable)
            .build();

        let tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(genesis_id.into(), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
                random_token_issuance_v1(
                    tf.chain_config().as_ref(),
                    Destination::AnyoneCanSpend,
                    &mut rng,
                ),
            ))))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(
                    tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero()),
                ),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let token_id = make_token_id(
            tf.chain_config().as_ref(),
            tf.next_block_height(),
            tx_1.inputs(),
        )
        .unwrap();

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
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        tf2.make_block_builder()
            .add_transaction(tx_1)
            .add_transaction(tx_2)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        assert_eq!(
            storage1.transaction_ro().unwrap().dump_raw(),
            storage2.transaction_ro().unwrap().dump_raw()
        );

        // create alternative chains that triggers reorg
        let block_1 = tf.make_block_builder().with_parent(genesis_id).build(&mut rng);
        let block_1_id = block_1.get_id();
        tf.process_block(block_1, BlockSource::Local).unwrap();
        tf.make_block_builder()
            .with_parent(block_1_id.into())
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        let block_2 = tf2.make_block_builder().with_parent(genesis_id).build(&mut rng);
        let block_2_id = block_2.get_id();
        tf2.process_block(block_2, BlockSource::Local).unwrap();
        tf2.make_block_builder()
            .with_parent(block_2_id.into())
            .build_and_process(&mut rng)
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
fn pos_accounting_homomorphism(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let storage1 = TestStore::new_empty().unwrap();
        let mut tf = TestFramework::builder(&mut rng)
            .with_storage(storage1.clone())
            .with_tx_verification_strategy(TxVerificationStrategy::Default)
            .build();

        let chainstate_config = tf.chainstate.get_chainstate_config();
        let genesis_id = tf.genesis().get_id().into();

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let min_stake_pool_pledge = tf.chainstate.get_chain_config().min_stake_pool_pledge();
        let (stake_pool_data, _) = create_stake_pool_data_with_all_reward_to_staker(
            &mut rng,
            min_stake_pool_pledge,
            vrf_pk,
        );
        let genesis_outpoint = UtxoOutPoint::new(OutPointSourceId::BlockReward(genesis_id), 0);
        let pool_id = PoolId::from_utxo(&genesis_outpoint);

        let storage2 = TestStore::new_empty().unwrap();
        let mut tf2 = TestFramework::builder(&mut rng)
            .with_chainstate_config(chainstate_config)
            .with_storage(storage2.clone())
            .with_tx_verification_strategy(TxVerificationStrategy::Disposable)
            .build();

        let tx_1 = TransactionBuilder::new()
            .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000))),
                anyonecanspend_address(),
            ))
            .build();

        let tx_2 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::Transaction(tx_1.transaction().get_id()),
                    1,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::CreateDelegationId(
                Destination::AnyoneCanSpend,
                pool_id,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(1000..2000))),
                anyonecanspend_address(),
            ))
            .build();

        let delegation_id = make_delegation_id(tx_2.inputs()).unwrap();
        let tx_3 = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::Transaction(tx_2.transaction().get_id()),
                    1,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::DelegateStaking(
                Amount::from_atoms(rng.gen_range(100..200)),
                delegation_id,
            ))
            .build();

        tf.make_block_builder()
            .add_transaction(tx_1.clone())
            .add_transaction(tx_2.clone())
            .add_transaction(tx_3.clone())
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        tf2.make_block_builder()
            .add_transaction(tx_1)
            .add_transaction(tx_2)
            .add_transaction(tx_3)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        assert_eq!(
            storage1.transaction_ro().unwrap().dump_raw(),
            storage2.transaction_ro().unwrap().dump_raw()
        );

        // create alternative chains that triggers reorg
        let block_1 = tf.make_block_builder().with_parent(genesis_id).build(&mut rng);
        let block_1_id = block_1.get_id();
        tf.process_block(block_1, BlockSource::Local).unwrap();
        tf.make_block_builder()
            .with_parent(block_1_id.into())
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        let block_2 = tf2.make_block_builder().with_parent(genesis_id).build(&mut rng);
        let block_2_id = block_2.get_id();
        tf2.process_block(block_2, BlockSource::Local).unwrap();
        tf2.make_block_builder()
            .with_parent(block_2_id.into())
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        assert_eq!(
            storage1.transaction_ro().unwrap().dump_raw(),
            storage2.transaction_ro().unwrap().dump_raw()
        );
    });
}
