// Copyright (c) 2021-2022 RBB S.r.l
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

use super::helpers::in_memory_storage_wrapper::InMemoryStorageWrapper;
use super::*;

use chainstate_test_framework::{
    create_stake_pool_data_with_all_reward_to_staker, empty_witness, TestFramework, TestStore,
    TransactionBuilder,
};
use common::{
    chain::{
        config::{create_unit_test_config, ChainType},
        output_value::OutputValue,
        timelock::OutputTimeLock,
        tokens::{
            make_token_id, IsTokenFreezable, TokenIssuance, TokenIssuanceV0, TokenIssuanceV1,
            TokenTotalSupply,
        },
        AccountCommand, AccountNonce, AccountSpending, ChainConfig, ChainstateUpgradeBuilder,
        Destination, NetUpgrades, TokenIssuanceVersion, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, Fee, Idable},
};
use crypto::vrf::{VRFKeyKind, VRFPrivateKey};
use randomness::CryptoRng;
use test_utils::random_ascii_alphanumeric_string;
use tx_verifier::transaction_verifier::{TransactionSourceForConnect, TransactionVerifier};

fn setup(rng: &mut (impl Rng + CryptoRng)) -> (ChainConfig, InMemoryStorageWrapper, TestFramework) {
    let storage = TestStore::new_empty().unwrap();

    let chain_config = create_unit_test_config();
    let tf = TestFramework::builder(rng)
        .with_storage(storage.clone())
        .with_chain_config(chain_config.clone())
        .build();
    let storage = InMemoryStorageWrapper::new(storage, chain_config.clone());

    (chain_config, storage, tf)
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn simple_fee_from_coin_transfer(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (chain_config, storage, tf) = setup(&mut rng);

        let transfer_atoms = rng.gen_range(1..100_000);
        let genesis_amount = chainstate_test_framework::get_output_value(&tf.genesis().utxos()[0])
            .unwrap()
            .coin_amount()
            .unwrap();
        let expected_fee = Fee((genesis_amount - Amount::from_atoms(transfer_atoms)).unwrap());

        let outputs = test_utils::split_value(&mut rng, transfer_atoms)
            .into_iter()
            .map(|value| {
                TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(value)),
                    Destination::AnyoneCanSpend,
                )
            })
            .collect::<Vec<_>>();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tf.genesis().get_id().into(), 0),
                empty_witness(&mut rng),
            )
            .with_outputs(outputs)
            .build();

        let mut verifier = TransactionVerifier::new(&storage, &chain_config);

        let tx_source = TransactionSourceForConnect::Mempool {
            current_best: &tf.best_block_index(),
            effective_height: BlockHeight::new(1),
        };

        let actual_fee = verifier
            .connect_transaction(&tx_source, &tx, &tf.genesis().timestamp())
            .unwrap()
            .map_into_block_fees(&chain_config, BlockHeight::new(1))
            .unwrap();
        assert_eq!(expected_fee, actual_fee);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn transfer_lock_and_burn_outputs_fee(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (chain_config, storage, tf) = setup(&mut rng);

        let locked_atoms = rng.gen_range(1..100_000);
        let not_locked_atoms = rng.gen_range(1..100_000);
        let burned_atoms = rng.gen_range(1..100_000);
        let genesis_amount = chainstate_test_framework::get_output_value(&tf.genesis().utxos()[0])
            .unwrap()
            .coin_amount()
            .unwrap();
        let expected_fee = Fee((genesis_amount
            - Amount::from_atoms(locked_atoms + not_locked_atoms + burned_atoms))
        .unwrap());

        let locked_outputs = test_utils::split_value(&mut rng, locked_atoms)
            .into_iter()
            .map(|value| {
                TxOutput::LockThenTransfer(
                    OutputValue::Coin(Amount::from_atoms(value)),
                    Destination::AnyoneCanSpend,
                    OutputTimeLock::ForBlockCount(1),
                )
            })
            .collect::<Vec<_>>();
        let not_locked_outputs = test_utils::split_value(&mut rng, not_locked_atoms)
            .into_iter()
            .map(|value| {
                TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(value)),
                    Destination::AnyoneCanSpend,
                )
            })
            .collect::<Vec<_>>();
        let burned_outputs = test_utils::split_value(&mut rng, burned_atoms)
            .into_iter()
            .map(|value| TxOutput::Burn(OutputValue::Coin(Amount::from_atoms(value))))
            .collect::<Vec<_>>();
        let outputs = locked_outputs
            .into_iter()
            .chain(not_locked_outputs.into_iter())
            .chain(burned_outputs.into_iter())
            .collect();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tf.genesis().get_id().into(), 0),
                empty_witness(&mut rng),
            )
            .with_outputs(outputs)
            .build();

        let mut verifier = TransactionVerifier::new(&storage, &chain_config);

        let tx_source = TransactionSourceForConnect::Mempool {
            current_best: &tf.best_block_index(),
            effective_height: BlockHeight::new(1),
        };

        let actual_fee = verifier
            .connect_transaction(&tx_source, &tx, &tf.genesis().timestamp())
            .unwrap()
            .map_into_block_fees(&chain_config, BlockHeight::new(1))
            .unwrap();
        assert_eq!(expected_fee, actual_fee);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn locked_outputs_can_go_to_fee(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (chain_config, storage, mut tf) = setup(&mut rng);

        let locked_atoms = rng.gen_range(1..100_000);
        let timelock_secs = 10;
        let locked_outputs = test_utils::split_value(&mut rng, locked_atoms)
            .into_iter()
            .map(|value| {
                TxOutput::LockThenTransfer(
                    OutputValue::Coin(Amount::from_atoms(value)),
                    Destination::AnyoneCanSpend,
                    OutputTimeLock::ForSeconds(timelock_secs),
                )
            })
            .collect::<Vec<_>>();
        let locked_outputs_count = locked_outputs.len();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tf.genesis().get_id().into(), 0),
                empty_witness(&mut rng),
            )
            .with_outputs(locked_outputs)
            .build();
        let tx_id = tx.transaction().get_id();
        tf.make_block_builder().add_transaction(tx).build_and_process(&mut rng).unwrap();

        let not_locked_atoms = rng.gen_range(1..=locked_atoms);
        let expected_fee = Fee(Amount::from_atoms(locked_atoms - not_locked_atoms));

        let not_locked_outputs = test_utils::split_value(&mut rng, not_locked_atoms)
            .into_iter()
            .map(|value| {
                TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(value)),
                    Destination::AnyoneCanSpend,
                )
            })
            .collect::<Vec<_>>();

        let witnesses = vec![InputWitness::NoSignature(None); locked_outputs_count];
        let inputs = (0..locked_outputs_count)
            .map(|i| TxInput::from_utxo(tx_id.into(), i as u32))
            .collect::<Vec<_>>();
        let tx = TransactionBuilder::new()
            .with_inputs(inputs)
            .with_witnesses(witnesses)
            .with_outputs(not_locked_outputs)
            .build();

        let mut verifier = TransactionVerifier::new(&storage, &chain_config);

        let tx_source = TransactionSourceForConnect::Mempool {
            current_best: &tf.best_block_index(),
            effective_height: BlockHeight::new(2),
        };

        let actual_fee = verifier
            .connect_transaction(
                &tx_source,
                &tx,
                &tf.genesis().timestamp().add_int_seconds(timelock_secs).unwrap(),
            )
            .unwrap()
            .map_into_block_fees(&chain_config, BlockHeight::new(1))
            .unwrap();
        assert_eq!(expected_fee, actual_fee);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_stake_pool(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (chain_config, storage, tf) = setup(&mut rng);

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let min_stake_pool_pledge =
            tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
        let amount_to_stake =
            Amount::from_atoms(rng.gen_range(min_stake_pool_pledge..(min_stake_pool_pledge * 10)));
        let (stake_pool_data, _) =
            create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk);

        let genesis_amount = chainstate_test_framework::get_output_value(&tf.genesis().utxos()[0])
            .unwrap()
            .coin_amount()
            .unwrap();
        let expected_fee = Fee((genesis_amount - amount_to_stake).unwrap());

        let stake_pool_outpoint = UtxoOutPoint::new(tf.genesis().get_id().into(), 0);
        let pool_id = pos_accounting::make_pool_id(&stake_pool_outpoint);
        let tx = TransactionBuilder::new()
            .add_input(TxInput::Utxo(stake_pool_outpoint), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();

        let mut verifier = TransactionVerifier::new(&storage, &chain_config);

        let tx_source = TransactionSourceForConnect::Mempool {
            current_best: &tf.best_block_index(),
            effective_height: BlockHeight::new(1),
        };

        let actual_fee = verifier
            .connect_transaction(&tx_source, &tx, &tf.genesis().timestamp())
            .unwrap()
            .map_into_block_fees(&chain_config, BlockHeight::new(1))
            .unwrap();
        assert_eq!(expected_fee, actual_fee);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delegate_staking(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (chain_config, storage, mut tf) = setup(&mut rng);

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let min_stake_pool_pledge =
            tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
        let amount_to_stake =
            Amount::from_atoms(rng.gen_range(min_stake_pool_pledge..(min_stake_pool_pledge * 10)));
        let (stake_pool_data, _) =
            create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk);
        let delegated_atoms = rng.gen_range(1..100_000);

        let stake_pool_outpoint = UtxoOutPoint::new(tf.genesis().get_id().into(), 0);
        let pool_id = pos_accounting::make_pool_id(&stake_pool_outpoint);
        let stake_pool_tx = TransactionBuilder::new()
            .add_input(TxInput::Utxo(stake_pool_outpoint), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(delegated_atoms)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let stake_pool_tx_id = stake_pool_tx.transaction().get_id();

        let delegation_id =
            pos_accounting::make_delegation_id(&UtxoOutPoint::new(stake_pool_tx_id.into(), 1));
        let create_delegation_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(stake_pool_tx_id.into(), 1),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::CreateDelegationId(
                Destination::AnyoneCanSpend,
                pool_id,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(delegated_atoms)),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let create_delegation_tx_id = create_delegation_tx.transaction().get_id();

        tf.make_block_builder()
            .with_transactions(vec![stake_pool_tx, create_delegation_tx])
            .build_and_process(&mut rng)
            .unwrap();

        let mut delegation_atoms = test_utils::split_value(&mut rng, delegated_atoms);
        let expected_fee = Amount::from_atoms(delegation_atoms.pop().unwrap_or(0));

        let delegation_outputs = delegation_atoms
            .into_iter()
            .map(|value| TxOutput::DelegateStaking(Amount::from_atoms(value), delegation_id))
            .collect::<Vec<_>>();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(create_delegation_tx_id.into(), 1),
                empty_witness(&mut rng),
            )
            .with_outputs(delegation_outputs)
            .build();

        let mut verifier = TransactionVerifier::new(&storage, &chain_config);

        let tx_source = TransactionSourceForConnect::Mempool {
            current_best: &tf.best_block_index(),
            effective_height: BlockHeight::new(1),
        };

        let actual_fee = verifier
            .connect_transaction(&tx_source, &tx, &tf.genesis().timestamp())
            .unwrap()
            .map_into_block_fees(&chain_config, BlockHeight::new(1))
            .unwrap();
        assert_eq!(Fee(expected_fee), actual_fee);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn fee_from_decommissioning_stake_pool(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (_, storage, mut tf) = setup(&mut rng);

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let min_stake_pool_pledge =
            tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
        let amount_to_stake =
            Amount::from_atoms(rng.gen_range(min_stake_pool_pledge..(min_stake_pool_pledge * 10)));
        let (stake_pool_data, _) =
            create_stake_pool_data_with_all_reward_to_staker(&mut rng, amount_to_stake, vrf_pk);

        let stake_pool_outpoint = UtxoOutPoint::new(tf.genesis().get_id().into(), 0);
        let pool_id = pos_accounting::make_pool_id(&stake_pool_outpoint);
        let stake_pool_tx = TransactionBuilder::new()
            .add_input(TxInput::Utxo(stake_pool_outpoint), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();
        let stake_pool_tx_id = stake_pool_tx.transaction().get_id();

        tf.make_block_builder()
            .add_transaction(stake_pool_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // use regtest with pos for new tx
        let chain_config = common::chain::config::Builder::new(ChainType::Regtest)
            .consensus_upgrades(NetUpgrades::regtest_with_pos())
            .build();
        let required_maturity_distance =
            chain_config.staking_pool_spend_maturity_block_count(BlockHeight::new(2));
        let maturity_distance = rng.gen_range(
            required_maturity_distance.to_int()..(required_maturity_distance.to_int() * 2),
        );

        let decommission_outputs =
            test_utils::split_value(&mut rng, amount_to_stake.into_atoms() / 2)
                .into_iter()
                .map(|value| {
                    TxOutput::LockThenTransfer(
                        OutputValue::Coin(Amount::from_atoms(value)),
                        Destination::AnyoneCanSpend,
                        OutputTimeLock::ForBlockCount(maturity_distance),
                    )
                })
                .collect::<Vec<_>>();

        let expected_fee = Fee((amount_to_stake / 2).and_then(|v| amount_to_stake - v).unwrap());

        let decommission_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(stake_pool_tx_id.into(), 0),
                empty_witness(&mut rng),
            )
            .with_outputs(decommission_outputs)
            .build();

        let mut verifier = TransactionVerifier::new(&storage, &chain_config);

        let tx_source = TransactionSourceForConnect::Mempool {
            current_best: &tf.best_block_index(),
            effective_height: BlockHeight::new(2),
        };

        let actual_fee = verifier
            .connect_transaction(&tx_source, &decommission_tx, &tf.genesis().timestamp())
            .unwrap()
            .map_into_block_fees(&chain_config, BlockHeight::new(1))
            .unwrap();
        assert_eq!(expected_fee, actual_fee);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn fee_from_spending_delegation_share(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (_, storage, mut tf) = setup(&mut rng);

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let (stake_pool_data, _) = create_stake_pool_data_with_all_reward_to_staker(
            &mut rng,
            tf.chainstate.get_chain_config().min_stake_pool_pledge(),
            vrf_pk,
        );

        let stake_pool_outpoint = UtxoOutPoint::new(tf.genesis().get_id().into(), 0);
        let pool_id = pos_accounting::make_pool_id(&stake_pool_outpoint);
        let delegation_id = pos_accounting::make_delegation_id(&stake_pool_outpoint);
        let amount_to_delegate = Amount::from_atoms(rng.gen_range(1..100_000));

        let delegate_staking_tx = TransactionBuilder::new()
            .add_input(TxInput::Utxo(stake_pool_outpoint), empty_witness(&mut rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .add_output(TxOutput::CreateDelegationId(
                Destination::AnyoneCanSpend,
                pool_id,
            ))
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .build();

        tf.make_block_builder()
            .add_transaction(delegate_staking_tx)
            .build_and_process(&mut rng)
            .unwrap();

        // use regtest with pos for new tx
        let chain_config = common::chain::config::Builder::new(ChainType::Regtest)
            .consensus_upgrades(NetUpgrades::regtest_with_pos())
            .build();
        let required_maturity_distance =
            chain_config.staking_pool_spend_maturity_block_count(BlockHeight::new(2));
        let maturity_distance = rng.gen_range(
            required_maturity_distance.to_int()..(required_maturity_distance.to_int() * 2),
        );

        let spend_share_outputs =
            test_utils::split_value(&mut rng, amount_to_delegate.into_atoms() / 2)
                .into_iter()
                .map(|value| {
                    TxOutput::LockThenTransfer(
                        OutputValue::Coin(Amount::from_atoms(value)),
                        Destination::AnyoneCanSpend,
                        OutputTimeLock::ForBlockCount(maturity_distance),
                    )
                })
                .collect::<Vec<_>>();

        let expected_fee =
            Fee((amount_to_delegate / 2).and_then(|v| amount_to_delegate - v).unwrap());

        let spend_share_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_account(
                    AccountNonce::new(0),
                    AccountSpending::DelegationBalance(delegation_id, amount_to_delegate),
                ),
                empty_witness(&mut rng),
            )
            .with_outputs(spend_share_outputs)
            .build();

        let mut verifier = TransactionVerifier::new(&storage, &chain_config);

        let tx_source = TransactionSourceForConnect::Mempool {
            current_best: &tf.best_block_index(),
            effective_height: BlockHeight::new(2),
        };

        let actual_fee = verifier
            .connect_transaction(&tx_source, &spend_share_tx, &tf.genesis().timestamp())
            .unwrap()
            .map_into_block_fees(&chain_config, BlockHeight::new(1))
            .unwrap();
        assert_eq!(expected_fee, actual_fee);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_fungible_token_v0(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let storage = TestStore::new_empty().unwrap();

        let tf = TestFramework::builder(&mut rng)
            .with_storage(storage.clone())
            .with_chain_config(
                common::chain::config::Builder::test_chain()
                    .chainstate_upgrades(
                        common::chain::NetUpgrades::initialize(vec![(
                            BlockHeight::zero(),
                            ChainstateUpgradeBuilder::latest()
                                .token_issuance_version(TokenIssuanceVersion::V0)
                                .build(),
                        )])
                        .unwrap(),
                    )
                    .genesis_unittest(Destination::AnyoneCanSpend)
                    .build(),
            )
            .build();
        let storage = InMemoryStorageWrapper::new(storage, tf.chain_config().as_ref().clone());

        let issuance = TokenIssuanceV0 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            amount_to_issue: Amount::from_atoms(100),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
        };

        let token_issuance_fee = tf.chain_config().fungible_token_issuance_fee();

        let genesis_amount = chainstate_test_framework::get_output_value(&tf.genesis().utxos()[0])
            .unwrap()
            .coin_amount()
            .unwrap();
        let expected_fee = Fee((genesis_amount - token_issuance_fee).unwrap());

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tf.genesis().get_id().into(), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Transfer(
                issuance.into(),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Burn(OutputValue::Coin(token_issuance_fee)))
            .build();

        let mut verifier = TransactionVerifier::new(&storage, tf.chain_config().as_ref());

        let tx_source = TransactionSourceForConnect::Mempool {
            current_best: &tf.best_block_index(),
            effective_height: BlockHeight::new(1),
        };

        let actual_fee = verifier
            .connect_transaction(&tx_source, &tx, &tf.genesis().timestamp())
            .unwrap()
            .map_into_block_fees(tf.chain_config(), BlockHeight::new(1))
            .unwrap();
        assert_eq!(expected_fee, actual_fee);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn issue_fungible_token_v1(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (chain_config, storage, tf) = setup(&mut rng);

        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
            authority: Destination::AnyoneCanSpend,
            is_freezable: IsTokenFreezable::No,
        });

        let genesis_amount = chainstate_test_framework::get_output_value(&tf.genesis().utxos()[0])
            .unwrap()
            .coin_amount()
            .unwrap();
        let expected_fee =
            Fee((genesis_amount - chain_config.fungible_token_issuance_fee()).unwrap());

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tf.genesis().get_id().into(), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::IssueFungibleToken(Box::new(issuance)))
            .build();

        let mut verifier = TransactionVerifier::new(&storage, &chain_config);

        let tx_source = TransactionSourceForConnect::Mempool {
            current_best: &tf.best_block_index(),
            effective_height: BlockHeight::new(1),
        };

        let actual_fee = verifier
            .connect_transaction(&tx_source, &tx, &tf.genesis().timestamp())
            .unwrap()
            .map_into_block_fees(&chain_config, BlockHeight::new(1))
            .unwrap();
        assert_eq!(expected_fee, actual_fee);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tokens_cannot_be_used_in_fee(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (chain_config, storage, mut tf) = setup(&mut rng);

        let issuance = TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: random_ascii_alphanumeric_string(&mut rng, 1..5).as_bytes().to_vec(),
            number_of_decimals: rng.gen_range(1..18),
            metadata_uri: random_ascii_alphanumeric_string(&mut rng, 1..1024).as_bytes().to_vec(),
            total_supply: TokenTotalSupply::Unlimited,
            authority: Destination::AnyoneCanSpend,
            is_freezable: IsTokenFreezable::No,
        });

        let token_issuance_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tf.genesis().get_id().into(), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::IssueFungibleToken(Box::new(issuance)))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(
                    (chain_config.token_supply_change_fee(BlockHeight::zero()) * 2).unwrap(),
                ),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let token_issuance_tx_id = token_issuance_tx.transaction().get_id();
        let token_id = make_token_id(token_issuance_tx.transaction().inputs()).unwrap();

        let amount_to_mint = Amount::from_atoms(rng.gen_range(1..100_000));
        let token_mint_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(token_issuance_tx_id.into(), 1),
                empty_witness(&mut rng),
            )
            .add_input(
                TxInput::from_command(
                    AccountNonce::new(0),
                    AccountCommand::MintTokens(token_id, amount_to_mint),
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(chain_config.token_supply_change_fee(BlockHeight::zero())),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let token_mint_tx_id = token_mint_tx.transaction().get_id();

        tf.make_block_builder()
            .with_transactions(vec![token_issuance_tx, token_mint_tx])
            .build_and_process(&mut rng)
            .unwrap();

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(token_mint_tx_id.into(), 0),
                empty_witness(&mut rng),
            )
            .add_input(
                TxInput::from_utxo(token_mint_tx_id.into(), 1),
                empty_witness(&mut rng),
            )
            .build();

        let mut verifier = TransactionVerifier::new(&storage, &chain_config);

        let tx_source = TransactionSourceForConnect::Mempool {
            current_best: &tf.best_block_index(),
            effective_height: BlockHeight::new(1),
        };

        let expected_fee = Fee(chain_config.token_supply_change_fee(BlockHeight::zero()));
        let actual_fee = verifier
            .connect_transaction(&tx_source, &tx, &tf.genesis().timestamp())
            .unwrap()
            .map_into_block_fees(&chain_config, BlockHeight::new(1))
            .unwrap();
        assert_eq!(expected_fee, actual_fee);
    });
}
