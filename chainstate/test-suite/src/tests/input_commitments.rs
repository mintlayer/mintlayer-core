// Copyright (c) 2021-2025 RBB S.r.l
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

use std::borrow::Cow;

use itertools::Itertools as _;
use rstest::rstest;

use chainstate::{
    chainstate_interface::ChainstateInterface, BlockError, ChainstateError, ConnectTransactionError,
};
use chainstate_test_framework::{
    create_chain_config_with_staking_pool, empty_witness, PoSBlockBuilder, TestFramework,
    TransactionBuilder,
};
use common::{
    chain::{
        self,
        config::create_unit_test_config,
        make_order_id,
        output_value::OutputValue,
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            sighash::input_commitments::SighashInputCommitment,
            DestinationSigError,
        },
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{IsTokenFreezable, TokenTotalSupply},
        AccountCommand, AccountNonce, ChainstateUpgradeBuilder, Destination, OrderAccountCommand,
        OrderData, OrderId, OrdersVersion, OutPointSourceId, PoolId, SighashInputCommitmentVersion,
        SignedTransaction, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Idable, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{transcript::with_rng::RngCoreAndCrypto, VRFKeyKind, VRFPrivateKey, VRFPublicKey},
};
use logging::log;
use randomness::{CryptoRng, Rng};
use test_utils::{
    assert_matches_return_val,
    random::{make_seedable_rng, Seed},
};
use tx_verifier::{
    error::{InputCheckError, ScriptError},
    input_check::InputCheckErrorPayload,
};

use crate::tests::helpers::calculate_fill_order;

use super::helpers::issue_and_mint_random_token_from_best_block;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn pool_decommissioning(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let genesis_pool_id = PoolId::new(H256::random_using(&mut rng));
    let genesis_pool_info = PoolInfoForStaking::new_random(&mut rng, genesis_pool_id);

    let min_pledge = create_unit_test_config().min_stake_pool_pledge();
    let genesis_pool_pledge_amount = min_pledge;

    let genesis_output_amount = Amount::from_atoms(
        rng.gen_range(min_pledge.into_atoms() * 5..min_pledge.into_atoms() * 10),
    );

    let blocks_to_produce_by_another_pool = rng.gen_range(1..=3);
    // This is the number of blocks after "another pool" has produced its last block until
    // the fork to SighashInputCommitmentVersion::V1 happens. We want it to be non-zero,
    // so that we can try V0 commitments too.
    let fork_distance_after_setup_finished = rng.gen_range(1..=3);
    // Add 1 to account for the block that creates "another pool".
    // Add another 1 because we're interested in what happens on "next_block_height" after the setup is finished.
    let fork_height = BlockHeight::new(
        1 + 1 + blocks_to_produce_by_another_pool + fork_distance_after_setup_finished,
    );

    let chain_config = create_chain_config_with_staking_pool(
        &mut rng,
        genesis_output_amount,
        genesis_pool_id,
        genesis_pool_info.new_stake_pool_data_with_all_reward_to_staker(genesis_pool_pledge_amount),
    )
    .chainstate_upgrades(
        common::chain::NetUpgrades::initialize(vec![
            (
                BlockHeight::zero(),
                ChainstateUpgradeBuilder::latest()
                    .sighash_input_commitment_version(SighashInputCommitmentVersion::V0)
                    .build(),
            ),
            (
                fork_height,
                ChainstateUpgradeBuilder::latest()
                    .sighash_input_commitment_version(SighashInputCommitmentVersion::V1)
                    .build(),
            ),
        ])
        .unwrap(),
    )
    .build();

    let target_block_spacing = chain_config.target_block_spacing();

    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config.clone()).build();
    tf.progress_time_seconds_since_epoch(target_block_spacing.as_secs());

    let coins_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );

    let min_pledge = tf.chain_config().min_stake_pool_pledge();
    let staking_pool_spend_maturity_block_count =
        tf.chain_config().staking_pool_spend_maturity_block_count(1.into()).to_int();

    let another_pool_pledge_amount =
        Amount::from_atoms(rng.gen_range(min_pledge.into_atoms()..min_pledge.into_atoms() * 2));

    let another_pool_id = PoolId::from_utxo(&coins_outpoint);
    let another_pool_info = PoolInfoForStaking::new_random(&mut rng, another_pool_id);

    let another_pool_creation_tx = TransactionBuilder::new()
        .add_input(coins_outpoint.into(), empty_witness(&mut rng))
        .add_output(TxOutput::CreateStakePool(
            another_pool_id,
            Box::new(
                another_pool_info
                    .new_stake_pool_data_with_all_reward_to_staker(another_pool_pledge_amount),
            ),
        ))
        .build();

    genesis_pool_info
        .make_block_builder(&mut tf)
        .add_transaction(another_pool_creation_tx)
        .build_and_process(&mut rng)
        .unwrap();

    for _ in 0..blocks_to_produce_by_another_pool {
        another_pool_info
            .make_block_builder(&mut tf)
            .build_and_process(&mut rng)
            .unwrap();
    }

    let last_block_by_another_pool_id = tf.best_block_id();
    let produce_block_outpoint = UtxoOutPoint::new(last_block_by_another_pool_id.into(), 0);

    let make_another_pool_decommission_txs =
        |tf: &TestFramework,
         mut rng: &mut dyn RngCoreAndCrypto,
         current_commitment_version: SighashInputCommitmentVersion| {
            let produce_block_utxo = tf.utxo(&produce_block_outpoint).take_output();

            let staker_balance = tf
                .pos_accounting_data_at_tip()
                .pool_data
                .get(&another_pool_info.id)
                .unwrap()
                .staker_balance()
                .unwrap();

            let tx = Transaction::new(
                0,
                vec![produce_block_outpoint.clone().into()],
                vec![TxOutput::LockThenTransfer(
                    OutputValue::Coin(staker_balance),
                    Destination::AnyoneCanSpend,
                    OutputTimeLock::ForBlockCount(staking_pool_spend_maturity_block_count),
                )],
            )
            .unwrap();

            let bad_utxo = {
                let (dest, pool_id) = assert_matches_return_val!(
                    &produce_block_utxo,
                    TxOutput::ProduceBlockFromStake(dest, pool_id),
                    (dest, pool_id)
                );
                assert_eq!(*pool_id, another_pool_info.id);
                TxOutput::ProduceBlockFromStake(dest.clone(), genesis_pool_info.id)
            };

            let (good_commitments, bad_commitments) = {
                let good_commitments_v0 =
                    vec![SighashInputCommitment::Utxo(Cow::Borrowed(&produce_block_utxo))];
                let good_commitments_v1 = vec![SighashInputCommitment::ProduceBlockFromStakeUtxo {
                    utxo: Cow::Borrowed(&produce_block_utxo),
                    staker_balance,
                }];

                let bad_staker_balance = amount_variation(&mut rng, staker_balance);

                let mut bad_commitments = vec![
                    vec![SighashInputCommitment::Utxo(Cow::Borrowed(&bad_utxo))],
                    vec![SighashInputCommitment::ProduceBlockFromStakeUtxo {
                        utxo: Cow::Borrowed(&bad_utxo),
                        staker_balance,
                    }],
                    vec![SighashInputCommitment::ProduceBlockFromStakeUtxo {
                        utxo: Cow::Borrowed(&produce_block_utxo),
                        staker_balance: bad_staker_balance,
                    }],
                ];

                match current_commitment_version {
                    SighashInputCommitmentVersion::V0 => {
                        bad_commitments.push(good_commitments_v1);
                        (good_commitments_v0, bad_commitments)
                    }
                    SighashInputCommitmentVersion::V1 => {
                        bad_commitments.push(good_commitments_v0);
                        (good_commitments_v1, bad_commitments)
                    }
                }
            };

            let good_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &another_pool_info.decommission_sk,
                Default::default(),
                another_pool_info.decommission_dest.clone(),
                &tx,
                &good_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            let good_tx =
                SignedTransaction::new(tx.clone(), vec![InputWitness::Standard(good_sig)]).unwrap();

            let bad_txs = bad_commitments
                .into_iter()
                .map(|bad_comm| {
                    let bad_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                        &another_pool_info.decommission_sk,
                        Default::default(),
                        another_pool_info.decommission_dest.clone(),
                        &tx,
                        &bad_comm,
                        0,
                        &mut rng,
                    )
                    .unwrap();
                    SignedTransaction::new(tx.clone(), vec![InputWitness::Standard(bad_sig)])
                        .unwrap()
                })
                .collect_vec();

            (good_tx, bad_txs)
        };

    // Sanity check
    assert!(tf.next_block_height() < fork_height);

    {
        let (good_tx, bad_txs) =
            make_another_pool_decommission_txs(&tf, &mut rng, SighashInputCommitmentVersion::V0);

        check_txs_pos(&genesis_pool_info, &mut tf, &mut rng, good_tx, bad_txs);
    }

    // Get rid of the block that has decommissioned the pool so that we can try doing it again.
    invalidate_tip(&mut tf);

    {
        for _ in 0..fork_distance_after_setup_finished {
            genesis_pool_info
                .make_block_builder(&mut tf)
                .build_and_process(&mut rng)
                .unwrap();
        }
    }

    // Sanity check
    assert!(tf.next_block_height() >= fork_height);

    {
        let (good_tx, bad_txs) =
            make_another_pool_decommission_txs(&tf, &mut rng, SighashInputCommitmentVersion::V1);

        check_txs_pos(&genesis_pool_info, &mut tf, &mut rng, good_tx, bad_txs);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn order_fill(#[case] seed: Seed, #[case] orders_version: OrdersVersion) {
    let mut rng = make_seedable_rng(seed);

    let fork_distance_after_setup_finished = rng.gen_range(1..=3);

    // Add 4 to account for creating and minting a token and creating and partially filling an order.
    // Add another 1 because we're interested in what happens on "next_block_height" after the setup is finished.
    let fork_height = BlockHeight::new(4 + 1 + fork_distance_after_setup_finished);

    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(
            chain::config::Builder::test_chain()
                .chainstate_upgrades(
                    common::chain::NetUpgrades::initialize(vec![
                        (
                            BlockHeight::zero(),
                            ChainstateUpgradeBuilder::latest()
                                .orders_version(orders_version)
                                .sighash_input_commitment_version(SighashInputCommitmentVersion::V0)
                                .build(),
                        ),
                        (
                            fork_height,
                            ChainstateUpgradeBuilder::latest()
                                .orders_version(orders_version)
                                .sighash_input_commitment_version(SighashInputCommitmentVersion::V1)
                                .build(),
                        ),
                    ])
                    .unwrap(),
                )
                .build(),
        )
        .build();

    let coins_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );

    let token_amount_to_mint = Amount::from_atoms(rng.gen_range(1_000_000..2_000_000));
    let (token_id, tokens_outpoint, coins_outpoint) = issue_and_mint_random_token_from_best_block(
        &mut rng,
        &mut tf,
        coins_outpoint,
        token_amount_to_mint,
        TokenTotalSupply::Unlimited,
        IsTokenFreezable::Yes,
    );
    let coins_left = tf.coin_amount_from_utxo(&coins_outpoint);

    let initial_ask_amount = Amount::from_atoms(rng.gen_range(10..1000));
    let initial_give_amount =
        Amount::from_atoms(rng.gen_range(10..=token_amount_to_mint.into_atoms()));
    let initially_asked = OutputValue::Coin(initial_ask_amount);
    let initially_given = OutputValue::TokenV1(token_id, initial_give_amount);
    let order_data = OrderData::new(
        Destination::AnyoneCanSpend,
        initially_asked.clone(),
        initially_given.clone(),
    );

    let order_creation_tx = TransactionBuilder::new()
        .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
        .add_output(TxOutput::CreateOrder(Box::new(order_data)))
        .build();
    let order_id = make_order_id(order_creation_tx.inputs()).unwrap();

    tf.make_block_builder()
        .add_transaction(order_creation_tx)
        .build_and_process(&mut rng)
        .unwrap();

    let fill_amount = Amount::from_atoms(rng.gen_range(1..initial_ask_amount.into_atoms() / 2));
    let filled_amount = calculate_fill_order(&tf, &order_id, fill_amount, orders_version);
    let left_to_fill = (initial_ask_amount - fill_amount).unwrap();
    let coins_left = (coins_left - fill_amount).unwrap();

    let fill_order_input =
        make_fill_order_input(orders_version, AccountNonce::new(0), &order_id, fill_amount);

    let (coins_owner_sk, coins_owner_pk) =
        PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let coins_owner_dest = Destination::PublicKey(coins_owner_pk);

    let order_fill_tx = TransactionBuilder::new()
        .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
        .add_input(fill_order_input, InputWitness::NoSignature(None))
        .add_output(TxOutput::Transfer(
            OutputValue::TokenV1(token_id, filled_amount),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(coins_left),
            coins_owner_dest.clone(),
        ))
        .build();
    let order_fill_tx_id = order_fill_tx.transaction().get_id();
    let coins_outpoint = UtxoOutPoint::new(order_fill_tx_id.into(), 1);

    tf.make_block_builder()
        .add_transaction(order_fill_tx)
        .build_and_process(&mut rng)
        .unwrap();

    // Here we'll create FillOrder txs that actually require signing.
    let make_fill_order_txs =
        |tf: &TestFramework,
         mut rng: &mut dyn RngCoreAndCrypto,
         current_commitment_version: SighashInputCommitmentVersion| {
            let fill_amount = Amount::from_atoms(rng.gen_range(1..left_to_fill.into_atoms() / 2));
            let filled_amount = calculate_fill_order(tf, &order_id, fill_amount, orders_version);

            let fill_order_input =
                make_fill_order_input(orders_version, AccountNonce::new(1), &order_id, fill_amount);

            let tx = Transaction::new(
                0,
                vec![coins_outpoint.clone().into(), fill_order_input],
                vec![TxOutput::Transfer(
                    OutputValue::TokenV1(token_id, filled_amount),
                    Destination::AnyoneCanSpend,
                )],
            )
            .unwrap();

            let coins_utxo = tf.utxo(&coins_outpoint).take_output();
            let bad_coins_utxo = {
                let (dest, amount) = assert_matches_return_val!(
                    &coins_utxo,
                    TxOutput::Transfer(OutputValue::Coin(amount), dest),
                    (dest, amount)
                );
                TxOutput::Transfer(
                    OutputValue::Coin(amount_variation(&mut rng, *amount)),
                    dest.clone(),
                )
            };

            let (good_commitments, bad_commitments) = {
                let coins_utxo_commitment =
                    SighashInputCommitment::Utxo(Cow::Borrowed(&coins_utxo));

                let good_fill_order_input_commitment_v0 = SighashInputCommitment::None;
                let good_commitments_v0 = vec![
                    coins_utxo_commitment.clone(),
                    good_fill_order_input_commitment_v0.clone(),
                ];

                let initially_asked = OutputValue::Coin(initial_ask_amount);
                let initially_given = OutputValue::TokenV1(token_id, initial_give_amount);

                let good_fill_order_input_commitment_v1 =
                    SighashInputCommitment::FillOrderAccountCommand {
                        initially_asked: initially_asked.clone(),
                        initially_given: initially_given.clone(),
                    };
                let good_commitments_v1 = vec![
                    coins_utxo_commitment.clone(),
                    good_fill_order_input_commitment_v1.clone(),
                ];

                let bad_initially_asked = if rng.gen_bool(0.5) {
                    OutputValue::Coin(amount_variation(&mut rng, initial_ask_amount))
                } else {
                    OutputValue::TokenV1(token_id, initial_ask_amount)
                };
                let bad_initially_given = if rng.gen_bool(0.5) {
                    OutputValue::TokenV1(token_id, amount_variation(&mut rng, initial_give_amount))
                } else {
                    OutputValue::Coin(initial_give_amount)
                };

                let mut bad_commitments = vec![
                    vec![
                        SighashInputCommitment::Utxo(Cow::Borrowed(&bad_coins_utxo)),
                        good_fill_order_input_commitment_v0.clone(),
                    ],
                    vec![
                        SighashInputCommitment::Utxo(Cow::Borrowed(&bad_coins_utxo)),
                        good_fill_order_input_commitment_v1.clone(),
                    ],
                    vec![
                        coins_utxo_commitment.clone(),
                        SighashInputCommitment::FillOrderAccountCommand {
                            initially_asked: bad_initially_asked,
                            initially_given: initially_given.clone(),
                        },
                    ],
                    vec![
                        coins_utxo_commitment.clone(),
                        SighashInputCommitment::FillOrderAccountCommand {
                            initially_asked: initially_asked.clone(),
                            initially_given: bad_initially_given,
                        },
                    ],
                ];

                match current_commitment_version {
                    SighashInputCommitmentVersion::V0 => {
                        bad_commitments.push(good_commitments_v1);
                        (good_commitments_v0, bad_commitments)
                    }
                    SighashInputCommitmentVersion::V1 => {
                        bad_commitments.push(good_commitments_v0);
                        (good_commitments_v1, bad_commitments)
                    }
                }
            };

            let good_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &coins_owner_sk,
                Default::default(),
                coins_owner_dest.clone(),
                &tx,
                &good_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            let good_tx = SignedTransaction::new(
                tx.clone(),
                vec![InputWitness::Standard(good_sig), InputWitness::NoSignature(None)],
            )
            .unwrap();

            let bad_txs = bad_commitments
                .into_iter()
                .map(|bad_comm| {
                    let bad_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                        &coins_owner_sk,
                        Default::default(),
                        coins_owner_dest.clone(),
                        &tx,
                        &bad_comm,
                        0,
                        &mut rng,
                    )
                    .unwrap();
                    SignedTransaction::new(
                        tx.clone(),
                        vec![InputWitness::Standard(bad_sig), InputWitness::NoSignature(None)],
                    )
                    .unwrap()
                })
                .collect_vec();

            (good_tx, bad_txs)
        };

    // Sanity check
    assert!(tf.next_block_height() < fork_height);

    {
        let (good_tx, bad_txs) =
            make_fill_order_txs(&tf, &mut rng, SighashInputCommitmentVersion::V0);

        check_txs_non_pos(&mut tf, &mut rng, good_tx, bad_txs);
    }

    // Get rid of the block that has decommissioned the pool so that we can try doing it again.
    invalidate_tip(&mut tf);

    {
        for _ in 0..fork_distance_after_setup_finished {
            tf.make_block_builder().build_and_process(&mut rng).unwrap();
        }
    }

    // Sanity check
    assert!(tf.next_block_height() >= fork_height);

    {
        let (good_tx, bad_txs) =
            make_fill_order_txs(&tf, &mut rng, SighashInputCommitmentVersion::V1);

        check_txs_non_pos(&mut tf, &mut rng, good_tx, bad_txs);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), OrdersVersion::V1)]
fn order_conclude(#[case] seed: Seed, #[case] orders_version: OrdersVersion) {
    let mut rng = make_seedable_rng(seed);

    let fork_distance_after_setup_finished = rng.gen_range(1..=3);

    // Add 4 to account for creating and minting a token and creating and partially filling an order.
    // Add another 1 because we're interested in what happens on "next_block_height" after the setup is finished.
    let fork_height = BlockHeight::new(4 + 1 + fork_distance_after_setup_finished);

    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(
            chain::config::Builder::test_chain()
                .chainstate_upgrades(
                    common::chain::NetUpgrades::initialize(vec![
                        (
                            BlockHeight::zero(),
                            ChainstateUpgradeBuilder::latest()
                                .orders_version(orders_version)
                                .sighash_input_commitment_version(SighashInputCommitmentVersion::V0)
                                .build(),
                        ),
                        (
                            fork_height,
                            ChainstateUpgradeBuilder::latest()
                                .orders_version(orders_version)
                                .sighash_input_commitment_version(SighashInputCommitmentVersion::V1)
                                .build(),
                        ),
                    ])
                    .unwrap(),
                )
                .build(),
        )
        .build();

    let coins_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );

    let token_amount_to_mint = Amount::from_atoms(rng.gen_range(1_000_000..2_000_000));
    let (token_id, tokens_outpoint, coins_outpoint) = issue_and_mint_random_token_from_best_block(
        &mut rng,
        &mut tf,
        coins_outpoint,
        token_amount_to_mint,
        TokenTotalSupply::Unlimited,
        IsTokenFreezable::Yes,
    );
    let coins_left = tf.coin_amount_from_utxo(&coins_outpoint);

    let (order_owner_sk, order_owner_pk) =
        PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let order_owner_dest = Destination::PublicKey(order_owner_pk);

    let initial_ask_amount = Amount::from_atoms(rng.gen_range(10..1000));
    let initial_give_amount =
        Amount::from_atoms(rng.gen_range(10..=token_amount_to_mint.into_atoms()));
    let initially_asked = OutputValue::Coin(initial_ask_amount);
    let initially_given = OutputValue::TokenV1(token_id, initial_give_amount);
    let order_data = OrderData::new(
        order_owner_dest.clone(),
        initially_asked.clone(),
        initially_given.clone(),
    );

    let order_creation_tx = TransactionBuilder::new()
        .add_input(tokens_outpoint.into(), InputWitness::NoSignature(None))
        .add_output(TxOutput::CreateOrder(Box::new(order_data)))
        .build();
    let order_id = make_order_id(order_creation_tx.inputs()).unwrap();

    tf.make_block_builder()
        .add_transaction(order_creation_tx)
        .build_and_process(&mut rng)
        .unwrap();

    let fill_amount = Amount::from_atoms(rng.gen_range(1..initial_ask_amount.into_atoms() / 2));
    let filled_amount = calculate_fill_order(&tf, &order_id, fill_amount, orders_version);
    let ask_balance = (initial_ask_amount - fill_amount).unwrap();
    let give_balance = (initial_give_amount - filled_amount).unwrap();
    let coins_left = (coins_left - fill_amount).unwrap();

    let fill_order_input =
        make_fill_order_input(orders_version, AccountNonce::new(0), &order_id, fill_amount);

    let order_fill_tx = TransactionBuilder::new()
        .add_input(coins_outpoint.into(), InputWitness::NoSignature(None))
        .add_input(fill_order_input, InputWitness::NoSignature(None))
        .add_output(TxOutput::Transfer(
            OutputValue::TokenV1(token_id, filled_amount),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(coins_left),
            Destination::AnyoneCanSpend,
        ))
        .build();

    tf.make_block_builder()
        .add_transaction(order_fill_tx)
        .build_and_process(&mut rng)
        .unwrap();

    let make_conclude_order_txs =
        |mut rng: &mut dyn RngCoreAndCrypto,
         current_commitment_version: SighashInputCommitmentVersion| {
            let conclude_order_input =
                make_conclude_order_input(orders_version, AccountNonce::new(1), &order_id);

            let tx = Transaction::new(
                0,
                vec![conclude_order_input],
                vec![
                    TxOutput::Transfer(
                        OutputValue::TokenV1(token_id, give_balance),
                        Destination::AnyoneCanSpend,
                    ),
                    TxOutput::Transfer(OutputValue::Coin(fill_amount), Destination::AnyoneCanSpend),
                ],
            )
            .unwrap();

            let (good_commitments, bad_commitments) = {
                let good_commitments_v0 = vec![SighashInputCommitment::None];
                let good_commitments_v1 =
                    vec![SighashInputCommitment::ConcludeOrderAccountCommand {
                        initially_asked: initially_asked.clone(),
                        initially_given: initially_given.clone(),
                        ask_balance,
                        give_balance,
                    }];

                let bad_initially_asked = if rng.gen_bool(0.5) {
                    OutputValue::Coin(amount_variation(&mut rng, initial_ask_amount))
                } else {
                    OutputValue::TokenV1(token_id, initial_ask_amount)
                };
                let bad_initially_given = if rng.gen_bool(0.5) {
                    OutputValue::TokenV1(token_id, amount_variation(&mut rng, initial_give_amount))
                } else {
                    OutputValue::Coin(initial_give_amount)
                };

                let bad_ask_balance = amount_variation(&mut rng, ask_balance);
                let bad_give_balance = amount_variation(&mut rng, give_balance);

                let mut bad_commitments = vec![
                    vec![SighashInputCommitment::ConcludeOrderAccountCommand {
                        initially_asked: bad_initially_asked,
                        initially_given: initially_given.clone(),
                        ask_balance,
                        give_balance,
                    }],
                    vec![SighashInputCommitment::ConcludeOrderAccountCommand {
                        initially_asked: initially_asked.clone(),
                        initially_given: bad_initially_given,
                        ask_balance,
                        give_balance,
                    }],
                    vec![SighashInputCommitment::ConcludeOrderAccountCommand {
                        initially_asked: initially_asked.clone(),
                        initially_given: initially_given.clone(),
                        ask_balance: bad_ask_balance,
                        give_balance,
                    }],
                    vec![SighashInputCommitment::ConcludeOrderAccountCommand {
                        initially_asked: initially_asked.clone(),
                        initially_given: initially_given.clone(),
                        ask_balance,
                        give_balance: bad_give_balance,
                    }],
                ];

                match current_commitment_version {
                    SighashInputCommitmentVersion::V0 => {
                        bad_commitments.push(good_commitments_v1);
                        (good_commitments_v0, bad_commitments)
                    }
                    SighashInputCommitmentVersion::V1 => {
                        bad_commitments.push(good_commitments_v0);
                        (good_commitments_v1, bad_commitments)
                    }
                }
            };

            let good_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                &order_owner_sk,
                Default::default(),
                order_owner_dest.clone(),
                &tx,
                &good_commitments,
                0,
                &mut rng,
            )
            .unwrap();

            let good_tx =
                SignedTransaction::new(tx.clone(), vec![InputWitness::Standard(good_sig)]).unwrap();

            let bad_txs = bad_commitments
                .into_iter()
                .map(|bad_comm| {
                    let bad_sig = StandardInputSignature::produce_uniparty_signature_for_input(
                        &order_owner_sk,
                        Default::default(),
                        order_owner_dest.clone(),
                        &tx,
                        &bad_comm,
                        0,
                        &mut rng,
                    )
                    .unwrap();
                    SignedTransaction::new(tx.clone(), vec![InputWitness::Standard(bad_sig)])
                        .unwrap()
                })
                .collect_vec();

            (good_tx, bad_txs)
        };

    // Sanity check
    assert!(tf.next_block_height() < fork_height);

    {
        let (good_tx, bad_txs) =
            make_conclude_order_txs(&mut rng, SighashInputCommitmentVersion::V0);

        check_txs_non_pos(&mut tf, &mut rng, good_tx, bad_txs);
    }

    // Get rid of the block that has decommissioned the pool so that we can try doing it again.
    invalidate_tip(&mut tf);

    {
        for _ in 0..fork_distance_after_setup_finished {
            tf.make_block_builder().build_and_process(&mut rng).unwrap();
        }
    }

    // Sanity check
    assert!(tf.next_block_height() >= fork_height);

    {
        let (good_tx, bad_txs) =
            make_conclude_order_txs(&mut rng, SighashInputCommitmentVersion::V1);

        check_txs_non_pos(&mut tf, &mut rng, good_tx, bad_txs);
    }
}

fn make_fill_order_input(
    orders_version: OrdersVersion,
    nonce: AccountNonce,
    order_id: &OrderId,
    fill_amount: Amount,
) -> TxInput {
    match orders_version {
        OrdersVersion::V0 => TxInput::AccountCommand(
            nonce,
            AccountCommand::FillOrder(*order_id, fill_amount, Destination::AnyoneCanSpend),
        ),
        OrdersVersion::V1 => {
            TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(*order_id, fill_amount))
        }
    }
}

fn make_conclude_order_input(
    orders_version: OrdersVersion,
    nonce: AccountNonce,
    order_id: &OrderId,
) -> TxInput {
    match orders_version {
        OrdersVersion::V0 => {
            TxInput::AccountCommand(nonce, AccountCommand::ConcludeOrder(*order_id))
        }
        OrdersVersion::V1 => {
            TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(*order_id))
        }
    }
}

fn amount_variation(rng: &mut (impl Rng + CryptoRng), amount: Amount) -> Amount {
    if rng.gen_bool(0.5) {
        (amount - Amount::from_atoms(1)).unwrap()
    } else {
        (amount + Amount::from_atoms(1)).unwrap()
    }
}

// Try to create a block from each of bad_txs, expect failure. Try to create a block from good_tx, expect success.
fn check_txs_pos(
    pool_info: &PoolInfoForStaking,
    tf: &mut TestFramework,
    rng: &mut (impl Rng + CryptoRng),
    good_tx: SignedTransaction,
    bad_txs: Vec<SignedTransaction>,
) {
    for (idx, bad_tx) in bad_txs.into_iter().enumerate() {
        log::debug!("Checking bad tx #{idx}");

        let err = pool_info
            .make_block_builder(tf)
            .add_transaction(bad_tx)
            .build_and_process(rng)
            .unwrap_err();

        assert_eq!(
            err,
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    InputCheckErrorPayload::Verification(ScriptError::Signature(
                        DestinationSigError::SignatureVerificationFailed
                    ))
                ))
            ))
        );
    }

    pool_info
        .make_block_builder(tf)
        .add_transaction(good_tx)
        .build_and_process(rng)
        .unwrap();
}

fn check_txs_non_pos(
    tf: &mut TestFramework,
    rng: &mut (impl Rng + CryptoRng),
    good_tx: SignedTransaction,
    bad_txs: Vec<SignedTransaction>,
) {
    for (idx, bad_tx) in bad_txs.into_iter().enumerate() {
        log::debug!("Checking bad tx #{idx}");

        let err = tf
            .make_block_builder()
            .add_transaction(bad_tx)
            .build_and_process(rng)
            .unwrap_err();

        assert_eq!(
            err,
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::InputCheck(InputCheckError::new(
                    0,
                    InputCheckErrorPayload::Verification(ScriptError::Signature(
                        DestinationSigError::SignatureVerificationFailed
                    ))
                ))
            ))
        );
    }

    tf.make_block_builder().add_transaction(good_tx).build_and_process(rng).unwrap();
}

fn invalidate_tip(tf: &mut TestFramework) {
    let tip_id = tf.best_block_id().classify(tf.chain_config()).chain_block_id().unwrap();
    tf.chainstate.invalidate_block(&tip_id).unwrap();
}

struct PoolInfoForStaking {
    id: PoolId,
    vrf_sk: VRFPrivateKey,
    vrf_pk: VRFPublicKey,
    staking_sk: PrivateKey,
    staking_dest: Destination,
    decommission_sk: PrivateKey,
    decommission_dest: Destination,
}

impl PoolInfoForStaking {
    fn new_random(rng: &mut (impl Rng + CryptoRng), id: PoolId) -> Self {
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
        let (staking_sk, staking_pk) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
        let staking_dest = Destination::PublicKey(staking_pk);
        let (decommission_sk, decommission_pk) =
            PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
        let decommission_dest = Destination::PublicKey(decommission_pk);

        Self {
            id,
            vrf_sk,
            vrf_pk,
            staking_sk,
            staking_dest,
            decommission_sk,
            decommission_dest,
        }
    }

    fn new_stake_pool_data_with_all_reward_to_staker(&self, pledge: Amount) -> StakePoolData {
        StakePoolData::new(
            pledge,
            self.staking_dest.clone(),
            self.vrf_pk.clone(),
            self.decommission_dest.clone(),
            PerThousand::new(1000).unwrap(),
            Amount::from_atoms(0),
        )
    }

    fn make_block_builder<'a>(&self, tf: &'a mut TestFramework) -> PoSBlockBuilder<'a> {
        let kernel_input = tf.find_kernel_outpoint_for_pool(&self.id).unwrap();

        tf.make_pos_block_builder()
            .with_stake_pool_id(self.id)
            .with_stake_spending_key(self.staking_sk.clone())
            .with_vrf_key(self.vrf_sk.clone())
            .with_kernel_input(kernel_input)
    }
}
