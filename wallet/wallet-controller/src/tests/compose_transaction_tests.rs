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

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use itertools::Itertools as _;
use rstest::rstest;

use chainstate::ChainInfo;
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        ChainConfig, Destination, OrderAccountCommand, OrderData, OrderId, Transaction, TxInput,
        TxOutput, UtxoOutPoint,
        block::timestamp::BlockTimestamp,
        config::create_regtest,
        htlc::{HashedTimelockContract, HtlcSecret, HtlcSecretHash},
        output_value::OutputValue,
        partially_signed_transaction::PartiallySignedTransactionConsistencyCheck,
        timelock::OutputTimeLock,
        tokens::{RPCTokenInfo, TokenId},
    },
    primitives::{Amount, BlockHeight, H256, Id, Idable},
};
use node_comm::{mock::ClonableMockNodeInterface, node_traits::MockNodeInterface};
use randomness::RngExt as _;
use test_utils::{
    assert_matches_return_val,
    random::{Seed, gen_random_alnum_string, make_seedable_rng},
};
use wallet::{
    account::TransactionToSign, wallet::test_helpers::create_wallet_with_mnemonic,
    wallet_events::WalletEventsNoOp,
};
use wallet_types::{
    partially_signed_transaction::{
        OrderAdditionalInfo, PartiallySignedTransaction, PtxAdditionalInfo,
    },
    wallet_type::WalletControllerMode,
};

use wallet_storage::DefaultBackend;

use crate::{
    Controller,
    helpers::get_referenced_token_ids_from_partially_signed_transaction,
    runtime_wallet::RuntimeWallet,
    tests::test_utils::{
        MNEMONIC, assert_fees, create_block_scan_wallet,
        random_rpc_ft_info_with_id_ticker_decimals, tx_with_outputs, wallet_new_dest,
    },
    types::TransactionToInspect,
};

#[rstest]
#[case(Seed::from_entropy(), false)]
#[case(Seed::from_entropy(), true)]
#[trace]
#[tokio::test]
async fn general_test(#[case] seed: Seed, #[case] use_htlc_secret: bool) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(create_regtest());
    let mut wallet = create_wallet_with_mnemonic(Arc::clone(&chain_config), MNEMONIC).await;

    let token1_id = TokenId::random_using(&mut rng);
    let token2_id = TokenId::random_using(&mut rng);
    let token3_id = TokenId::random_using(&mut rng);
    let token4_id = TokenId::random_using(&mut rng);

    let token1_amount = Amount::from_atoms(rng.random_range(1000..2000));
    let token2_amount = Amount::from_atoms(rng.random_range(1000..2000));
    let block_reward_amount = Amount::from_atoms(rng.random_range(1000..2000));

    let token1_tx_output_dest = wallet_new_dest(&mut wallet);
    let token1_tx_output = TxOutput::Transfer(
        OutputValue::TokenV1(token1_id, token1_amount),
        token1_tx_output_dest.clone(),
    );
    let tx_with_token1 = tx_with_outputs(vec![token1_tx_output.clone()]);
    let tx_with_token1_id = tx_with_token1.transaction().get_id();
    let token2_tx_output_dest = Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
    let token2_tx_output = TxOutput::Transfer(
        OutputValue::TokenV1(token2_id, token2_amount),
        token2_tx_output_dest.clone(),
    );

    let last_block = create_block_scan_wallet(
        &chain_config,
        &mut wallet,
        vec![tx_with_token1],
        block_reward_amount,
        Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
        0,
    )
    .await;
    let last_height = 1;

    let token1_outpoint = UtxoOutPoint::new(tx_with_token1_id.into(), 0);
    let token2_outpoint = UtxoOutPoint::new(
        Id::<Transaction>::random_using(&mut rng).into(),
        rng.random(),
    );

    let token4_num_decimals = rng.random_range(1..20);
    let token4_ticker = gen_random_alnum_string(&mut rng, 5, 10);

    let created_order_coin_give_amount = Amount::from_atoms(rng.random_range(1000..2000));
    let create_order_output = TxOutput::CreateOrder(Box::new(OrderData::new(
        Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
        OutputValue::TokenV1(token3_id, Amount::from_atoms(rng.random())),
        OutputValue::Coin(created_order_coin_give_amount),
    )));
    let htlc_amount = Amount::from_atoms(rng.random_range(1000..2000));
    let htlc_spend_key = Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
    let htlc_refund_key = Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
    // Note: the wallet doesn't check that the secret and the secret hash are consistent.
    let htlc_secret = HtlcSecret::new_from_rng(&mut rng);
    let create_htlc_output = TxOutput::Htlc(
        OutputValue::TokenV1(token4_id, htlc_amount),
        Box::new(HashedTimelockContract {
            secret_hash: HtlcSecretHash::random_using(&mut rng),
            spend_key: htlc_spend_key.clone(),
            refund_timelock: OutputTimeLock::ForBlockCount(rng.random()),
            refund_key: htlc_refund_key.clone(),
        }),
    );
    let create_htlc_outpoint = UtxoOutPoint::new(
        Id::<Transaction>::random_using(&mut rng).into(),
        rng.random(),
    );

    let coins_outpoint = UtxoOutPoint::new(Id::<Transaction>::random_using(&mut rng).into(), 0);
    let coins_outpoint_amount = (created_order_coin_give_amount
        + Amount::from_atoms(rng.random_range(1000..2000)))
    .unwrap();
    let coins_utxo_dest = Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
    let coins_utxo = TxOutput::LockThenTransfer(
        OutputValue::Coin(coins_outpoint_amount),
        coins_utxo_dest.clone(),
        OutputTimeLock::ForBlockCount(rng.random()),
    );

    let node_mock = {
        let mut node_mock = MockNodeInterface::new();

        let utxos_to_return = BTreeMap::from([
            // Note: token1_tx_output should already be known to the wallet,
            // since it should have seen it in a block and the address belonged to the wallet.
            (token2_outpoint.clone(), token2_tx_output.clone()),
            (coins_outpoint.clone(), coins_utxo.clone()),
            (create_htlc_outpoint.clone(), create_htlc_output.clone()),
        ]);

        let token_infos_to_return = BTreeMap::from([(
            token4_id,
            RPCTokenInfo::FungibleToken(random_rpc_ft_info_with_id_ticker_decimals(
                token4_id,
                token4_ticker.clone(),
                token4_num_decimals,
                &mut rng,
            )),
        )]);

        let chain_info_to_return = ChainInfo {
            best_block_height: BlockHeight::new(last_height),
            best_block_id: last_block.get_id().into(),
            best_block_timestamp: last_block.timestamp(),
            median_time: BlockTimestamp::from_int_seconds(rng.random()),
            is_initial_block_download: false,
        };

        node_mock.expect_is_cold_wallet_node().returning(|| WalletControllerMode::Hot);

        node_mock
            .expect_get_utxo()
            .returning(move |outpoint| Ok(Some(utxos_to_return.get(&outpoint).unwrap().clone())));

        node_mock.expect_get_token_info().returning(move |token_id| {
            Ok(Some(token_infos_to_return.get(&token_id).unwrap().clone()))
        });

        node_mock
            .expect_chainstate_info()
            .returning(move || Ok(chain_info_to_return.clone()));

        node_mock
            .expect_mempool_subscribe_to_events()
            .returning(|| Ok(Box::new(futures::stream::empty())));

        node_mock
    };

    let controller = Controller::new(
        Arc::clone(&chain_config),
        ClonableMockNodeInterface::from_mock(node_mock),
        RuntimeWallet::Software(wallet),
        WalletEventsNoOp,
    )
    .await
    .unwrap();

    let inputs = vec![token1_outpoint, token2_outpoint, coins_outpoint, create_htlc_outpoint];
    let inputs_utxos = vec![token1_tx_output, token2_tx_output, coins_utxo, create_htlc_output];
    let expected_htlc_dest = if use_htlc_secret {
        htlc_spend_key
    } else {
        htlc_refund_key
    };
    let expected_inputs_destinations = vec![
        Some(token1_tx_output_dest),
        Some(token2_tx_output_dest),
        Some(coins_utxo_dest),
        Some(expected_htlc_dest),
    ];
    let outputs = vec![
        TxOutput::Transfer(
            OutputValue::TokenV1(token1_id, token1_amount),
            Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
        ),
        TxOutput::Transfer(
            OutputValue::TokenV1(token2_id, token2_amount),
            Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
        ),
        create_order_output,
    ];
    let htlc_secrets = vec![None, None, None, use_htlc_secret.then_some(htlc_secret)];
    let (composed_tx, fees) = controller
        .compose_transaction(
            inputs.clone(),
            outputs.clone(),
            Some(htlc_secrets.clone()),
            false,
        )
        .await
        .unwrap();
    let composed_tx = assert_matches_return_val!(composed_tx, TransactionToSign::Partial(tx), tx);

    let expected_coins_fee = (coins_outpoint_amount - created_order_coin_give_amount).unwrap();
    assert_fees(
        &fees,
        expected_coins_fee,
        &BTreeMap::from([(token4_id, htlc_amount)]),
        &BTreeMap::from([(token4_id, token4_num_decimals)]),
        &chain_config,
    );

    assert_eq!(
        composed_tx.tx(),
        &Transaction::new(
            0,
            inputs.into_iter().map(TxInput::Utxo).collect_vec(),
            outputs
        )
        .unwrap()
    );
    assert!(composed_tx.witnesses().iter().all(|w| w.is_none()));
    assert_eq!(
        composed_tx.input_utxos(),
        inputs_utxos.into_iter().map(Some).collect_vec()
    );
    assert_eq!(composed_tx.destinations(), &expected_inputs_destinations);
    assert_eq!(composed_tx.htlc_secrets(), &htlc_secrets);
    assert_eq!(composed_tx.additional_info(), &PtxAdditionalInfo::new());

    let expected_token_ids = BTreeSet::from([token1_id, token2_id, token3_id, token4_id]);
    let actual_token_ids = get_referenced_token_ids_from_partially_signed_transaction(&composed_tx);
    assert_eq!(actual_token_ids, expected_token_ids);
}

async fn create_controller_for_inspection(
    chain_config: &Arc<ChainConfig>,
    token_infos: BTreeMap<TokenId, RPCTokenInfo>,
    utxos_to_return: BTreeMap<UtxoOutPoint, TxOutput>,
) -> Controller<ClonableMockNodeInterface, WalletEventsNoOp, DefaultBackend> {
    let mut wallet = create_wallet_with_mnemonic(Arc::clone(chain_config), MNEMONIC).await;

    let last_block = create_block_scan_wallet(
        chain_config,
        &mut wallet,
        vec![],
        Amount::from_atoms(1000),
        Destination::AnyoneCanSpend,
        0,
    )
    .await;

    let chain_info_to_return = ChainInfo {
        best_block_height: BlockHeight::new(1),
        best_block_id: last_block.get_id().into(),
        best_block_timestamp: last_block.timestamp(),
        median_time: BlockTimestamp::from_int_seconds(0),
        is_initial_block_download: false,
    };

    let node_mock = {
        let mut node_mock = MockNodeInterface::new();

        node_mock.expect_is_cold_wallet_node().returning(|| WalletControllerMode::Hot);

        node_mock.expect_get_utxo().returning(move |outpoint| {
            Ok(Some(
                utxos_to_return
                    .get(&outpoint)
                    .unwrap_or_else(|| panic!("unexpected utxo request: {outpoint:?}"))
                    .clone(),
            ))
        });

        node_mock.expect_get_token_info().returning(move |token_id| {
            Ok(Some(
                token_infos
                    .get(&token_id)
                    .unwrap_or_else(|| panic!("unexpected token info request: {token_id:?}"))
                    .clone(),
            ))
        });

        node_mock
            .expect_chainstate_info()
            .returning(move || Ok(chain_info_to_return.clone()));

        node_mock
            .expect_mempool_subscribe_to_events()
            .returning(|| Ok(Box::new(futures::stream::empty())));

        node_mock
    };

    Controller::new(
        Arc::clone(chain_config),
        ClonableMockNodeInterface::from_mock(node_mock),
        RuntimeWallet::Software(wallet),
        WalletEventsNoOp,
    )
    .await
    .unwrap()
}

// Order conclude inputs free the escrowed balances of an order, so these amounts must be
// credited when the wallet calculates the fee/balances data of a partially signed
// transaction. Otherwise a valid transaction spending purely the freed order funds is
// rejected with "Insufficient UTXO amount".
#[rstest]
#[case(Seed::from_entropy())]
#[trace]
#[tokio::test]
async fn inspect_partially_signed_tx_with_order_conclude_input(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(create_regtest());

    let token_id = TokenId::random_using(&mut rng);
    let token_num_decimals = rng.random_range(1..20);
    let token_ticker = gen_random_alnum_string(&mut rng, 5, 10);

    // The order initially asked for 100 coins, giving 200 tokens in exchange. 30 coins have
    // been paid into the order so far, so concluding it frees 70 coins and all 200 tokens.
    let order_id = OrderId::new(H256::random_using(&mut rng));
    let order_info = OrderAdditionalInfo {
        initially_asked: OutputValue::Coin(Amount::from_atoms(100)),
        initially_given: OutputValue::TokenV1(token_id, Amount::from_atoms(200)),
        ask_balance: Amount::from_atoms(30),
        give_balance: Amount::from_atoms(200),
    };

    let freed_ask_amount = (order_info.initially_asked.amount() - order_info.ask_balance).unwrap();
    let conclude_destination = Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));

    // The freed funds are moved on, keeping 10 units of each currency as the transaction fee.
    let outputs = vec![
        TxOutput::Transfer(
            OutputValue::Coin((freed_ask_amount - Amount::from_atoms(10)).unwrap()),
            conclude_destination.clone(),
        ),
        TxOutput::Transfer(
            OutputValue::TokenV1(
                token_id,
                (order_info.give_balance - Amount::from_atoms(10)).unwrap(),
            ),
            conclude_destination,
        ),
    ];

    let tx = Transaction::new(
        0,
        vec![TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id))],
        outputs,
    )
    .unwrap();
    let ptx = PartiallySignedTransaction::new(
        tx,
        vec![None],
        vec![None],
        vec![None],
        None,
        PtxAdditionalInfo::new().with_order_info(order_id, order_info),
        PartiallySignedTransactionConsistencyCheck::WithAdditionalInfo,
    )
    .unwrap();

    let token_infos_to_return = BTreeMap::from([(
        token_id,
        RPCTokenInfo::FungibleToken(random_rpc_ft_info_with_id_ticker_decimals(
            token_id,
            token_ticker,
            token_num_decimals,
            &mut rng,
        )),
    )]);

    let controller =
        create_controller_for_inspection(&chain_config, token_infos_to_return, BTreeMap::new())
            .await;

    let inspect_result = controller
        .inspect_transaction(TransactionToInspect::Partial(ptx))
        .await
        .unwrap();

    assert_fees(
        inspect_result.fees.as_ref().unwrap(),
        Amount::from_atoms(10),
        &BTreeMap::from([(token_id, Amount::from_atoms(10))]),
        &BTreeMap::from([(token_id, token_num_decimals)]),
        &chain_config,
    );
}

// Order fill inputs consume the fill amount in the ask currency from the transaction's UTXO
// inputs and credit the filled amount in the give currency, which must be reflected in the
// fee/balances data of a partially signed transaction.
#[rstest]
#[case(Seed::from_entropy())]
#[trace]
#[tokio::test]
async fn inspect_partially_signed_tx_with_order_fill_input(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(create_regtest());

    let token_id = TokenId::random_using(&mut rng);
    let token_num_decimals = rng.random_range(1..20);
    let token_ticker = gen_random_alnum_string(&mut rng, 5, 10);

    // The order initially asked for 100 coins, giving 200 tokens in exchange, i.e. the price
    // is 2 tokens per coin. 30 coins have been filled so far. Filling 30 more coins pays
    // 30 coins into the order and returns 60 tokens to the filler.
    let order_id = OrderId::new(H256::random_using(&mut rng));
    let order_info = OrderAdditionalInfo {
        initially_asked: OutputValue::Coin(Amount::from_atoms(100)),
        initially_given: OutputValue::TokenV1(token_id, Amount::from_atoms(200)),
        ask_balance: Amount::from_atoms(70),
        give_balance: Amount::from_atoms(140),
    };
    let fill_amount_in_ask_currency = Amount::from_atoms(30);

    let coins_outpoint = UtxoOutPoint::new(Id::<Transaction>::random_using(&mut rng).into(), 0);
    let coins_utxo = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(100)),
        Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
    );

    let token_destination = Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
    let change_destination = Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));

    let outputs = vec![
        TxOutput::Transfer(
            OutputValue::TokenV1(token_id, Amount::from_atoms(60)),
            token_destination,
        ),
        TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(69)),
            change_destination,
        ),
    ];

    let tx = Transaction::new(
        0,
        vec![
            TxInput::Utxo(coins_outpoint.clone()),
            TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                order_id,
                fill_amount_in_ask_currency,
            )),
        ],
        outputs,
    )
    .unwrap();
    let ptx = PartiallySignedTransaction::new(
        tx,
        vec![None, None],
        vec![Some(coins_utxo.clone()), None],
        vec![None, None],
        None,
        PtxAdditionalInfo::new().with_order_info(order_id, order_info),
        PartiallySignedTransactionConsistencyCheck::WithAdditionalInfo,
    )
    .unwrap();

    let token_infos_to_return = BTreeMap::from([(
        token_id,
        RPCTokenInfo::FungibleToken(random_rpc_ft_info_with_id_ticker_decimals(
            token_id,
            token_ticker,
            token_num_decimals,
            &mut rng,
        )),
    )]);

    let controller = create_controller_for_inspection(
        &chain_config,
        token_infos_to_return,
        BTreeMap::from([(coins_outpoint, coins_utxo)]),
    )
    .await;

    let inspect_result = controller
        .inspect_transaction(TransactionToInspect::Partial(ptx))
        .await
        .unwrap();

    // 100 coins come from the UTXO, 30 of them are consumed by the order fill and 69 are
    // transferred on, leaving 1 coin of fee. The 60 tokens received from the order fully
    // cover the token output.
    assert_fees(
        inspect_result.fees.as_ref().unwrap(),
        Amount::from_atoms(1),
        &BTreeMap::new(),
        &BTreeMap::from([(token_id, token_num_decimals)]),
        &chain_config,
    );
}
