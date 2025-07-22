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

use std::{collections::BTreeMap, sync::Arc};

use itertools::Itertools as _;
use rstest::rstest;

use chainstate::ChainInfo;
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        block::timestamp::BlockTimestamp,
        config::create_regtest,
        htlc::{HashedTimelockContract, HtlcSecret, HtlcSecretHash},
        output_value::OutputValue,
        timelock::OutputTimeLock,
        tokens::{RPCTokenInfo, TokenId},
        Destination, OrderData, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id, Idable},
};
use node_comm::{mock::ClonableMockNodeInterface, node_traits::MockNodeInterface};
use randomness::Rng;
use test_utils::{
    assert_matches_return_val,
    random::{gen_random_alnum_string, make_seedable_rng, Seed},
};
use wallet::{
    account::TransactionToSign, wallet::test_helpers::create_wallet_with_mnemonic,
    wallet_events::WalletEventsNoOp,
};
use wallet_types::partially_signed_transaction::{TokenAdditionalInfo, TxAdditionalInfo};

use crate::{
    runtime_wallet::RuntimeWallet,
    tests::test_utils::{
        assert_fees, create_block_scan_wallet, random_rpc_ft_info_with_id_ticker_decimals,
        tx_with_outputs, wallet_new_dest, MNEMONIC,
    },
    Controller,
};

#[rstest]
#[trace]
#[case(Seed::from_entropy(), false)]
#[trace]
#[case(Seed::from_entropy(), true)]
#[tokio::test]
async fn general_test(#[case] seed: Seed, #[case] use_htlc_secret: bool) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(create_regtest());
    let mut wallet = create_wallet_with_mnemonic(Arc::clone(&chain_config), MNEMONIC);

    let token1_id = TokenId::random_using(&mut rng);
    let token2_id = TokenId::random_using(&mut rng);
    let token3_id = TokenId::random_using(&mut rng);
    let token4_id = TokenId::random_using(&mut rng);

    let token1_amount = Amount::from_atoms(rng.gen_range(1000..2000));
    let token2_amount = Amount::from_atoms(rng.gen_range(1000..2000));
    let block_reward_amount = Amount::from_atoms(rng.gen_range(1000..2000));

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
    );
    let last_height = 1;

    let token1_outpoint = UtxoOutPoint::new(tx_with_token1_id.into(), 0);
    let token2_outpoint =
        UtxoOutPoint::new(Id::<Transaction>::random_using(&mut rng).into(), rng.gen());

    let token1_num_decimals = rng.gen_range(1..20);
    let token1_ticker = gen_random_alnum_string(&mut rng, 5, 10);
    let token2_num_decimals = rng.gen_range(1..20);
    let token2_ticker = gen_random_alnum_string(&mut rng, 5, 10);
    let token3_num_decimals = rng.gen_range(1..20);
    let token3_ticker = gen_random_alnum_string(&mut rng, 5, 10);
    let token4_num_decimals = rng.gen_range(1..20);
    let token4_ticker = gen_random_alnum_string(&mut rng, 5, 10);

    let created_order_coin_give_amount = Amount::from_atoms(rng.gen_range(1000..2000));
    let create_order_output = TxOutput::CreateOrder(Box::new(OrderData::new(
        Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
        OutputValue::TokenV1(token3_id, Amount::from_atoms(rng.gen())),
        OutputValue::Coin(created_order_coin_give_amount),
    )));
    let htlc_amount = Amount::from_atoms(rng.gen_range(1000..2000));
    let htlc_spend_key = Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
    let htlc_refund_key = Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
    // Note: the wallet doesn't check that the secret and the secret hash are consistent.
    let htlc_secret = HtlcSecret::new_from_rng(&mut rng);
    let create_htlc_output = TxOutput::Htlc(
        OutputValue::TokenV1(token4_id, htlc_amount),
        Box::new(HashedTimelockContract {
            secret_hash: HtlcSecretHash::random_using(&mut rng),
            spend_key: htlc_spend_key.clone(),
            refund_timelock: OutputTimeLock::ForBlockCount(rng.gen()),
            refund_key: htlc_refund_key.clone(),
        }),
    );
    let create_htlc_outpoint =
        UtxoOutPoint::new(Id::<Transaction>::random_using(&mut rng).into(), rng.gen());

    let coins_outpoint = UtxoOutPoint::new(Id::<Transaction>::random_using(&mut rng).into(), 0);
    let coins_outpoint_amount =
        (created_order_coin_give_amount + Amount::from_atoms(rng.gen_range(1000..2000))).unwrap();
    let coins_utxo_dest = Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
    let coins_utxo = TxOutput::LockThenTransfer(
        OutputValue::Coin(coins_outpoint_amount),
        coins_utxo_dest.clone(),
        OutputTimeLock::ForBlockCount(rng.gen()),
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

        let token_infos_to_return = BTreeMap::from([
            (
                token1_id,
                RPCTokenInfo::FungibleToken(random_rpc_ft_info_with_id_ticker_decimals(
                    token1_id,
                    token1_ticker.clone(),
                    token1_num_decimals,
                    &mut rng,
                )),
            ),
            (
                token2_id,
                RPCTokenInfo::FungibleToken(random_rpc_ft_info_with_id_ticker_decimals(
                    token2_id,
                    token2_ticker.clone(),
                    token2_num_decimals,
                    &mut rng,
                )),
            ),
            (
                token3_id,
                RPCTokenInfo::FungibleToken(random_rpc_ft_info_with_id_ticker_decimals(
                    token3_id,
                    token3_ticker.clone(),
                    token3_num_decimals,
                    &mut rng,
                )),
            ),
            (
                token4_id,
                RPCTokenInfo::FungibleToken(random_rpc_ft_info_with_id_ticker_decimals(
                    token4_id,
                    token4_ticker.clone(),
                    token4_num_decimals,
                    &mut rng,
                )),
            ),
        ]);

        let chain_info_to_return = ChainInfo {
            best_block_height: BlockHeight::new(last_height),
            best_block_id: last_block.get_id().into(),
            best_block_timestamp: last_block.timestamp(),
            median_time: BlockTimestamp::from_int_seconds(rng.gen()),
            is_initial_block_download: false,
        };

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
    assert_eq!(
        composed_tx.additional_info(),
        &TxAdditionalInfo::new()
            .with_token_info(
                token1_id,
                TokenAdditionalInfo {
                    num_decimals: token1_num_decimals,
                    ticker: token1_ticker.into_bytes()
                }
            )
            .with_token_info(
                token2_id,
                TokenAdditionalInfo {
                    num_decimals: token2_num_decimals,
                    ticker: token2_ticker.into_bytes()
                }
            )
            .with_token_info(
                token3_id,
                TokenAdditionalInfo {
                    num_decimals: token3_num_decimals,
                    ticker: token3_ticker.into_bytes()
                }
            )
            .with_token_info(
                token4_id,
                TokenAdditionalInfo {
                    num_decimals: token4_num_decimals,
                    ticker: token4_ticker.into_bytes()
                }
            )
    );
}
