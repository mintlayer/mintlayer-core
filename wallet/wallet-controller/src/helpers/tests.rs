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

use std::{collections::BTreeMap, num::NonZeroU8, sync::Arc};

use itertools::Itertools as _;
use rstest::rstest;

use chainstate::ChainInfo;
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward, ConsensusData},
        classic_multisig::ClassicMultisigChallenge,
        config::create_regtest,
        htlc::{HashedTimelockContract, HtlcSecret, HtlcSecretHash},
        make_delegation_id, make_order_id, make_token_id,
        output_value::{OutputValue, RpcOutputValue},
        signature::inputsig::InputWitness,
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{
            IsTokenFreezable, RPCFungibleTokenInfo, RPCTokenInfo, TokenId, TokenIssuance,
            TokenIssuanceV1, TokenTotalSupply,
        },
        AccountCommand, AccountNonce, AccountOutPoint, AccountSpending, Block, ChainConfig,
        DelegationId, Destination, OrderAccountCommand, OrderData, PoolId, RpcOrderInfo,
        SignedTransaction, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Id, Idable},
};
use node_comm::node_traits::MockNodeInterface;
use randomness::{Rng, SliceRandom as _};
use test_utils::random::{gen_random_alnum_string, gen_random_bytes, make_seedable_rng, Seed};
use wallet::{
    wallet::test_helpers::{create_wallet_with_mnemonic, scan_wallet},
    DefaultWallet,
};
use wallet_types::{
    account_info::DEFAULT_ACCOUNT_INDEX,
    partially_signed_transaction::{
        OrderAdditionalInfo, PoolAdditionalInfo, TokenAdditionalInfo, TxAdditionalInfo,
    },
};

use crate::{
    tests::test_utils::{
        create_block_scan_wallet, random_is_token_unfreezable, random_nft_issuance,
        random_order_currencies_with_token, random_pub_key,
        random_rpc_ft_info_with_id_ticker_decimals, random_rpc_is_token_frozen,
        random_token_data_with_id_and_authority, random_vrf_pub_key, tx_with_outputs,
        wallet_new_dest, OrderCurrencies, TestOrderData, TestTokenData, MNEMONIC,
    },
    {
        helpers::{fetch_utxo, tx_to_partially_signed_tx},
        runtime_wallet::RuntimeWallet,
    },
};

mod tx_to_partially_signed_tx_general_test {
    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let random_tokens_count = 15;
        let random_tokens = (0..random_tokens_count)
            .map(|_| {
                use crate::tests::test_utils::random_token_data_with_id_and_authority;

                random_token_data_with_id_and_authority(
                    TokenId::random_using(&mut rng),
                    Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
                    &mut rng,
                )
            })
            .collect_vec();

        let chain_config = Arc::new(create_regtest());
        let block_timestamp = chain_config.genesis_block().timestamp();
        let mut wallet = create_wallet_with_mnemonic(Arc::clone(&chain_config), MNEMONIC);

        // Transfer to a destination belonging to the wallet.
        let token0_transfer_utxo_dest = wallet_new_dest(&mut wallet);
        let token0_transfer_utxo = TxOutput::Transfer(
            OutputValue::TokenV1(random_tokens[0].id, Amount::from_atoms(rng.gen())),
            token0_transfer_utxo_dest.clone(),
        );
        let tx_with_token0_transfer = tx_with_outputs(vec![token0_transfer_utxo.clone()]);
        let tx_with_token0_transfer_id = tx_with_token0_transfer.transaction().get_id();
        let token0_transfer_outpoint = UtxoOutPoint::new(tx_with_token0_transfer_id.into(), 0);

        // Transfer to a random destination.
        let token1_transfer_utxo_dest =
            Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
        let token1_transfer_utxo = TxOutput::Transfer(
            OutputValue::TokenV1(random_tokens[1].id, Amount::from_atoms(rng.gen())),
            token1_transfer_utxo_dest.clone(),
        );
        let token1_transfer_outpoint =
            UtxoOutPoint::new(Id::<Transaction>::random_using(&mut rng).into(), rng.gen());

        let lock_then_transfer_utxo_dest =
            Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
        let lock_then_transfer_utxo = TxOutput::LockThenTransfer(
            OutputValue::TokenV1(random_tokens[2].id, Amount::from_atoms(rng.gen())),
            lock_then_transfer_utxo_dest.clone(),
            OutputTimeLock::ForBlockCount(rng.gen()),
        );
        let lock_then_transfer_outpoint =
            UtxoOutPoint::new(Id::<Transaction>::random_using(&mut rng).into(), rng.gen());

        let delegation_dest = wallet_new_dest(&mut wallet);
        let tx_with_delegation = SignedTransaction::new(
            Transaction::new(
                0,
                vec![TxInput::Utxo(UtxoOutPoint::new(
                    Id::<Transaction>::random_using(&mut rng).into(),
                    rng.r#gen(),
                ))],
                vec![TxOutput::CreateDelegationId(
                    delegation_dest.clone(),
                    PoolId::random_using(&mut rng),
                )],
            )
            .unwrap(),
            vec![InputWitness::NoSignature(None)],
        )
        .unwrap();
        let delegation_id = make_delegation_id(tx_with_delegation.transaction().inputs()).unwrap();

        // This pool's info will be cached inside the wallet because the decommission destination
        // belongs to it.
        let known_pool_id = PoolId::random_using(&mut rng);
        let known_pool_staker_balance = Amount::from_atoms(rng.gen());
        let known_pool_decommission_dest = wallet_new_dest(&mut wallet);
        let tx_with_pool_creation = tx_with_outputs(vec![TxOutput::CreateStakePool(
            known_pool_id,
            Box::new(StakePoolData::new(
                Amount::from_atoms(rng.r#gen()),
                Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
                random_vrf_pub_key(&mut rng),
                known_pool_decommission_dest.clone(),
                PerThousand::new(rng.gen_range(0..=1000)).unwrap(),
                Amount::from_atoms(rng.r#gen()),
            )),
        )]);

        let mut blocks = Vec::new();

        blocks.push(
            Block::new(
                vec![tx_with_token0_transfer, tx_with_delegation, tx_with_pool_creation],
                chain_config.genesis_block_id(),
                chain_config.genesis_block().timestamp(),
                ConsensusData::None,
                BlockReward::new(vec![]),
            )
            .unwrap(),
        );

        let wallet_tokens_count = 7;
        let wallet_tokens = make_blocks_with_wallet_tokens(
            &mut blocks,
            &chain_config,
            wallet_tokens_count,
            &mut wallet,
            &mut rng,
        );
        let wallet_orders = make_blocks_with_wallet_orders(
            &mut blocks,
            &chain_config,
            &[
                random_order_currencies_with_token(&mut rng, random_tokens[3].id),
                random_order_currencies_with_token(&mut rng, random_tokens[4].id),
                random_order_currencies_with_token(&mut rng, random_tokens[5].id),
                random_order_currencies_with_token(&mut rng, random_tokens[6].id),
                random_order_currencies_with_token(&mut rng, random_tokens[7].id),
            ],
            &mut wallet,
            &mut rng,
        );

        // This utxo will be cached inside the wallet because the info about the pool has been cached.
        let known_produce_block_from_stake_utxo = TxOutput::ProduceBlockFromStake(
            Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
            known_pool_id,
        );
        let pool_id_for_known_create_pool_utxo = PoolId::random_using(&mut rng);
        let pool_staker_balance_for_known_create_pool_utxo = Amount::from_atoms(rng.gen());
        let pool_decommission_dest_for_known_create_pool_utxo = wallet_new_dest(&mut wallet);
        // This utxo will be cached inside the wallet because the decommission destination
        // belongs to it.
        let known_create_pool_utxo = TxOutput::CreateStakePool(
            pool_id_for_known_create_pool_utxo,
            Box::new(StakePoolData::new(
                Amount::from_atoms(rng.r#gen()),
                Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
                random_vrf_pub_key(&mut rng),
                pool_decommission_dest_for_known_create_pool_utxo.clone(),
                PerThousand::new(rng.gen_range(0..=1000)).unwrap(),
                Amount::from_atoms(rng.r#gen()),
            )),
        );
        blocks.push(
            Block::new(
                vec![],
                blocks.last().unwrap().get_id().into(),
                chain_config.genesis_block().timestamp(),
                ConsensusData::None,
                BlockReward::new(vec![
                    known_produce_block_from_stake_utxo.clone(),
                    known_create_pool_utxo.clone(),
                ]),
            )
            .unwrap(),
        );
        let last_block_id = blocks.last().unwrap().get_id();
        let known_produce_block_from_stake_outpoint = UtxoOutPoint::new(last_block_id.into(), 0);
        let known_create_pool_outpoint = UtxoOutPoint::new(last_block_id.into(), 1);

        let last_height = blocks.len() as u64 + 1;
        scan_wallet(&mut wallet, BlockHeight::new(0), blocks);

        let htlc_spend_key = Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
        let htlc_refund_key = Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
        // Note: the wallet doesn't check that the secret and the secret hash are consistent.
        let htlc_secret = HtlcSecret::new_from_rng(&mut rng);
        let create_htlc_utxo = TxOutput::Htlc(
            OutputValue::TokenV1(random_tokens[8].id, Amount::from_atoms(rng.gen())),
            Box::new(HashedTimelockContract {
                secret_hash: HtlcSecretHash::random_using(&mut rng),
                spend_key: htlc_spend_key.clone(),
                refund_timelock: OutputTimeLock::ForBlockCount(rng.gen()),
                refund_key: htlc_refund_key.clone(),
            }),
        );
        let create_htlc_outpoint =
            UtxoOutPoint::new(Id::<Transaction>::random_using(&mut rng).into(), rng.gen());

        let coins_utxo_dest = Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
        let coins_utxo = TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen())),
            coins_utxo_dest.clone(),
        );
        let coins_outpoint =
            UtxoOutPoint::new(Id::<Transaction>::random_using(&mut rng).into(), rng.gen());

        let pool_id_for_unknown_create_pool_utxo = PoolId::random_using(&mut rng);
        let pool_decommission_dest_for_unknown_create_pool_utxo =
            Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
        let unknown_create_pool_utxo = TxOutput::CreateStakePool(
            pool_id_for_unknown_create_pool_utxo,
            Box::new(StakePoolData::new(
                Amount::from_atoms(rng.r#gen()),
                Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
                random_vrf_pub_key(&mut rng),
                pool_decommission_dest_for_unknown_create_pool_utxo.clone(),
                PerThousand::new(rng.gen_range(0..=1000)).unwrap(),
                Amount::from_atoms(rng.r#gen()),
            )),
        );
        let unknown_create_pool_outpoint =
            UtxoOutPoint::new(Id::<Transaction>::random_using(&mut rng).into(), rng.gen());
        let staker_balance_for_pool_for_unknown_create_pool_utxo = Amount::from_atoms(rng.gen());

        let pool_id_for_unknown_produce_block_from_stake_utxo = PoolId::random_using(&mut rng);
        let pool_decommission_dest_for_unknown_produce_block_from_stake_utxo =
            Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
        let unknown_produce_block_from_stake_utxo = TxOutput::ProduceBlockFromStake(
            Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
            pool_id_for_unknown_produce_block_from_stake_utxo,
        );
        let unknown_produce_block_from_stake_outpoint =
            UtxoOutPoint::new(Id::<Transaction>::random_using(&mut rng).into(), rng.gen());
        let staker_balance_for_pool_for_unknown_produce_block_from_stake_utxo =
            Amount::from_atoms(rng.gen());

        let use_htlc_secret = rng.gen_bool(0.5);
        let expected_htlc_dest = if use_htlc_secret {
            htlc_spend_key
        } else {
            htlc_refund_key
        };
        let fill_order_v0_dest = Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
        let mut inputs_utxos_destinations_htlc_secrets = vec![
            (
                TxInput::Utxo(coins_outpoint.clone()),
                Some(coins_utxo.clone()),
                Some(coins_utxo_dest),
                None,
            ),
            (
                TxInput::Utxo(token0_transfer_outpoint),
                Some(token0_transfer_utxo),
                Some(token0_transfer_utxo_dest),
                None,
            ),
            (
                TxInput::Utxo(token1_transfer_outpoint.clone()),
                Some(token1_transfer_utxo.clone()),
                Some(token1_transfer_utxo_dest),
                None,
            ),
            (
                TxInput::Utxo(lock_then_transfer_outpoint.clone()),
                Some(lock_then_transfer_utxo.clone()),
                Some(lock_then_transfer_utxo_dest),
                None,
            ),
            (
                TxInput::Utxo(create_htlc_outpoint.clone()),
                Some(create_htlc_utxo.clone()),
                Some(expected_htlc_dest),
                use_htlc_secret.then_some(htlc_secret),
            ),
            (
                TxInput::Utxo(known_produce_block_from_stake_outpoint),
                Some(known_produce_block_from_stake_utxo),
                Some(known_pool_decommission_dest),
                None,
            ),
            (
                TxInput::Utxo(known_create_pool_outpoint),
                Some(known_create_pool_utxo),
                Some(pool_decommission_dest_for_known_create_pool_utxo),
                None,
            ),
            (
                TxInput::Utxo(unknown_create_pool_outpoint.clone()),
                Some(unknown_create_pool_utxo.clone()),
                Some(pool_decommission_dest_for_unknown_create_pool_utxo.clone()),
                None,
            ),
            (
                TxInput::Utxo(unknown_produce_block_from_stake_outpoint.clone()),
                Some(unknown_produce_block_from_stake_utxo.clone()),
                Some(pool_decommission_dest_for_unknown_produce_block_from_stake_utxo.clone()),
                None,
            ),
            (
                TxInput::Account(AccountOutPoint::new(
                    AccountNonce::new(rng.r#gen()),
                    AccountSpending::DelegationBalance(
                        delegation_id,
                        Amount::from_atoms(rng.r#gen()),
                    ),
                )),
                None,
                Some(delegation_dest),
                None,
            ),
            (
                TxInput::AccountCommand(
                    AccountNonce::new(rng.r#gen()),
                    AccountCommand::MintTokens(
                        wallet_tokens[0].id,
                        Amount::from_atoms(rng.r#gen()),
                    ),
                ),
                None,
                Some(wallet_tokens[0].authority.clone()),
                None,
            ),
            (
                TxInput::AccountCommand(
                    AccountNonce::new(rng.r#gen()),
                    AccountCommand::UnmintTokens(wallet_tokens[1].id),
                ),
                None,
                Some(wallet_tokens[1].authority.clone()),
                None,
            ),
            (
                TxInput::AccountCommand(
                    AccountNonce::new(rng.r#gen()),
                    AccountCommand::LockTokenSupply(wallet_tokens[2].id),
                ),
                None,
                Some(wallet_tokens[2].authority.clone()),
                None,
            ),
            (
                TxInput::AccountCommand(
                    AccountNonce::new(rng.r#gen()),
                    AccountCommand::FreezeToken(
                        wallet_tokens[3].id,
                        random_is_token_unfreezable(&mut rng),
                    ),
                ),
                None,
                Some(wallet_tokens[3].authority.clone()),
                None,
            ),
            (
                TxInput::AccountCommand(
                    AccountNonce::new(rng.r#gen()),
                    AccountCommand::UnfreezeToken(wallet_tokens[4].id),
                ),
                None,
                Some(wallet_tokens[4].authority.clone()),
                None,
            ),
            (
                TxInput::AccountCommand(
                    AccountNonce::new(rng.r#gen()),
                    AccountCommand::ChangeTokenAuthority(
                        wallet_tokens[5].id,
                        Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
                    ),
                ),
                None,
                Some(wallet_tokens[5].authority.clone()),
                None,
            ),
            (
                TxInput::AccountCommand(
                    AccountNonce::new(rng.r#gen()),
                    AccountCommand::ChangeTokenMetadataUri(
                        wallet_tokens[6].id,
                        gen_random_alnum_string(&mut rng, 10, 20).into_bytes(),
                    ),
                ),
                None,
                Some(wallet_tokens[6].authority.clone()),
                None,
            ),
            (
                TxInput::AccountCommand(
                    AccountNonce::new(rng.r#gen()),
                    AccountCommand::ConcludeOrder(wallet_orders[0].id),
                ),
                None,
                Some(wallet_orders[0].conclude_key.clone()),
                None,
            ),
            (
                TxInput::AccountCommand(
                    AccountNonce::new(rng.r#gen()),
                    AccountCommand::FillOrder(
                        wallet_orders[1].id,
                        Amount::from_atoms(rng.r#gen()),
                        fill_order_v0_dest.clone(),
                    ),
                ),
                None,
                Some(fill_order_v0_dest),
                None,
            ),
            (
                TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(
                    wallet_orders[2].id,
                )),
                None,
                Some(wallet_orders[2].conclude_key.clone()),
                None,
            ),
            (
                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                    wallet_orders[3].id,
                    Amount::from_atoms(rng.r#gen()),
                )),
                None,
                Some(Destination::AnyoneCanSpend),
                None,
            ),
            (
                TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(wallet_orders[4].id)),
                None,
                Some(wallet_orders[4].conclude_key.clone()),
                None,
            ),
        ];
        inputs_utxos_destinations_htlc_secrets.shuffle(&mut rng);
        let (inputs, expected_inputs_utxos, expected_inputs_destinations, htlc_secrets) = {
            let mut inputs = Vec::with_capacity(inputs_utxos_destinations_htlc_secrets.len());
            let mut utxos = Vec::with_capacity(inputs_utxos_destinations_htlc_secrets.len());
            let mut destinations = Vec::with_capacity(inputs_utxos_destinations_htlc_secrets.len());
            let mut htlc_secrets = Vec::with_capacity(inputs_utxos_destinations_htlc_secrets.len());

            for (input, utxo, dest, htlc_secret) in inputs_utxos_destinations_htlc_secrets {
                inputs.push(input);
                utxos.push(utxo);
                destinations.push(dest);
                htlc_secrets.push(htlc_secret);
            }

            (inputs, utxos, destinations, htlc_secrets)
        };

        let outputs = vec![
            TxOutput::Transfer(
                OutputValue::TokenV1(random_tokens[9].id, Amount::from_atoms(rng.r#gen())),
                Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
            ),
            TxOutput::LockThenTransfer(
                OutputValue::TokenV1(random_tokens[10].id, Amount::from_atoms(rng.r#gen())),
                Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
                OutputTimeLock::ForBlockCount(rng.r#gen()),
            ),
            TxOutput::Burn(OutputValue::TokenV1(
                random_tokens[11].id,
                Amount::from_atoms(rng.r#gen()),
            )),
            TxOutput::CreateStakePool(
                PoolId::random_using(&mut rng),
                Box::new(StakePoolData::new(
                    Amount::from_atoms(rng.r#gen()),
                    Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
                    random_vrf_pub_key(&mut rng),
                    Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
                    PerThousand::new(rng.gen_range(0..=1000)).unwrap(),
                    Amount::from_atoms(rng.r#gen()),
                )),
            ),
            TxOutput::CreateDelegationId(
                Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
                PoolId::random_using(&mut rng),
            ),
            TxOutput::DelegateStaking(
                Amount::from_atoms(rng.r#gen()),
                DelegationId::random_using(&mut rng),
            ),
            TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(TokenIssuanceV1 {
                token_ticker: gen_random_alnum_string(&mut rng, 10, 20).into_bytes(),
                number_of_decimals: rng.r#gen(),
                metadata_uri: gen_random_alnum_string(&mut rng, 10, 20).into_bytes(),
                total_supply: TokenTotalSupply::Unlimited,
                authority: Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
                is_freezable: IsTokenFreezable::Yes,
            }))),
            TxOutput::IssueNft(
                TokenId::random_using(&mut rng),
                Box::new(random_nft_issuance(&mut rng)),
                Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
            ),
            TxOutput::DataDeposit(gen_random_bytes(&mut rng, 10, 20)),
            TxOutput::Htlc(
                OutputValue::TokenV1(random_tokens[12].id, Amount::from_atoms(rng.r#gen())),
                Box::new(HashedTimelockContract {
                    secret_hash: HtlcSecretHash::random_using(&mut rng),
                    spend_key: Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
                    refund_timelock: OutputTimeLock::ForBlockCount(rng.r#gen()),
                    refund_key: Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
                }),
            ),
            TxOutput::CreateOrder(Box::new(OrderData::new(
                Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
                OutputValue::TokenV1(random_tokens[13].id, Amount::from_atoms(rng.r#gen())),
                OutputValue::TokenV1(random_tokens[14].id, Amount::from_atoms(rng.r#gen())),
            ))),
        ];

        let node_mock = {
            let mut node_mock = MockNodeInterface::new();

            let utxos_to_return = BTreeMap::from([
                // Note: token0_tx_output should already be known to the wallet,
                // since it should have seen it in a block and the address belonged to the wallet.
                // Same for known_produce_block_from_stake_utxo and known_create_pool_utxo.
                (token1_transfer_outpoint, token1_transfer_utxo),
                (lock_then_transfer_outpoint, lock_then_transfer_utxo),
                (coins_outpoint, coins_utxo),
                (create_htlc_outpoint.clone(), create_htlc_utxo.clone()),
                (
                    unknown_create_pool_outpoint.clone(),
                    unknown_create_pool_utxo.clone(),
                ),
                (
                    unknown_produce_block_from_stake_outpoint.clone(),
                    unknown_produce_block_from_stake_utxo.clone(),
                ),
            ]);

            // Note: the "wallet" token infos won't be queried, because those tokens
            // are only used by token-related AccountCommand's, for which we don't collect
            // TokenAdditionalInfo's currently.
            let token_infos_to_return = random_tokens
                .iter()
                .map(|token_data| (token_data.id, make_rpc_token_info(token_data, &mut rng)))
                .collect::<BTreeMap<_, _>>();

            let order_infos_to_return = wallet_orders
                .iter()
                .map(|order_data| (order_data.id, make_rpc_order_info(order_data, &mut rng)))
                .collect::<BTreeMap<_, _>>();

            let staker_balances_to_return = BTreeMap::from([
                (known_pool_id, known_pool_staker_balance),
                (
                    pool_id_for_known_create_pool_utxo,
                    pool_staker_balance_for_known_create_pool_utxo,
                ),
                (
                    pool_id_for_unknown_create_pool_utxo,
                    staker_balance_for_pool_for_unknown_create_pool_utxo,
                ),
                (
                    pool_id_for_unknown_produce_block_from_stake_utxo,
                    staker_balance_for_pool_for_unknown_produce_block_from_stake_utxo,
                ),
            ]);

            let decommission_destinations_to_return = BTreeMap::from([
                (
                    pool_id_for_unknown_produce_block_from_stake_utxo,
                    pool_decommission_dest_for_unknown_produce_block_from_stake_utxo,
                ),
                // Note: technically this shouldn't be needed, because the destination can be extracted
                // from the utxo itself. But we do query it in this case currently.
                (
                    pool_id_for_unknown_create_pool_utxo,
                    pool_decommission_dest_for_unknown_create_pool_utxo,
                ),
            ]);

            let chain_info_to_return = ChainInfo {
                best_block_height: BlockHeight::new(last_height),
                best_block_id: last_block_id.into(),
                best_block_timestamp: block_timestamp,
                median_time: BlockTimestamp::from_int_seconds(rng.gen()),
                is_initial_block_download: false,
            };

            node_mock.expect_get_utxo().returning(move |outpoint| {
                Ok(Some(utxos_to_return.get(&outpoint).unwrap().clone()))
            });

            node_mock.expect_get_token_info().returning(move |token_id| {
                Ok(Some(token_infos_to_return.get(&token_id).unwrap().clone()))
            });

            node_mock.expect_get_order_info().returning(move |token_id| {
                Ok(Some(order_infos_to_return.get(&token_id).unwrap().clone()))
            });

            node_mock.expect_get_staker_balance().returning(move |pool_id| {
                Ok(Some(*staker_balances_to_return.get(&pool_id).unwrap()))
            });

            node_mock.expect_get_pool_decommission_destination().returning(move |pool_id| {
                Ok(Some(
                    decommission_destinations_to_return.get(&pool_id).unwrap().clone(),
                ))
            });

            node_mock
                .expect_chainstate_info()
                .returning(move || Ok(chain_info_to_return.clone()));

            node_mock
        };

        let tx = Transaction::new(0, inputs, outputs).unwrap();
        let wallet = RuntimeWallet::Software(wallet);
        let ptx =
            tx_to_partially_signed_tx(&node_mock, &wallet, tx.clone(), Some(htlc_secrets.clone()))
                .await
                .unwrap();

        assert_eq!(ptx.tx(), &tx);

        assert!(ptx.witnesses().iter().all(|w| w.is_none()));
        assert_eq!(ptx.input_utxos(), &expected_inputs_utxos);
        assert_eq!(ptx.destinations(), &expected_inputs_destinations);
        assert_eq!(ptx.htlc_secrets(), &htlc_secrets);

        let expected_tx_additional_info = {
            let mut info = TxAdditionalInfo::new();

            // Note: the "wallet" tokens are only used by token-related AccountCommand's, for which
            // we don't collect TokenAdditionalInfo's currently. So we don't append them here.
            for token in random_tokens {
                info = info.with_token_info(
                    token.id,
                    TokenAdditionalInfo {
                        num_decimals: token.num_decimals,
                        ticker: token.ticker.into_bytes(),
                    },
                )
            }

            for order in wallet_orders {
                info = info.with_order_info(
                    order.id,
                    OrderAdditionalInfo {
                        initially_asked: order.initially_asked,
                        initially_given: order.initially_given,
                        ask_balance: order.ask_balance,
                        give_balance: order.give_balance,
                    },
                )
            }

            // Note: the info for pool_id_for_known_create_pool_utxo is not returned (because it can be extracted
            // from the utxo itself).
            info.with_pool_info(
                known_pool_id,
                PoolAdditionalInfo {
                    staker_balance: known_pool_staker_balance,
                },
            )
            .with_pool_info(
                pool_id_for_unknown_produce_block_from_stake_utxo,
                PoolAdditionalInfo {
                    staker_balance:
                        staker_balance_for_pool_for_unknown_produce_block_from_stake_utxo,
                },
            )
        };
        assert_eq!(ptx.additional_info(), &expected_tx_additional_info);
    }

    // Make blocks with txs that issue tokens with authority destinations belonging to the wallet.
    fn make_blocks_with_wallet_tokens(
        blocks: &mut Vec<Block>,
        chain_config: &ChainConfig,
        tokens_count: usize,
        wallet: &mut DefaultWallet,
        rng: &mut impl Rng,
    ) -> Vec<TestTokenData> {
        let mut result = Vec::with_capacity(tokens_count);

        for _ in 0..tokens_count {
            let tx_inputs = vec![TxInput::Utxo(UtxoOutPoint::new(
                Id::<Transaction>::random_using(rng).into(),
                rng.r#gen(),
            ))];
            let id = make_token_id(chain_config, BlockHeight::new(0), &tx_inputs).unwrap();
            let authority = wallet_new_dest(wallet);
            let data = random_token_data_with_id_and_authority(id, authority, rng);

            let issuance = TokenIssuanceV1 {
                token_ticker: data.ticker.clone().into_bytes(),
                number_of_decimals: data.num_decimals,
                metadata_uri: data.metadata_uri.clone().into_bytes(),
                total_supply: data.total_supply,
                authority: data.authority.clone(),
                is_freezable: data.is_freezable,
            };

            result.push(data);

            let tx = SignedTransaction::new(
                Transaction::new(
                    0,
                    tx_inputs,
                    vec![TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(issuance)))],
                )
                .unwrap(),
                vec![InputWitness::NoSignature(None)],
            )
            .unwrap();

            blocks.push(
                Block::new(
                    vec![tx],
                    blocks.last().unwrap().get_id().into(),
                    chain_config.genesis_block().timestamp(),
                    ConsensusData::None,
                    BlockReward::new(vec![]),
                )
                .unwrap(),
            );
        }

        result
    }

    // Make blocks with txs that create orders with conclude keys belonging to the wallet.
    fn make_blocks_with_wallet_orders(
        blocks: &mut Vec<Block>,
        chain_config: &ChainConfig,
        curencies: &[OrderCurrencies],
        wallet: &mut DefaultWallet,
        rng: &mut impl Rng,
    ) -> Vec<TestOrderData> {
        let mut result = Vec::with_capacity(curencies.len());

        for curencies in curencies {
            let tx_inputs = vec![TxInput::Utxo(UtxoOutPoint::new(
                Id::<Transaction>::random_using(rng).into(),
                rng.r#gen(),
            ))];
            let id = make_order_id(&tx_inputs).unwrap();
            let initially_asked = curencies.ask.into_output_value(Amount::from_atoms(rng.gen()));
            let initially_given = curencies.give.into_output_value(Amount::from_atoms(rng.gen()));
            let ask_balance = Amount::from_atoms(rng.gen());
            let give_balance = Amount::from_atoms(rng.gen());
            let conclude_key = wallet_new_dest(wallet);

            result.push(TestOrderData {
                id,
                initially_asked: initially_asked.clone(),
                initially_given: initially_given.clone(),
                give_balance,
                ask_balance,
                conclude_key: conclude_key.clone(),
            });

            let tx = SignedTransaction::new(
                Transaction::new(
                    0,
                    tx_inputs,
                    vec![TxOutput::CreateOrder(Box::new(OrderData::new(
                        conclude_key,
                        initially_asked,
                        initially_given,
                    )))],
                )
                .unwrap(),
                vec![InputWitness::NoSignature(None)],
            )
            .unwrap();

            blocks.push(
                Block::new(
                    vec![tx],
                    blocks.last().unwrap().get_id().into(),
                    chain_config.genesis_block().timestamp(),
                    ConsensusData::None,
                    BlockReward::new(vec![]),
                )
                .unwrap(),
            );
        }

        result
    }

    fn make_rpc_token_info(data: &TestTokenData, rng: &mut impl Rng) -> RPCTokenInfo {
        RPCTokenInfo::FungibleToken(RPCFungibleTokenInfo {
            token_id: data.id,
            token_ticker: data.ticker.clone().into(),
            number_of_decimals: data.num_decimals,
            metadata_uri: data.metadata_uri.clone().into(),
            circulating_supply: Amount::from_atoms(rng.gen()),
            total_supply: data.total_supply.into(),
            is_locked: rng.gen(),
            frozen: random_rpc_is_token_frozen(rng),
            authority: data.authority.clone(),
        })
    }

    fn make_rpc_order_info(data: &TestOrderData, rng: &mut impl Rng) -> RpcOrderInfo {
        RpcOrderInfo {
            conclude_key: data.conclude_key.clone(),
            initially_asked: RpcOutputValue::from_output_value(&data.initially_asked).unwrap(),
            initially_given: RpcOutputValue::from_output_value(&data.initially_given).unwrap(),
            give_balance: data.give_balance,
            ask_balance: data.ask_balance,
            nonce: Some(AccountNonce::new(rng.gen())),
        }
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[trace]
#[tokio::test]
async fn tx_to_partially_signed_tx_htlc_input_with_known_utxo_test(
    #[case] seed: Seed,
    #[values(false, true)] use_htlc_secret: bool,
    #[values(false, true)] spend_key_belongs_to_wallet: bool,
    #[values(false, true)] refund_key_known_to_wallet: bool,
    #[values(false, true)] utxo_known_to_wallet: bool,
) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(create_regtest());
    let mut wallet = create_wallet_with_mnemonic(Arc::clone(&chain_config), MNEMONIC);

    let token_id = TokenId::random_using(&mut rng);

    let htlc_spend_key = if spend_key_belongs_to_wallet {
        wallet_new_dest(&mut wallet)
    } else {
        Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng))
    };
    let htlc_refund_key = if refund_key_known_to_wallet {
        let keys = vec![random_pub_key(&mut rng), random_pub_key(&mut rng)];
        let pkh = wallet
            .add_standalone_multisig(
                DEFAULT_ACCOUNT_INDEX,
                ClassicMultisigChallenge::new(&chain_config, NonZeroU8::new(2).unwrap(), keys)
                    .unwrap(),
                None,
            )
            .unwrap();
        Destination::ClassicMultisig(pkh)
    } else {
        Destination::ClassicMultisig(PublicKeyHash::random_using(&mut rng))
    };
    // Note: the wallet doesn't check that the secret and the secret hash are consistent.
    let htlc_secret = HtlcSecret::new_from_rng(&mut rng);
    let create_htlc_output = TxOutput::Htlc(
        OutputValue::TokenV1(token_id, Amount::from_atoms(rng.gen())),
        Box::new(HashedTimelockContract {
            secret_hash: HtlcSecretHash::random_using(&mut rng),
            spend_key: htlc_spend_key.clone(),
            refund_timelock: OutputTimeLock::ForBlockCount(rng.gen()),
            refund_key: htlc_refund_key.clone(),
        }),
    );

    let tx = tx_with_outputs(vec![create_htlc_output.clone()]);
    let tx_id = tx.transaction().get_id();
    let create_htlc_outpoint = UtxoOutPoint::new(tx_id.into(), 0);

    let last_block = create_block_scan_wallet(
        &chain_config,
        &mut wallet,
        if utxo_known_to_wallet {
            vec![tx]
        } else {
            vec![]
        },
        Amount::from_atoms(rng.gen()),
        Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
        0,
    );
    let last_height = 1;

    let token_num_decimals = rng.gen_range(1..20);
    let token_ticker = gen_random_alnum_string(&mut rng, 5, 10);

    let node_mock = {
        let mut node_mock = MockNodeInterface::new();

        let utxos_to_return = if utxo_known_to_wallet
            && (spend_key_belongs_to_wallet || refund_key_known_to_wallet)
        {
            // In this case the utxo will be cached inside the wallet; it must be able to both find
            // the utxo and extract the destination from it by correctly propagating the proper
            // HtlcSpendingCondition.
            BTreeMap::new()
        } else {
            BTreeMap::from([(create_htlc_outpoint.clone(), create_htlc_output.clone())])
        };

        let token_infos_to_return = BTreeMap::from([(
            token_id,
            RPCTokenInfo::FungibleToken(random_rpc_ft_info_with_id_ticker_decimals(
                token_id,
                token_ticker.clone(),
                token_num_decimals,
                &mut rng,
            )),
        )]);

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

    let inputs = vec![create_htlc_outpoint.clone()];
    let expected_inputs_utxos = vec![Some(create_htlc_output.clone())];
    let expected_htlc_dest = if use_htlc_secret {
        htlc_spend_key
    } else {
        htlc_refund_key
    };
    let expected_inputs_destinations = vec![Some(expected_htlc_dest)];
    let outputs = vec![];
    let htlc_secrets = vec![use_htlc_secret.then_some(htlc_secret)];

    let tx = Transaction::new(
        0,
        inputs.into_iter().map(TxInput::Utxo).collect_vec(),
        outputs,
    )
    .unwrap();
    let wallet = RuntimeWallet::Software(wallet);
    let ptx =
        tx_to_partially_signed_tx(&node_mock, &wallet, tx.clone(), Some(htlc_secrets.clone()))
            .await
            .unwrap();

    assert_eq!(ptx.tx(), &tx);
    assert!(ptx.witnesses().iter().all(|w| w.is_none()));
    assert_eq!(ptx.input_utxos(), &expected_inputs_utxos);
    assert_eq!(ptx.destinations(), &expected_inputs_destinations);
    assert_eq!(ptx.htlc_secrets(), &htlc_secrets);
    assert_eq!(
        ptx.additional_info(),
        &TxAdditionalInfo::new().with_token_info(
            token_id,
            TokenAdditionalInfo {
                num_decimals: token_num_decimals,
                ticker: token_ticker.clone().into_bytes()
            }
        )
    );

    // Also call fetch_utxo for the same outpoint; the expectations are exactly the same:
    // if the wallet has cached the utxo, node interface should not be queried.
    let fetched_utxo = fetch_utxo(&node_mock, &wallet, &create_htlc_outpoint).await.unwrap();
    assert_eq!(fetched_utxo, create_htlc_output);
}
