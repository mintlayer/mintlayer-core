// Copyright (c) 2024 RBB S.r.l
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

use crate::{blockchain_state::BlockchainState, sync::local_state::LocalBlockchainState};

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
    sync::Arc,
};

use api_server_common::storage::{
    impls::in_memory::transactional::TransactionalApiServerInMemoryStorage,
    storage_api::{
        ApiServerStorageRead, ApiServerStorageWrite, ApiServerTransactionRw, CoinOrTokenStatistic,
        Transactional, UtxoLock,
    },
};

use chainstate::{chainstate_interface::ChainstateInterface, BlockSource, ChainstateConfig};
use chainstate_test_framework::TestFramework;
use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        config::create_unit_test_config,
        make_delegation_id, make_order_id, make_token_id,
        output_value::{OutputValue, RpcOutputValue},
        tokens::{IsTokenFrozen, NftIssuance, RPCNonFungibleTokenMetadata, RPCTokenInfo, TokenId},
        AccountCommand, AccountNonce, AccountSpending, AccountType, ChainConfig,
        ChainstateUpgradeBuilder, ConsensusUpgrade, DelegationId, Destination, GenBlockId,
        NetUpgrades, OrderId, OutPointSourceId, PoSChainConfigBuilder, PoolId,
        TokenIdGenerationVersion, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockCount, BlockHeight, CoinOrTokenId, Idable, H256},
};
use constraints_value_accumulator::{AccumulatedFee, ConstrainedValueAccumulator};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use orders_accounting::{OrderData, OrdersAccountingOperations, OrdersAccountingView};
use pos_accounting::PoSAccountingView;
use randomness::Rng;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};
use tokens_accounting::TokensAccountingView;

struct PoSAccountingAdapterToCheckFees<'a> {
    chainstate: &'a dyn ChainstateInterface,
}

impl<'a> PoSAccountingAdapterToCheckFees<'a> {
    pub fn new(chainstate: &'a dyn ChainstateInterface) -> Self {
        Self { chainstate }
    }
}

impl PoSAccountingView for PoSAccountingAdapterToCheckFees<'_> {
    type Error = pos_accounting::Error;

    fn pool_exists(&self, _pool_id: PoolId) -> Result<bool, Self::Error> {
        unimplemented!()
    }

    fn get_pool_balance(&self, _pool_id: PoolId) -> Result<Amount, Self::Error> {
        unimplemented!()
    }

    fn get_pool_data(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<pos_accounting::PoolData>, Self::Error> {
        Ok(self.chainstate.get_stake_pool_data(pool_id).unwrap())
    }

    fn get_pool_delegations_shares(
        &self,
        _pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Self::Error> {
        unimplemented!()
    }

    fn get_delegation_balance(&self, _delegation_id: DelegationId) -> Result<Amount, Self::Error> {
        // only used for checks for attempted to print money but we don't need to check that here
        Ok(Amount::from_atoms(i128::MAX as u128))
    }

    fn get_delegation_data(
        &self,
        _delegation_id: DelegationId,
    ) -> Result<Option<pos_accounting::DelegationData>, Self::Error> {
        // we don't care about actual data
        Ok(Some(pos_accounting::DelegationData::new(
            PoolId::new(H256::zero()),
            Destination::AnyoneCanSpend,
        )))
    }

    fn get_pool_delegation_share(
        &self,
        _pool_id: PoolId,
        _delegation_id: DelegationId,
    ) -> Result<Amount, Self::Error> {
        unimplemented!()
    }
}

struct StubTokensAccounting;

impl TokensAccountingView for StubTokensAccounting {
    type Error = tokens_accounting::Error;

    fn get_token_data(
        &self,
        _id: &TokenId,
    ) -> Result<Option<tokens_accounting::TokenData>, Self::Error> {
        let data = tokens_accounting::TokenData::FungibleToken(
            tokens_accounting::FungibleTokenData::new_unchecked(
                "tkn1".into(),
                0,
                Vec::new(),
                common::chain::tokens::TokenTotalSupply::Unlimited,
                false,
                IsTokenFrozen::No(common::chain::tokens::IsTokenFreezable::No),
                Destination::AnyoneCanSpend,
            ),
        );
        Ok(Some(data))
    }

    fn get_circulating_supply(&self, _id: &TokenId) -> Result<Amount, Self::Error> {
        Ok(Amount::ZERO)
    }
}

struct OrderAccountingAdapterToCheckFees<'a> {
    chainstate: &'a dyn ChainstateInterface,
}

impl<'a> OrderAccountingAdapterToCheckFees<'a> {
    pub fn new(chainstate: &'a dyn ChainstateInterface) -> Self {
        Self { chainstate }
    }
}

impl OrdersAccountingView for OrderAccountingAdapterToCheckFees<'_> {
    type Error = orders_accounting::Error;

    fn get_order_data(&self, id: &OrderId) -> Result<Option<OrderData>, Self::Error> {
        Ok(self.chainstate.get_order_data(id).unwrap())
    }

    fn get_ask_balance(&self, id: &OrderId) -> Result<Amount, Self::Error> {
        Ok(self.chainstate.get_order_ask_balance(id).unwrap().unwrap_or(Amount::ZERO))
    }

    fn get_give_balance(&self, id: &OrderId) -> Result<Amount, Self::Error> {
        Ok(self.chainstate.get_order_give_balance(id).unwrap().unwrap_or(Amount::ZERO))
    }
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy(), 20, 50)]
#[tokio::test]
async fn simulation(
    #[case] seed: Seed,
    #[case] max_blocks: usize,
    #[case] max_tx_per_block: usize,
) {
    let mut rng = make_seedable_rng(seed);
    let mut statistics: BTreeMap<CoinOrTokenStatistic, BTreeMap<CoinOrTokenId, Amount>> =
        BTreeMap::new();

    let num_blocks = rng.gen_range((max_blocks / 2)..max_blocks);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (staking_sk, staking_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let (config_builder, genesis_pool_id) =
        chainstate_test_framework::create_chain_config_with_default_staking_pool(
            &mut rng, staking_pk, vrf_pk,
        );

    let upgrades = vec![(
        BlockHeight::new(0),
        ConsensusUpgrade::PoS {
            initial_difficulty: None,
            config: PoSChainConfigBuilder::new_for_unit_test()
                .staking_pool_spend_maturity_block_count(BlockCount::new(5))
                .build(),
        },
    )];
    let consensus_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");

    let epoch_length = NonZeroU64::new(rng.gen_range(1..10)).unwrap();
    let sealed_epoch_distance_from_tip = rng.gen_range(1..10);
    let token_id_generation_v1_fork_height =
        BlockHeight::new(rng.gen_range(1..=num_blocks + 1) as u64);
    let chain_config = config_builder
        .consensus_upgrades(consensus_upgrades)
        .max_future_block_time_offset(Some(std::time::Duration::from_secs(1_000_000)))
        .epoch_length(epoch_length)
        .sealed_epoch_distance_from_tip(sealed_epoch_distance_from_tip)
        .chainstate_upgrades(
            common::chain::NetUpgrades::initialize(vec![
                (
                    BlockHeight::zero(),
                    ChainstateUpgradeBuilder::latest()
                        .token_id_generation_version(TokenIdGenerationVersion::V0)
                        .build(),
                ),
                (
                    token_id_generation_v1_fork_height,
                    ChainstateUpgradeBuilder::latest()
                        .token_id_generation_version(TokenIdGenerationVersion::V1)
                        .build(),
                ),
            ])
            .unwrap(),
        )
        .build();
    let target_time = chain_config.target_block_spacing();
    let genesis_pool_outpoint = UtxoOutPoint::new(chain_config.genesis_block_id().into(), 1);

    // Initialize original TestFramework
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.clone())
        .with_chainstate_config(ChainstateConfig::new().with_heavy_checks_enabled(false))
        .with_initial_time_since_genesis(target_time.as_secs())
        .with_staking_pools(BTreeMap::from_iter([(
            genesis_pool_id,
            (
                staking_sk.clone(),
                vrf_sk.clone(),
                genesis_pool_outpoint.clone(),
            ),
        )]))
        .build();

    let storage = {
        let mut storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

        let mut db_tx = storage.transaction_rw().await.unwrap();
        db_tx.reinitialize_storage(&chain_config).await.unwrap();
        db_tx.commit().await.unwrap();

        storage
    };
    let mut local_state = BlockchainState::new(Arc::new(chain_config.clone()), storage);
    local_state.scan_genesis(chain_config.genesis_block().as_ref()).await.unwrap();

    {
        let stake_amount = create_unit_test_config().min_stake_pool_pledge();
        let mint_amount = Amount::from_atoms(100_000_000 * common::chain::CoinUnit::ATOMS_PER_COIN);
        statistics
            .entry(CoinOrTokenStatistic::Preminted)
            .or_default()
            .insert(CoinOrTokenId::Coin, (stake_amount + mint_amount).unwrap());
        statistics
            .entry(CoinOrTokenStatistic::CirculatingSupply)
            .or_default()
            .insert(CoinOrTokenId::Coin, (stake_amount + mint_amount).unwrap());
        statistics
            .entry(CoinOrTokenStatistic::Staked)
            .or_default()
            .insert(CoinOrTokenId::Coin, stake_amount);
    }

    check_all_statistics(&local_state, &statistics, CoinOrTokenId::Coin).await;

    let mut utxo_outpoints = Vec::new();
    let mut staking_pools: BTreeSet<PoolId> = BTreeSet::new();
    staking_pools.insert(genesis_pool_id);

    let mut delegations = BTreeSet::new();
    let mut token_ids = BTreeSet::new();
    let mut order_ids = BTreeSet::new();

    let mut data_per_block_height = BTreeMap::new();
    data_per_block_height.insert(
        BlockHeight::zero(),
        (
            utxo_outpoints.clone(),
            staking_pools.clone(),
            delegations.clone(),
            token_ids.clone(),
            order_ids.clone(),
            statistics.clone(),
        ),
    );

    let mut tf_internal_staking_pools = BTreeMap::new();
    tf_internal_staking_pools.insert(BlockHeight::zero(), tf.staking_pools.clone());

    // Generate a random chain
    for current_height in 0..num_blocks {
        let create_reorg = rng.gen_bool(0.1);
        let height_to_continue_from = if create_reorg {
            rng.gen_range(0..=current_height)
        } else {
            current_height
        };

        tf = if create_reorg {
            let blocks = if height_to_continue_from > 0 {
                tf.chainstate
                    .get_mainchain_blocks(BlockHeight::new(1), height_to_continue_from)
                    .unwrap()
            } else {
                vec![]
            };
            let mut new_tf = TestFramework::builder(&mut rng)
                .with_chain_config(chain_config.clone())
                .with_initial_time_since_genesis(target_time.as_secs())
                .with_staking_pools(BTreeMap::from_iter([(
                    genesis_pool_id,
                    (
                        staking_sk.clone(),
                        vrf_sk.clone(),
                        genesis_pool_outpoint.clone(),
                    ),
                )]))
                .build();
            for block in blocks {
                new_tf.progress_time_seconds_since_epoch(target_time.as_secs());
                new_tf.process_block(block.clone(), BlockSource::Local).unwrap();
            }
            new_tf.staking_pools = tf_internal_staking_pools
                .get(&BlockHeight::new(height_to_continue_from as u64))
                .unwrap()
                .clone();
            new_tf.key_manager = tf.key_manager;

            (
                utxo_outpoints,
                staking_pools,
                delegations,
                token_ids,
                order_ids,
                statistics,
            ) = data_per_block_height
                .get(&BlockHeight::new(height_to_continue_from as u64))
                .unwrap()
                .clone();

            new_tf
        } else {
            tf
        };

        let block_height_to_continue_from = BlockHeight::new(height_to_continue_from as u64);
        let mut prev_block_hash = tf
            .chainstate
            .get_block_id_from_height(&block_height_to_continue_from)
            .unwrap()
            .unwrap();

        for block_height_idx in 0..=(current_height - height_to_continue_from) {
            let block_height =
                BlockHeight::new((height_to_continue_from + block_height_idx) as u64);

            let mut block_builder = tf.make_pos_block_builder().with_random_staking_pool(&mut rng);

            for _ in 0..rng.gen_range(10..max_tx_per_block) {
                block_builder = block_builder.add_test_transaction(&mut rng);
            }

            let block = block_builder.build(&mut rng);

            let orders_store = OrderAccountingAdapterToCheckFees::new(tf.chainstate.as_ref());
            let mut new_orders_cache = orders_accounting::OrdersAccountingCache::new(&orders_store);

            for tx in block.transactions() {
                let new_utxos = (0..tx.outputs().len()).map(|output_index| {
                    UtxoOutPoint::new(
                        OutPointSourceId::Transaction(tx.transaction().get_id()),
                        output_index as u32,
                    )
                });
                utxo_outpoints.extend(new_utxos);

                // store new ids
                tx.outputs().iter().for_each(|out| match out {
                    TxOutput::CreateStakePool(pool_id, _) => {
                        staking_pools.insert(*pool_id);
                    }
                    TxOutput::IssueNft(_, _, _) | TxOutput::IssueFungibleToken(_) => {
                        token_ids.insert(
                            make_token_id(&chain_config, tf.next_block_height(), tx.inputs())
                                .unwrap(),
                        );
                    }
                    TxOutput::CreateDelegationId(_, _) => {
                        delegations.insert(make_delegation_id(tx.inputs()).unwrap());
                    }
                    | TxOutput::Burn(_)
                    | TxOutput::Transfer(_, _)
                    | TxOutput::LockThenTransfer(_, _, _)
                    | TxOutput::DataDeposit(_)
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::ProduceBlockFromStake(_, _)
                    | TxOutput::Htlc(_, _) => {}
                    TxOutput::CreateOrder(order_data) => {
                        let order_id = make_order_id(tx.inputs()).unwrap();
                        let _ = new_orders_cache
                            .create_order(order_id, order_data.as_ref().clone().into())
                            .unwrap();
                        order_ids.insert(order_id);
                    }
                });

                update_statistics(
                    &mut statistics,
                    tx.transaction(),
                    &chain_config,
                    block_height,
                );
            }

            let block_subsidy = chain_config.block_subsidy_at_height(&block_height.next_height());
            statistics
                .entry(CoinOrTokenStatistic::CirculatingSupply)
                .or_default()
                .entry(CoinOrTokenId::Coin)
                .and_modify(|amount| *amount = (*amount + block_subsidy).unwrap())
                .or_insert(block_subsidy);
            statistics
                .entry(CoinOrTokenStatistic::Staked)
                .or_default()
                .entry(CoinOrTokenId::Coin)
                .and_modify(|amount| *amount = (*amount + block_subsidy).unwrap())
                .or_insert(block_subsidy);

            let pos_store = PoSAccountingAdapterToCheckFees::new(tf.chainstate.as_ref());
            let tokens_store = StubTokensAccounting;

            let mut total_fees = AccumulatedFee::new();
            for tx in block.transactions().iter() {
                let inputs_utxos: Vec<_> = tx
                    .inputs()
                    .iter()
                    .map(|inp| match inp.utxo_outpoint() {
                        Some(outpoint) => {
                            tf.chainstate.utxo(outpoint).unwrap().map(|utxo| utxo.take_output())
                        }
                        None => None,
                    })
                    .collect();

                let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
                    &chain_config,
                    block_height,
                    &new_orders_cache,
                    &pos_store,
                    &tokens_store,
                    tx.inputs(),
                    &inputs_utxos,
                )
                .expect("valid block");
                let outputs_accumulator = ConstrainedValueAccumulator::from_outputs(
                    &chain_config,
                    block_height,
                    tx.outputs(),
                )
                .expect("valid block");
                let consumed_accumulator =
                    inputs_accumulator.satisfy_with(outputs_accumulator).expect("valid block");
                let fee = consumed_accumulator;
                total_fees = total_fees.combine(fee.clone()).expect("no overflow");
            }

            let total_fees = total_fees
                .map_into_block_fees(&chain_config, block_height)
                .expect("no overflow");
            statistics
                .entry(CoinOrTokenStatistic::Staked)
                .or_default()
                .entry(CoinOrTokenId::Coin)
                .and_modify(|amount| *amount = (*amount + total_fees.0).unwrap())
                .or_insert(block_subsidy);

            prev_block_hash = block.get_id().into();
            tf.process_block(block.clone(), BlockSource::Local).unwrap();

            // save current state
            tf_internal_staking_pools.insert(block_height.next_height(), tf.staking_pools.clone());
            data_per_block_height.insert(
                block_height.next_height(),
                (
                    utxo_outpoints.clone(),
                    staking_pools.clone(),
                    delegations.clone(),
                    token_ids.clone(),
                    order_ids.clone(),
                    statistics.clone(),
                ),
            );

            local_state.scan_blocks(block_height, vec![block]).await.unwrap();
        }

        let block_height = BlockHeight::new(current_height as u64);
        let median_time = tf.chainstate.calculate_median_time_past(&prev_block_hash).unwrap();

        check_utxos(
            &tf,
            &local_state,
            &utxo_outpoints,
            median_time,
            block_height.next_height(),
        )
        .await;

        check_staking_pools(&tf, &local_state, &staking_pools).await;
        check_delegations(&tf, &local_state, &delegations).await;
        check_tokens(&tf, &local_state, &token_ids).await;
        check_orders(&tf, &local_state, order_ids.iter().copied()).await;

        check_all_statistics(&local_state, &statistics, CoinOrTokenId::Coin).await;
        for token_id in &token_ids {
            check_all_statistics(&local_state, &statistics, CoinOrTokenId::TokenId(*token_id))
                .await;
        }
    }
}

fn burn_value(
    statistics: &mut BTreeMap<CoinOrTokenStatistic, BTreeMap<CoinOrTokenId, Amount>>,
    burn: &OutputValue,
) {
    let (coin_or_token, burn_amount) = match burn {
        OutputValue::Coin(burn_amount) => (CoinOrTokenId::Coin, *burn_amount),
        OutputValue::TokenV0(_) => return,
        OutputValue::TokenV1(token_id, burn_amount) => {
            (CoinOrTokenId::TokenId(*token_id), *burn_amount)
        }
    };

    statistics
        .entry(CoinOrTokenStatistic::Burned)
        .or_default()
        .entry(coin_or_token)
        .and_modify(|amount| *amount = (*amount + burn_amount).unwrap())
        .or_insert(burn_amount);

    let circulating_supply = statistics
        .entry(CoinOrTokenStatistic::CirculatingSupply)
        .or_default()
        .get_mut(&coin_or_token)
        .unwrap();

    *circulating_supply = (*circulating_supply - burn_amount).unwrap();
}

fn update_statistics(
    statistics: &mut BTreeMap<CoinOrTokenStatistic, BTreeMap<CoinOrTokenId, Amount>>,
    tx: &Transaction,
    chain_config: &ChainConfig,
    block_height: BlockHeight,
) {
    tx.outputs().iter().for_each(|out| match out {
        TxOutput::IssueNft(token_id, _, _) => {
            statistics
                .entry(CoinOrTokenStatistic::CirculatingSupply)
                .or_default()
                .insert(CoinOrTokenId::TokenId(*token_id), Amount::from_atoms(1));
            let nft_issuance_fee = chain_config.nft_issuance_fee(block_height);
            burn_coins(statistics, nft_issuance_fee);
        }
        TxOutput::IssueFungibleToken(_) => {
            let token_issuance_fee = chain_config.fungible_token_issuance_fee();
            burn_coins(statistics, token_issuance_fee);
        }
        TxOutput::CreateStakePool(_, data) => {
            statistics
                .entry(CoinOrTokenStatistic::Staked)
                .or_default()
                .entry(CoinOrTokenId::Coin)
                .and_modify(|amount| *amount = (*amount + data.pledge()).unwrap())
                .or_insert(data.pledge());
        }
        TxOutput::Burn(value) => {
            burn_value(statistics, value);
        }
        TxOutput::DataDeposit(_) => {
            let data_deposit_fee = chain_config.data_deposit_fee(BlockHeight::zero());
            burn_coins(statistics, data_deposit_fee);
        }
        TxOutput::DelegateStaking(to_stake, _) => {
            statistics
                .entry(CoinOrTokenStatistic::Staked)
                .or_default()
                .entry(CoinOrTokenId::Coin)
                .and_modify(|amount| *amount = (*amount + *to_stake).unwrap())
                .or_insert(*to_stake);
        }
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::Htlc(_, _)
        | TxOutput::CreateOrder(_) => {}
    });

    tx.inputs().iter().for_each(|inp| match inp {
        TxInput::Utxo(_) => {}
        TxInput::Account(acc) => match acc.account() {
            AccountSpending::DelegationBalance(_, to_spend) => {
                let staked = statistics
                    .entry(CoinOrTokenStatistic::Staked)
                    .or_default()
                    .get_mut(&CoinOrTokenId::Coin)
                    .unwrap();

                *staked = (*staked - *to_spend).unwrap();
            }
        },
        TxInput::AccountCommand(_, cmd) => match cmd {
            AccountCommand::MintTokens(token_id, to_mint) => {
                statistics
                    .entry(CoinOrTokenStatistic::CirculatingSupply)
                    .or_default()
                    .entry(CoinOrTokenId::TokenId(*token_id))
                    .and_modify(|amount| *amount = (*amount + *to_mint).unwrap())
                    .or_insert(*to_mint);
                let token_supply_change_fee = chain_config.token_supply_change_fee(block_height);
                burn_coins(statistics, token_supply_change_fee);
            }
            AccountCommand::UnmintTokens(_) => {
                let token_supply_change_fee = chain_config.token_supply_change_fee(block_height);
                burn_coins(statistics, token_supply_change_fee);
            }
            AccountCommand::FreezeToken(_, _) | AccountCommand::UnfreezeToken(_) => {
                let token_freeze_fee = chain_config.token_freeze_fee(block_height);
                burn_coins(statistics, token_freeze_fee);
            }
            AccountCommand::LockTokenSupply(_) => {
                let token_supply_change_fee = chain_config.token_supply_change_fee(block_height);
                burn_coins(statistics, token_supply_change_fee);
            }
            AccountCommand::ChangeTokenAuthority(_, _) => {
                let token_change_authority_fee =
                    chain_config.token_change_authority_fee(block_height);
                burn_coins(statistics, token_change_authority_fee);
            }
            AccountCommand::ChangeTokenMetadataUri(_token_id, _) => {
                let token_change_metadata_fee = chain_config.token_change_metadata_uri_fee();
                burn_coins(statistics, token_change_metadata_fee);
            }
            AccountCommand::ConcludeOrder(_) | AccountCommand::FillOrder(_, _, _) => {}
        },
        TxInput::OrderAccountCommand(..) => {}
    });
}

fn burn_coins(
    statistics: &mut BTreeMap<CoinOrTokenStatistic, BTreeMap<CoinOrTokenId, Amount>>,
    burn_coins: Amount,
) {
    statistics
        .entry(CoinOrTokenStatistic::Burned)
        .or_default()
        .entry(CoinOrTokenId::Coin)
        .and_modify(|amount| *amount = (*amount + burn_coins).unwrap())
        .or_insert(burn_coins);

    let circulating_supply = statistics
        .entry(CoinOrTokenStatistic::CirculatingSupply)
        .or_default()
        .get_mut(&CoinOrTokenId::Coin)
        .unwrap();

    *circulating_supply = (*circulating_supply - burn_coins).unwrap();
}

async fn check_all_statistics(
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    statistics: &BTreeMap<CoinOrTokenStatistic, BTreeMap<CoinOrTokenId, Amount>>,
    coin_or_token: CoinOrTokenId,
) {
    check_statistic(
        local_state,
        CoinOrTokenStatistic::Preminted,
        coin_or_token,
        statistics,
    )
    .await;

    check_statistic(
        local_state,
        CoinOrTokenStatistic::CirculatingSupply,
        coin_or_token,
        statistics,
    )
    .await;

    check_statistic(
        local_state,
        CoinOrTokenStatistic::Staked,
        coin_or_token,
        statistics,
    )
    .await;

    check_statistic(
        local_state,
        CoinOrTokenStatistic::Burned,
        coin_or_token,
        statistics,
    )
    .await;
}

async fn check_statistic(
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    statistic: CoinOrTokenStatistic,
    coin_or_token: CoinOrTokenId,
    expected: &BTreeMap<CoinOrTokenStatistic, BTreeMap<CoinOrTokenId, Amount>>,
) {
    let local_state_amount = local_state
        .storage()
        .transaction_ro()
        .await
        .unwrap()
        .get_statistic(statistic, coin_or_token)
        .await
        .unwrap()
        .unwrap_or(Amount::ZERO);
    assert_eq!(
        local_state_amount,
        expected
            .get(&statistic)
            .unwrap_or(&BTreeMap::new())
            .get(&coin_or_token)
            .copied()
            .unwrap_or(Amount::ZERO)
    );
}

async fn check_utxos(
    tf: &TestFramework,
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    utxos: &Vec<UtxoOutPoint>,
    current_median_time: BlockTimestamp,
    current_block_height: BlockHeight,
) {
    for outpoint in utxos {
        check_utxo(
            tf,
            local_state,
            outpoint.clone(),
            current_median_time,
            current_block_height,
        )
        .await;
    }
}

async fn check_utxo(
    tf: &TestFramework,
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    outpoint: UtxoOutPoint,
    current_median_time: BlockTimestamp,
    current_block_height: BlockHeight,
) {
    let c_utxo = tf.chainstate.utxo(&outpoint).unwrap();

    // if this is a locked utxo get the unlock time/height
    let unlock = c_utxo
        .as_ref()
        .and_then(|utxo| utxo.output().timelock().zip(utxo.source().blockchain_height().ok()))
        .map(|(lock, height)| {
            let block_id = tf.block_id(height.into_int());
            let utxo_block_id = block_id.classify(tf.chainstate.get_chain_config());
            let time_of_tx = match utxo_block_id {
                GenBlockId::Block(id) => {
                    tf.chainstate.get_block_header(id).unwrap().unwrap().timestamp()
                }
                GenBlockId::Genesis(_) => {
                    tf.chainstate.get_chain_config().genesis_block().timestamp()
                }
            };
            UtxoLock::from_output_lock(*lock, time_of_tx, height).into_time_and_height()
        });

    let tx = local_state.storage().transaction_ro().await.unwrap();

    // fetch the locked utxo
    let l_utxo = if let Some((unlock_time, unlock_height)) = unlock {
        tx.get_locked_utxos_until_now(
            unlock_height.unwrap_or(current_block_height),
            (
                current_median_time,
                unlock_time.unwrap_or(current_median_time),
            ),
        )
        .await
        .unwrap()
        .into_iter()
        .find_map(|(out, info)| (out == outpoint).then_some(info))
    } else {
        None
    };

    // fetch the unlocked utxo
    let s_utxo = tx.get_utxo(outpoint).await.unwrap();

    match (c_utxo, s_utxo) {
        (Some(c_utxo), Some(s_utxo)) => {
            // if utxo is in chainstate it should not be spent
            assert!(!s_utxo.spent());
            // check outputs are the same
            assert_eq!(c_utxo.output(), s_utxo.output());
        }
        (None, Some(s_utxo)) => {
            // if utxo is not found in chainstate but found in scanner it must be spent
            assert!(s_utxo.spent());
            // and not in locked utxos
            assert_eq!(l_utxo, None);
        }
        (Some(c_utxo), None) => {
            // if utxo is in chainstate but not in unlocked scanner utxos it must be in the locked
            // ones
            if let Some(l_utxo) = l_utxo {
                assert_eq!(c_utxo.output(), &l_utxo.output);
            } else {
                panic!("Utxo in chainstate but not in the scanner state");
            }
        }
        (None, None) => {
            // on reorg utxos will be gone from both chainstate and the scanner
            // same for locked
            assert_eq!(l_utxo, None);
        }
    };
}

async fn check_staking_pools(
    tf: &TestFramework,
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    staking_pools: &BTreeSet<PoolId>,
) {
    for pool_id in staking_pools {
        check_pool(tf, local_state, *pool_id).await;
    }
}

async fn check_pool(
    tf: &TestFramework,
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    pool_id: PoolId,
) {
    let tx = local_state.storage().transaction_ro().await.unwrap();
    let scanner_data = tx.get_pool_data(pool_id).await.unwrap().unwrap();

    if let Some(node_data) = tf.chainstate.get_stake_pool_data(pool_id).unwrap() {
        // check all fields are the same
        assert_eq!(node_data, scanner_data.pool_data);

        // check delegations_balance
        let node_pool_balance =
            tf.chainstate.get_stake_pool_balance(pool_id).unwrap().unwrap_or(Amount::ZERO);
        let scanner_pool_balance =
            (scanner_data.staker_balance().unwrap() + scanner_data.delegations_balance).unwrap();
        assert_eq!(node_pool_balance, scanner_pool_balance);
    } else {
        // the pool has been decommissioned
        assert_eq!(Amount::ZERO, scanner_data.pledge_amount());
        assert_eq!(Amount::ZERO, scanner_data.staker_balance().unwrap());
    }

    // Compare the delegation shares
    let node_delegations = tf
        .chainstate
        .get_stake_pool_delegations_shares(pool_id)
        .unwrap()
        .unwrap_or_default();

    let scanner_delegations = tx.get_pool_delegations(pool_id).await.unwrap();

    // check all delegations from the node are contained in the scanner
    for (id, share) in &node_delegations {
        let scanner_delegation = scanner_delegations.get(id).unwrap();
        // check the shares are the same
        assert_eq!(share, scanner_delegation.balance());
    }

    // delegations that have not been staked yet are stored in the scanner but not in the node
    for (id, scanner_delegation) in scanner_delegations {
        let share = node_delegations.get(&id).unwrap_or(&Amount::ZERO);
        // check the shares are the same
        assert_eq!(share, scanner_delegation.balance());
    }
}

async fn check_delegations(
    tf: &TestFramework,
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    delegations: &BTreeSet<DelegationId>,
) {
    for delegation_id in delegations {
        check_delegation(tf, local_state, *delegation_id).await
    }
}

async fn check_delegation(
    tf: &TestFramework,
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    delegation_id: DelegationId,
) {
    let tx = local_state.storage().transaction_ro().await.unwrap();
    let scanner_data = tx.get_delegation(delegation_id).await.unwrap().unwrap();

    if let Some(node_data) = tf.chainstate.get_stake_delegation_data(delegation_id).unwrap() {
        assert_eq!(node_data.source_pool(), scanner_data.pool_id());
        assert_eq!(
            node_data.spend_destination(),
            scanner_data.spend_destination()
        );

        // check delegation balances are the same
        let node_delegation_balance = tf
            .chainstate
            .get_stake_delegation_balance(delegation_id)
            .unwrap()
            .unwrap_or(Amount::ZERO);
        assert_eq!(node_delegation_balance, *scanner_data.balance());

        let node_acc_next_nonce = tf
            .chainstate
            .get_account_nonce_count(AccountType::Delegation(delegation_id))
            .unwrap()
            .map_or(AccountNonce::new(0), |nonce| nonce.increment().unwrap());
        assert_eq!(&node_acc_next_nonce, scanner_data.next_nonce());
    } else {
        // the pool has been decommissioned
        assert_eq!(Amount::ZERO, *scanner_data.balance());
    }
}

async fn check_tokens(
    tf: &TestFramework,
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    token_ids: &BTreeSet<TokenId>,
) {
    for token_id in token_ids {
        check_token(tf, local_state, *token_id).await;
    }
}

async fn check_token(
    tf: &TestFramework,
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    token_id: TokenId,
) {
    let tx = local_state.storage().transaction_ro().await.unwrap();
    let node_data = tf.chainstate.get_token_info_for_rpc(token_id).unwrap().unwrap();

    match node_data {
        RPCTokenInfo::FungibleToken(node_data) => {
            let scanner_data = tx.get_fungible_token_issuance(token_id).await.unwrap().unwrap();
            let scanner_data = scanner_data.into_rpc_token_info(token_id);
            assert_eq!(node_data, scanner_data);
        }
        RPCTokenInfo::NonFungibleToken(node_data) => {
            let scanner_data = tx.get_nft_token_issuance(token_id).await.unwrap().unwrap();

            match scanner_data.nft {
                NftIssuance::V0(scanner_data) => {
                    let scanner_metadata: RPCNonFungibleTokenMetadata =
                        (&scanner_data.metadata).into();
                    assert_eq!(node_data.metadata, scanner_metadata);
                }
            }
        }
    }
}

async fn check_orders(
    tf: &TestFramework,
    local_state: &BlockchainState<TransactionalApiServerInMemoryStorage>,
    order_ids: impl Iterator<Item = OrderId>,
) {
    for order_id in order_ids {
        let tx = local_state.storage().transaction_ro().await.unwrap();
        let scanner_data = tx.get_order(order_id).await.unwrap().unwrap();

        if let Some(node_data) = tf.chainstate.get_order_info_for_rpc(order_id).unwrap() {
            assert_eq!(scanner_data.conclude_destination, node_data.conclude_key);
            assert_eq!(
                scanner_data.next_nonce,
                node_data.nonce.map_or(AccountNonce::new(0), |nonce| nonce.increment().unwrap())
            );

            assert_eq!(scanner_data.ask_balance, node_data.ask_balance);
            assert_eq!(scanner_data.give_balance, node_data.give_balance);

            let to_rpc_output_value = |currency: CoinOrTokenId, amount| match currency {
                CoinOrTokenId::Coin => RpcOutputValue::Coin { amount },
                CoinOrTokenId::TokenId(id) => RpcOutputValue::Token { id, amount },
            };

            assert_eq!(
                to_rpc_output_value(scanner_data.ask_currency, scanner_data.initially_asked),
                node_data.initially_asked
            );

            assert_eq!(
                to_rpc_output_value(scanner_data.give_currency, scanner_data.initially_given),
                node_data.initially_given
            );
        } else {
            // order has been concluded
            assert_eq!(scanner_data.ask_balance, Amount::ZERO);
            assert_eq!(scanner_data.give_balance, Amount::ZERO);
        }
    }
}
