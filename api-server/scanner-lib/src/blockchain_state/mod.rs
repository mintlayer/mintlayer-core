// Copyright (c) 2023 RBB S.r.l
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

use crate::sync::local_state::LocalBlockchainState;
use api_server_common::storage::storage_api::{
    block_aux_data::{BlockAuxData, BlockWithExtraData},
    ApiServerStorage, ApiServerStorageError, ApiServerStorageRead, ApiServerStorageWrite,
    ApiServerTransactionRw, CoinOrTokenStatistic, Delegation, FungibleTokenData, LockedUtxo, Order,
    PoolDataWithExtraInfo, TransactionInfo, TxAdditionalInfo, Utxo, UtxoLock,
};
use chainstate::{
    calculate_median_time_past_from_blocktimestamps,
    constraints_value_accumulator::{AccumulatedFee, ConstrainedValueAccumulator},
};
use common::{
    address::Address,
    chain::{
        block::{timestamp::BlockTimestamp, ConsensusData},
        config::ChainConfig,
        make_order_id,
        output_value::OutputValue,
        tokens::{
            get_referenced_token_ids_ignore_issuance, make_token_id, IsTokenFrozen, TokenId,
            TokenIssuance,
        },
        transaction::OutPointSourceId,
        AccountCommand, AccountNonce, AccountSpending, Block, DelegationId, Destination, GenBlock,
        Genesis, OrderAccountCommand, OrderId, PoolId, SignedTransaction, Transaction, TxInput,
        TxOutput, UtxoOutPoint,
    },
    primitives::{id::WithId, Amount, BlockHeight, CoinOrTokenId, Fee, Id, Idable, H256},
};
use futures::{stream::FuturesOrdered, TryStreamExt};
use orders_accounting::OrderData;
use pos_accounting::{make_delegation_id, PoSAccountingView, PoolData};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::{Add, Sub},
    sync::Arc,
};
use tokens_accounting::TokensAccountingView;
use tx_verifier::transaction_verifier::{
    calculate_tokens_burned_in_outputs, distribute_pos_reward,
};

mod pos_adapter;

#[derive(Debug, thiserror::Error)]
pub enum BlockchainStateError {
    #[error("Unexpected storage error: {0}")]
    StorageError(#[from] ApiServerStorageError),
}

pub struct BlockchainState<S: ApiServerStorage> {
    chain_config: Arc<ChainConfig>,
    storage: S,
}

impl<S: ApiServerStorage> BlockchainState<S> {
    pub fn new(chain_config: Arc<ChainConfig>, storage: S) -> Self {
        Self {
            chain_config,
            storage,
        }
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    pub async fn scan_genesis(&mut self, genesis: &Genesis) -> Result<(), BlockchainStateError> {
        let mut db_tx = self.storage.transaction_rw().await.expect("Unable to connect to database");

        update_tables_from_block_reward(
            self.chain_config.clone(),
            &mut db_tx,
            BlockHeight::new(0),
            genesis.utxos(),
            genesis.get_id().into(),
        )
        .await
        .expect("Unable to update tables from block reward");

        db_tx.commit().await.expect("Unable to commit transaction");
        logging::log::info!("Database commit completed successfully");

        Ok(())
    }
}

#[async_trait::async_trait]
impl<S: ApiServerStorage + Send + Sync> LocalBlockchainState for BlockchainState<S> {
    type Error = BlockchainStateError;

    async fn best_block(&self) -> Result<(BlockHeight, Id<GenBlock>), Self::Error> {
        let db_tx = self.storage.transaction_ro().await.expect("Unable to connect to database");
        let best_block = db_tx.get_best_block().await.expect("Unable to get best block");
        Ok((best_block.block_height(), best_block.block_id()))
    }

    async fn scan_blocks(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
    ) -> Result<(), Self::Error> {
        let mut db_tx = self.storage.transaction_rw().await.expect("Unable to connect to database");

        disconnect_tables_above_height(&mut db_tx, common_block_height)
            .await
            .expect("Unable to disconnect tables");

        // Connect the new blocks in the new chain
        for (index, block) in blocks.into_iter().map(WithId::new).enumerate() {
            let block_height = BlockHeight::new(common_block_height.into_int() + index as u64 + 1);
            let block_timestamp = block.timestamp();

            // calculate the previous and new median_time
            let (previous_median_time, new_median_time) =
                previous_and_new_median_time(&mut db_tx, block_timestamp).await?;

            update_locked_amounts_for_current_block(
                &mut db_tx,
                &self.chain_config,
                block_height,
                (previous_median_time, new_median_time),
            )
            .await?;

            logging::log::info!("Connected block: ({}, {:x})", block_height, block.get_id());

            let mut total_fees = AccumulatedFee::new();
            let mut transactions = Vec::with_capacity(block.transactions().len());
            let mut tx_additional_infos = Vec::with_capacity(block.transactions().len());

            // The order in which data is processed and flushed to the storage is very specific.
            //
            // First, the tx fee is calculated and the tables dependant on tx info are updated. This is done
            // per tx because calculating fee requires up to date utxo and orders info.
            //
            // Second, total fee is accumulated and block is flushed to the db.
            //
            // Third, txs are flushed to the db AFTER the block.
            // This is done because transaction table has FOREIGN key `owning_block_id` referring block table.

            for tx in block.transactions().iter() {
                let (tx_fee, tx_additional_info) = calculate_tx_fee_and_collect_token_info(
                    &self.chain_config,
                    &mut db_tx,
                    tx.transaction(),
                    block_height,
                )
                .await?;

                total_fees = total_fees.combine(tx_fee).expect("no overflow");
                tx_additional_infos.push(tx_additional_info.clone());

                update_tables_from_transaction(
                    Arc::clone(&self.chain_config),
                    &mut db_tx,
                    (block_height, block_timestamp),
                    new_median_time,
                    tx,
                )
                .await
                .expect("Unable to update tables from transaction");

                let tx_info = TransactionInfo {
                    tx: tx.clone(),
                    additional_info: tx_additional_info,
                };
                transactions.push(tx_info);
            }

            let block_id = block.get_id();
            let block_with_extras = BlockWithExtraData {
                block: WithId::take(block.clone()),
                tx_additional_infos,
            };
            db_tx
                .set_mainchain_block(block_id, block_height, &block_with_extras)
                .await
                .expect("Unable to set block");

            for tx_info in transactions {
                db_tx
                    .set_transaction(tx_info.tx.transaction().get_id(), block_id, &tx_info)
                    .await
                    .expect("Unable to set transaction");
            }

            db_tx
                .set_block_aux_data(
                    block_id,
                    &BlockAuxData::new(block_id.into(), block_height, block_timestamp),
                )
                .await
                .expect("Unable to set block aux data");

            let block_fees = total_fees
                .map_into_block_fees(&self.chain_config, block_height)
                .expect("no overflow");

            update_tables_from_block(
                Arc::clone(&self.chain_config),
                &mut db_tx,
                block_height,
                &block,
                block_fees,
            )
            .await
            .expect("Unable to update tables from block");
        }

        db_tx.commit().await.expect("Unable to commit transaction");
        logging::log::info!("Database commit completed successfully");

        Ok(())
    }
}

// Find locked UTXOs that are unlocked at this height or time and update address balances
async fn update_locked_amounts_for_current_block<T: ApiServerStorageWrite>(
    db_tx: &mut T,
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    (previous_median_time, new_median_time): (BlockTimestamp, BlockTimestamp),
) -> Result<(), ApiServerStorageError> {
    let locked_utxos = db_tx
        .get_locked_utxos_until_now(block_height, (previous_median_time, new_median_time))
        .await?;

    for (outpoint, locked_utxo) in locked_utxos {
        match &locked_utxo.output {
            TxOutput::LockThenTransfer(outvalue, destination, _) => {
                let address = Address::<Destination>::new(chain_config, destination.clone())
                    .expect("Unable to encode destination");

                match outvalue {
                    OutputValue::Coin(amount) => {
                        increase_address_amount(
                            db_tx,
                            &address,
                            amount,
                            CoinOrTokenId::Coin,
                            block_height,
                        )
                        .await;
                        decrease_address_locked_amount(
                            db_tx,
                            address,
                            amount,
                            CoinOrTokenId::Coin,
                            block_height,
                        )
                        .await;
                    }
                    OutputValue::TokenV0(_) => {}
                    OutputValue::TokenV1(token_id, amount) => {
                        increase_address_amount(
                            db_tx,
                            &address,
                            amount,
                            CoinOrTokenId::TokenId(*token_id),
                            block_height,
                        )
                        .await;
                        decrease_address_locked_amount(
                            db_tx,
                            address,
                            amount,
                            CoinOrTokenId::TokenId(*token_id),
                            block_height,
                        )
                        .await;
                    }
                }
            }
            _ => panic!("locked utxo not lock then transfer output"),
        }

        if let Some(destination) = get_tx_output_destination(&locked_utxo.output) {
            let address = Address::<Destination>::new(chain_config, destination.clone())
                .expect("Unable to encode destination");
            let utxo = Utxo::new_with_info(locked_utxo, false);
            db_tx.set_utxo_at_height(outpoint, utxo, address.as_str(), block_height).await?;
        }
    }

    Ok(())
}

async fn previous_and_new_median_time<T: ApiServerStorageRead>(
    db_tx: &mut T,
    block_timestamp: BlockTimestamp,
) -> Result<(BlockTimestamp, BlockTimestamp), ApiServerStorageError> {
    let mut timestamps = db_tx.get_latest_blocktimestamps().await?;
    let previous_median_time =
        calculate_median_time_past_from_blocktimestamps(timestamps.iter().copied());
    timestamps.insert(0, block_timestamp);
    let new_median_time =
        calculate_median_time_past_from_blocktimestamps(timestamps.iter().copied());

    Ok((previous_median_time, new_median_time))
}

async fn disconnect_tables_above_height<T: ApiServerStorageWrite>(
    db_tx: &mut T,
    block_height: BlockHeight,
) -> Result<(), ApiServerStorageError> {
    logging::log::info!("Disconnecting blocks above: {:?}", block_height);
    db_tx.del_address_balance_above_height(block_height).await?;

    db_tx.del_address_locked_balance_above_height(block_height).await?;

    db_tx.del_address_transactions_above_height(block_height).await?;

    db_tx.del_utxo_above_height(block_height).await?;

    db_tx.del_locked_utxo_above_height(block_height).await?;

    db_tx.del_delegations_above_height(block_height).await?;

    db_tx.del_pools_above_height(block_height).await?;

    db_tx.del_token_issuance_above_height(block_height).await?;

    db_tx.del_nft_issuance_above_height(block_height).await?;

    db_tx.del_coin_or_token_decimals_above_height(block_height).await?;

    db_tx.del_main_chain_blocks_above_height(block_height).await?;

    db_tx.del_statistics_above_height(block_height).await?;

    db_tx.del_orders_above_height(block_height).await?;

    Ok(())
}

async fn update_tables_from_block<T: ApiServerStorageWrite>(
    chain_config: Arc<ChainConfig>,
    db_tx: &mut T,
    block_height: BlockHeight,
    block: &Block,
    total_tx_fees: Fee,
) -> Result<(), ApiServerStorageError> {
    update_tables_from_block_reward(
        chain_config.clone(),
        db_tx,
        block_height,
        block.block_reward().outputs(),
        block.get_id().into(),
    )
    .await
    .expect("Unable to update tables from block reward");

    update_tables_from_consensus_data(
        chain_config.clone(),
        db_tx,
        block_height,
        block,
        total_tx_fees,
    )
    .await
    .expect("Unable to update tables from consensus data");

    Ok(())
}

async fn update_tables_from_block_reward<T: ApiServerStorageWrite>(
    chain_config: Arc<ChainConfig>,
    db_tx: &mut T,
    block_height: BlockHeight,
    block_rewards: &[TxOutput],
    block_id: Id<GenBlock>,
) -> Result<(), ApiServerStorageError> {
    for (idx, output) in block_rewards.iter().enumerate() {
        let outpoint = UtxoOutPoint::new(OutPointSourceId::BlockReward(block_id), idx as u32);
        match output {
            TxOutput::Burn(_)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DataDeposit(_)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::Htlc(_, _)
            | TxOutput::CreateOrder(_) => {}
            TxOutput::ProduceBlockFromStake(_, _) => {
                set_utxo(
                    outpoint,
                    output,
                    None,
                    db_tx,
                    block_height,
                    false,
                    &chain_config,
                )
                .await;
            }
            TxOutput::CreateStakePool(pool_id, pool_data) => {
                let pool_data = PoolDataWithExtraInfo::new(pool_data.as_ref().clone().into());

                db_tx
                    .set_pool_data_at_height(*pool_id, &pool_data, block_height)
                    .await
                    .expect("unable to update pool data");
                set_utxo(
                    outpoint,
                    output,
                    None,
                    db_tx,
                    block_height,
                    false,
                    &chain_config,
                )
                .await;
                increase_statistic_amount(
                    db_tx,
                    CoinOrTokenStatistic::Preminted,
                    &pool_data.pledge_amount(),
                    CoinOrTokenId::Coin,
                    block_height,
                )
                .await;
                increase_statistic_amount(
                    db_tx,
                    CoinOrTokenStatistic::CirculatingSupply,
                    &pool_data.pledge_amount(),
                    CoinOrTokenId::Coin,
                    block_height,
                )
                .await;
                increase_statistic_amount(
                    db_tx,
                    CoinOrTokenStatistic::Staked,
                    &pool_data.pledge_amount(),
                    CoinOrTokenId::Coin,
                    block_height,
                )
                .await;
            }
            TxOutput::Transfer(output_value, destination)
            | TxOutput::LockThenTransfer(output_value, destination, _) => {
                let address = Address::<Destination>::new(&chain_config, destination.clone())
                    .expect("Unable to encode destination");
                let token_decimals = match output_value {
                    OutputValue::TokenV0(_) => None,
                    OutputValue::TokenV1(token_id, amount) => {
                        increase_address_amount(
                            db_tx,
                            &address,
                            amount,
                            CoinOrTokenId::TokenId(*token_id),
                            block_height,
                        )
                        .await;
                        increase_statistic_amount(
                            db_tx,
                            CoinOrTokenStatistic::Preminted,
                            amount,
                            CoinOrTokenId::TokenId(*token_id),
                            block_height,
                        )
                        .await;
                        increase_statistic_amount(
                            db_tx,
                            CoinOrTokenStatistic::CirculatingSupply,
                            amount,
                            CoinOrTokenId::TokenId(*token_id),
                            block_height,
                        )
                        .await;
                        Some(token_decimals(*token_id, &BTreeMap::new(), db_tx).await?.1)
                    }
                    OutputValue::Coin(amount) => {
                        increase_address_amount(
                            db_tx,
                            &address,
                            amount,
                            CoinOrTokenId::Coin,
                            block_height,
                        )
                        .await;
                        increase_statistic_amount(
                            db_tx,
                            CoinOrTokenStatistic::Preminted,
                            amount,
                            CoinOrTokenId::Coin,
                            block_height,
                        )
                        .await;
                        increase_statistic_amount(
                            db_tx,
                            CoinOrTokenStatistic::CirculatingSupply,
                            amount,
                            CoinOrTokenId::Coin,
                            block_height,
                        )
                        .await;
                        None
                    }
                };
                set_utxo(
                    outpoint,
                    output,
                    token_decimals,
                    db_tx,
                    block_height,
                    false,
                    &chain_config,
                )
                .await;
            }
        }
    }

    Ok(())
}

async fn calculate_tx_fee_and_collect_token_info<T: ApiServerStorageWrite>(
    chain_config: &ChainConfig,
    db_tx: &mut T,
    tx: &Transaction,
    block_height: BlockHeight,
) -> Result<(AccumulatedFee, TxAdditionalInfo), ApiServerStorageError> {
    let new_tokens: BTreeMap<_, _> = tx
        .outputs()
        .iter()
        .filter_map(|out| match out {
            TxOutput::IssueNft(token_id, _, _) => Some((*token_id, 0)),
            TxOutput::IssueFungibleToken(data) => {
                let token_id = make_token_id(tx.inputs()).expect("must exist");
                match data.as_ref() {
                    TokenIssuance::V1(data) => Some((token_id, data.number_of_decimals)),
                }
            }
            TxOutput::CreateStakePool(_, _)
            | TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::DataDeposit(_)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::Htlc(_, _)
            | TxOutput::CreateOrder(_) => None,
        })
        .collect();

    let fee = tx_fees(chain_config, block_height, tx, db_tx).await?;

    let input_tasks: FuturesOrdered<_> =
        tx.inputs().iter().map(|input| fetch_utxo(input, db_tx)).collect();
    let input_utxos: Vec<Option<TxOutput>> = input_tasks.try_collect().await?;
    let token_ids = {
        let mut token_ids = BTreeSet::new();
        for (inp, utxo) in tx.inputs().iter().zip(input_utxos.iter()) {
            match inp {
                TxInput::Utxo(_) => {
                    token_ids.extend(get_referenced_token_ids_ignore_issuance(
                        utxo.as_ref().expect("must be present"),
                    ));
                }
                TxInput::Account(_) => {}
                TxInput::AccountCommand(_, cmd) => match cmd {
                    AccountCommand::MintTokens(token_id, _)
                    | AccountCommand::FreezeToken(token_id, _)
                    | AccountCommand::UnmintTokens(token_id)
                    | AccountCommand::UnfreezeToken(token_id)
                    | AccountCommand::LockTokenSupply(token_id)
                    | AccountCommand::ChangeTokenMetadataUri(token_id, _)
                    | AccountCommand::ChangeTokenAuthority(token_id, _) => {
                        token_ids.insert(*token_id);
                    }
                    AccountCommand::ConcludeOrder(order_id)
                    | AccountCommand::FillOrder(order_id, _, _) => {
                        let order = db_tx.get_order(*order_id).await?.expect("must exist");
                        if let Some(id) = order.ask_currency.token_id() {
                            token_ids.insert(id);
                        }
                        if let Some(id) = order.give_currency.token_id() {
                            token_ids.insert(id);
                        }
                    }
                },
                TxInput::OrderAccountCommand(cmd) => match cmd {
                    OrderAccountCommand::FillOrder(order_id, _, _)
                    | OrderAccountCommand::FreezeOrder(order_id)
                    | OrderAccountCommand::ConcludeOrder(order_id) => {
                        let order = db_tx.get_order(*order_id).await?.expect("must exist");
                        if let Some(id) = order.ask_currency.token_id() {
                            token_ids.insert(id);
                        }
                        if let Some(id) = order.give_currency.token_id() {
                            token_ids.insert(id);
                        }
                    }
                },
            };
        }

        tx.outputs().iter().map(get_referenced_token_ids_ignore_issuance).fold(
            token_ids,
            |mut token_ids_acc, tokens_iter| {
                token_ids_acc.extend(tokens_iter);
                token_ids_acc
            },
        )
    };

    let token_tasks: FuturesOrdered<_> = token_ids
        .iter()
        .map(|token_id| token_decimals(*token_id, &new_tokens, db_tx))
        .collect();
    let token_decimals: BTreeMap<TokenId, u8> = token_tasks.try_collect().await?;

    let tx_aditional_infos = TxAdditionalInfo {
        fee: fee
            .clone()
            .map_into_block_fees(chain_config, block_height)
            .expect("no overflow")
            .0,
        input_utxos,
        token_decimals,
    };

    Ok((fee, tx_aditional_infos))
}

async fn fetch_utxo<T: ApiServerStorageRead>(
    input: &TxInput,
    db_tx: &T,
) -> Result<Option<TxOutput>, ApiServerStorageError> {
    match input {
        TxInput::Utxo(outpoint) => {
            let utxo = db_tx
                .get_utxo(outpoint.clone())
                .await?
                .map(|utxo| utxo.into_output())
                .expect("must be present");
            Ok(Some(utxo))
        }
        TxInput::Account(_) | TxInput::AccountCommand(_, _) | TxInput::OrderAccountCommand(_) => {
            Ok(None)
        }
    }
}

async fn token_decimals<T: ApiServerStorageRead>(
    token_id: TokenId,
    new_tokens: &BTreeMap<TokenId, u8>,
    db_tx: &T,
) -> Result<(TokenId, u8), ApiServerStorageError> {
    let decimals = if let Some(decimals) = new_tokens.get(&token_id) {
        *decimals
    } else {
        db_tx.get_token_num_decimals(token_id).await?.expect("must be present")
    };
    Ok((token_id, decimals))
}

struct PoSAccountingAdapterToCheckFees {
    pools: BTreeMap<PoolId, PoolData>,
}

impl PoSAccountingView for PoSAccountingAdapterToCheckFees {
    type Error = pos_accounting::Error;

    fn pool_exists(&self, _pool_id: PoolId) -> Result<bool, Self::Error> {
        unimplemented!()
    }

    fn get_pool_balance(&self, _pool_id: PoolId) -> Result<Amount, Self::Error> {
        unimplemented!()
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Self::Error> {
        Ok(self.pools.get(&pool_id).cloned())
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

async fn tx_fees<T: ApiServerStorageRead>(
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    tx: &Transaction,
    db_tx: &T,
) -> Result<AccumulatedFee, ApiServerStorageError> {
    let inputs_utxos = collect_inputs_utxos(db_tx, tx.inputs()).await?;
    let pools = prefetch_pool_data(&inputs_utxos, db_tx).await?;
    let pos_accounting_adapter = PoSAccountingAdapterToCheckFees { pools };
    let tokens_view = StubTokensAccounting;

    let orders_store = prefetch_orders(tx.inputs(), db_tx).await?;
    let orders_db = orders_accounting::OrdersAccountingDB::new(&orders_store);

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        chain_config,
        block_height,
        &orders_db,
        &pos_accounting_adapter,
        &tokens_view,
        tx.inputs(),
        &inputs_utxos,
    )
    .expect("valid block");
    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(chain_config, block_height, tx.outputs())
            .expect("valid block");
    let consumed_accumulator =
        inputs_accumulator.satisfy_with(outputs_accumulator).expect("valid block");
    Ok(consumed_accumulator)
}

async fn prefetch_pool_data<T: ApiServerStorageRead>(
    inputs_utxos: &Vec<Option<TxOutput>>,
    db_tx: &T,
) -> Result<BTreeMap<PoolId, PoolData>, ApiServerStorageError> {
    let mut pools = BTreeMap::new();
    for output in inputs_utxos {
        match output {
            Some(
                TxOutput::CreateStakePool(pool_id, _) | TxOutput::ProduceBlockFromStake(_, pool_id),
            ) => {
                let data = db_tx.get_pool_data(*pool_id).await?.expect("should exist").pool_data;
                pools.insert(*pool_id, data);
            }
            Some(
                TxOutput::Burn(_)
                | TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::DataDeposit(_)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _)
                | TxOutput::IssueNft(_, _, _)
                | TxOutput::IssueFungibleToken(_)
                | TxOutput::Htlc(_, _)
                | TxOutput::CreateOrder(_),
            ) => {}
            None => {}
        }
    }
    Ok(pools)
}

async fn prefetch_orders<T: ApiServerStorageRead>(
    inputs: &[TxInput],
    db_tx: &T,
) -> Result<orders_accounting::InMemoryOrdersAccounting, ApiServerStorageError> {
    let mut orders_data = BTreeMap::<OrderId, OrderData>::new();
    let mut ask_balances = BTreeMap::<OrderId, Amount>::new();
    let mut give_balances = BTreeMap::<OrderId, Amount>::new();

    let to_order_data = |order: &Order| {
        let ask = order.ask_currency.to_output_value(order.initially_asked);
        let give = order.give_currency.to_output_value(order.initially_given);
        OrderData::new(order.conclude_destination.clone(), ask, give)
    };

    for input in inputs {
        match input {
            TxInput::Utxo(_) | TxInput::Account(_) => {}
            TxInput::OrderAccountCommand(cmd) => match cmd {
                OrderAccountCommand::FillOrder(order_id, _, _)
                | OrderAccountCommand::FreezeOrder(order_id)
                | OrderAccountCommand::ConcludeOrder(order_id) => {
                    let order = db_tx.get_order(*order_id).await?.expect("must be present ");
                    let order_data = to_order_data(&order);

                    ask_balances.insert(*order_id, order.ask_balance);
                    give_balances.insert(*order_id, order.give_balance);
                    orders_data.insert(*order_id, order_data);
                }
            },
            TxInput::AccountCommand(_, account_command) => match account_command {
                AccountCommand::MintTokens(_, _)
                | AccountCommand::UnmintTokens(_)
                | AccountCommand::LockTokenSupply(_)
                | AccountCommand::FreezeToken(_, _)
                | AccountCommand::UnfreezeToken(_)
                | AccountCommand::ChangeTokenAuthority(_, _)
                | AccountCommand::ChangeTokenMetadataUri(_, _) => {}
                AccountCommand::FillOrder(order_id, _, _)
                | AccountCommand::ConcludeOrder(order_id) => {
                    let order = db_tx.get_order(*order_id).await?.expect("must be present ");
                    let order_data = to_order_data(&order);

                    ask_balances.insert(*order_id, order.ask_balance);
                    give_balances.insert(*order_id, order.give_balance);
                    orders_data.insert(*order_id, order_data);
                }
            },
        }
    }
    Ok(orders_accounting::InMemoryOrdersAccounting::from_values(
        orders_data,
        ask_balances,
        give_balances,
    ))
}

async fn collect_inputs_utxos<T: ApiServerStorageRead>(
    db_tx: &T,
    inputs: &[TxInput],
) -> Result<Vec<Option<TxOutput>>, ApiServerStorageError> {
    let mut outputs = Vec::with_capacity(inputs.len());
    for input in inputs {
        let output = fetch_utxo(input, db_tx).await?;
        outputs.push(output);
    }

    Ok(outputs)
}

async fn update_tables_from_consensus_data<T: ApiServerStorageWrite>(
    chain_config: Arc<ChainConfig>,
    db_tx: &mut T,
    block_height: BlockHeight,
    block: &Block,
    total_tx_fees: Fee,
) -> Result<(), ApiServerStorageError> {
    match block.consensus_data() {
        ConsensusData::None | ConsensusData::PoW(_) => {}
        ConsensusData::PoS(pos_data) => {
            for input in pos_data.kernel_inputs() {
                match input {
                    TxInput::Utxo(outpoint) => {
                        let utxo =
                            db_tx.get_utxo(outpoint.clone()).await?.expect("must be present");
                        set_utxo(
                            outpoint.clone(),
                            utxo.output(),
                            None,
                            db_tx,
                            block_height,
                            true,
                            &chain_config,
                        )
                        .await;
                    }
                    TxInput::Account(_)
                    | TxInput::AccountCommand(_, _)
                    | TxInput::OrderAccountCommand(_) => {}
                }
            }

            let block_subsidy = chain_config.as_ref().block_subsidy_at_height(&block_height);

            let total_reward = (block_subsidy + total_tx_fees.0)
                .expect("Block subsidy and fees should not overflow");

            let pool_id = *pos_data.stake_pool_id();
            let pool_data = db_tx
                .get_pool_data(pool_id)
                .await
                .expect("Unable to get pool data")
                .expect("Pool should exist");

            let delegation_shares = db_tx.get_pool_delegations(pool_id).await?;
            let mut adapter =
                pos_adapter::PoSAdapter::new(pool_id, pool_data.pool_data, &delegation_shares);

            let reward_distribution_version = chain_config
                .as_ref()
                .chainstate_upgrades()
                .version_at_height(block_height)
                .1
                .reward_distribution_version();

            distribute_pos_reward(
                &mut adapter,
                block.get_id(),
                pool_id,
                total_reward,
                reward_distribution_version,
            )
            .expect("no error");
            increase_statistic_amount(
                db_tx,
                CoinOrTokenStatistic::Staked,
                &total_reward,
                CoinOrTokenId::Coin,
                block_height,
            )
            .await;
            increase_statistic_amount(
                db_tx,
                CoinOrTokenStatistic::CirculatingSupply,
                &block_subsidy,
                CoinOrTokenId::Coin,
                block_height,
            )
            .await;

            for (delegation_id, rewards) in adapter.rewards_per_delegation() {
                let delegation = delegation_shares.get(delegation_id).expect("must exist").clone();
                let updated_delegation = delegation.stake(*rewards);
                db_tx
                    .set_delegation_at_height(*delegation_id, &updated_delegation, block_height)
                    .await?;
            }
            let delegation_rewards = adapter
                .rewards_per_delegation()
                .iter()
                .map(|x| x.1)
                .sum::<Option<Amount>>()
                .expect("no overflow");

            let new_pool_data =
                adapter.get_pool_data(pool_id).expect("no error").expect("must exist");
            let new_pool_data = PoolDataWithExtraInfo {
                pool_data: new_pool_data,
                delegations_balance: (pool_data.delegations_balance + delegation_rewards)
                    .expect("no overflow"),
            };
            db_tx.set_pool_data_at_height(pool_id, &new_pool_data, block_height).await?;
        }
    }

    Ok(())
}

async fn update_tables_from_transaction<T: ApiServerStorageWrite>(
    chain_config: Arc<ChainConfig>,
    db_tx: &mut T,
    (block_height, block_timestamp): (BlockHeight, BlockTimestamp),
    median_time: BlockTimestamp,
    transaction: &SignedTransaction,
) -> Result<(), ApiServerStorageError> {
    update_tables_from_transaction_inputs(
        Arc::clone(&chain_config),
        db_tx,
        block_height,
        transaction.transaction().inputs(),
        transaction.transaction(),
    )
    .await
    .expect("Unable to update tables from transaction inputs");

    update_tables_from_transaction_outputs(
        Arc::clone(&chain_config),
        db_tx,
        (block_height, block_timestamp),
        median_time,
        transaction.transaction().get_id(),
        transaction.transaction().inputs(),
        transaction.transaction().outputs(),
    )
    .await
    .expect("Unable to update tables from transaction outputs");

    Ok(())
}

async fn update_tables_from_transaction_inputs<T: ApiServerStorageWrite>(
    chain_config: Arc<ChainConfig>,
    db_tx: &mut T,
    block_height: BlockHeight,
    inputs: &[TxInput],
    tx: &Transaction,
) -> Result<(), ApiServerStorageError> {
    let mut address_transactions: BTreeMap<Address<Destination>, BTreeSet<Id<Transaction>>> =
        BTreeMap::new();

    for input in inputs {
        match input {
            TxInput::AccountCommand(_, cmd) => match cmd {
                AccountCommand::MintTokens(token_id, amount) => {
                    let issuance =
                        db_tx.get_fungible_token_issuance(*token_id).await?.expect("must exist");

                    let issuance = issuance.mint_tokens(*amount);
                    db_tx.set_fungible_token_data(*token_id, block_height, issuance).await?;
                    increase_statistic_amount(
                        db_tx,
                        CoinOrTokenStatistic::CirculatingSupply,
                        amount,
                        CoinOrTokenId::TokenId(*token_id),
                        block_height,
                    )
                    .await;
                    let amount = chain_config.token_supply_change_fee(block_height);
                    increase_statistic_amount(
                        db_tx,
                        CoinOrTokenStatistic::Burned,
                        &amount,
                        CoinOrTokenId::Coin,
                        block_height,
                    )
                    .await;
                    decrease_statistic_amount(
                        db_tx,
                        CoinOrTokenStatistic::CirculatingSupply,
                        &amount,
                        CoinOrTokenId::Coin,
                        block_height,
                    )
                    .await;
                }
                AccountCommand::UnmintTokens(token_id) => {
                    let total_burned =
                        calculate_tokens_burned_in_outputs(tx, token_id).expect("no overflow");

                    let issuance =
                        db_tx.get_fungible_token_issuance(*token_id).await?.expect("must exist");

                    let issuance = issuance.unmint_tokens(total_burned);
                    db_tx.set_fungible_token_data(*token_id, block_height, issuance).await?;
                    let amount = chain_config.token_supply_change_fee(block_height);
                    increase_statistic_amount(
                        db_tx,
                        CoinOrTokenStatistic::Burned,
                        &amount,
                        CoinOrTokenId::Coin,
                        block_height,
                    )
                    .await;
                    decrease_statistic_amount(
                        db_tx,
                        CoinOrTokenStatistic::CirculatingSupply,
                        &amount,
                        CoinOrTokenId::Coin,
                        block_height,
                    )
                    .await;
                }
                AccountCommand::FreezeToken(token_id, is_unfreezable) => {
                    let issuance =
                        db_tx.get_fungible_token_issuance(*token_id).await?.expect("must exist");

                    let issuance = issuance.freeze(*is_unfreezable);
                    db_tx.set_fungible_token_data(*token_id, block_height, issuance).await?;
                    let amount = chain_config.token_freeze_fee(block_height);
                    increase_statistic_amount(
                        db_tx,
                        CoinOrTokenStatistic::Burned,
                        &amount,
                        CoinOrTokenId::Coin,
                        block_height,
                    )
                    .await;
                    decrease_statistic_amount(
                        db_tx,
                        CoinOrTokenStatistic::CirculatingSupply,
                        &amount,
                        CoinOrTokenId::Coin,
                        block_height,
                    )
                    .await;
                }
                AccountCommand::UnfreezeToken(token_id) => {
                    let issuance =
                        db_tx.get_fungible_token_issuance(*token_id).await?.expect("must exist");

                    let issuance = issuance.unfreeze();
                    db_tx.set_fungible_token_data(*token_id, block_height, issuance).await?;
                    let amount = chain_config.token_freeze_fee(block_height);
                    increase_statistic_amount(
                        db_tx,
                        CoinOrTokenStatistic::Burned,
                        &amount,
                        CoinOrTokenId::Coin,
                        block_height,
                    )
                    .await;
                    decrease_statistic_amount(
                        db_tx,
                        CoinOrTokenStatistic::CirculatingSupply,
                        &amount,
                        CoinOrTokenId::Coin,
                        block_height,
                    )
                    .await;
                }
                AccountCommand::LockTokenSupply(token_id) => {
                    let issuance =
                        db_tx.get_fungible_token_issuance(*token_id).await?.expect("must exist");

                    let issuance = issuance.lock();
                    db_tx.set_fungible_token_data(*token_id, block_height, issuance).await?;
                    let amount = chain_config.token_supply_change_fee(block_height);
                    increase_statistic_amount(
                        db_tx,
                        CoinOrTokenStatistic::Burned,
                        &amount,
                        CoinOrTokenId::Coin,
                        block_height,
                    )
                    .await;
                    decrease_statistic_amount(
                        db_tx,
                        CoinOrTokenStatistic::CirculatingSupply,
                        &amount,
                        CoinOrTokenId::Coin,
                        block_height,
                    )
                    .await;
                }
                AccountCommand::ChangeTokenAuthority(token_id, destination) => {
                    let issuance =
                        db_tx.get_fungible_token_issuance(*token_id).await?.expect("must exist");

                    let issuance = issuance.change_authority(destination.clone());
                    db_tx.set_fungible_token_data(*token_id, block_height, issuance).await?;
                    let amount = chain_config.token_change_authority_fee(block_height);
                    increase_statistic_amount(
                        db_tx,
                        CoinOrTokenStatistic::Burned,
                        &amount,
                        CoinOrTokenId::Coin,
                        block_height,
                    )
                    .await;
                    decrease_statistic_amount(
                        db_tx,
                        CoinOrTokenStatistic::CirculatingSupply,
                        &amount,
                        CoinOrTokenId::Coin,
                        block_height,
                    )
                    .await;
                }
                AccountCommand::ChangeTokenMetadataUri(token_id, metadata_uri) => {
                    let issuance =
                        db_tx.get_fungible_token_issuance(*token_id).await?.expect("must exist");

                    let issuance = issuance.change_metadata_uri(metadata_uri.clone());
                    db_tx.set_fungible_token_data(*token_id, block_height, issuance).await?;
                    let amount = chain_config.token_change_metadata_uri_fee();
                    increase_statistic_amount(
                        db_tx,
                        CoinOrTokenStatistic::Burned,
                        &amount,
                        CoinOrTokenId::Coin,
                        block_height,
                    )
                    .await;
                    decrease_statistic_amount(
                        db_tx,
                        CoinOrTokenStatistic::CirculatingSupply,
                        &amount,
                        CoinOrTokenId::Coin,
                        block_height,
                    )
                    .await;
                }
                AccountCommand::FillOrder(order_id, fill_amount_in_ask_currency, _) => {
                    let order = db_tx.get_order(*order_id).await?.expect("must exist");
                    let order =
                        order.fill(&chain_config, block_height, *fill_amount_in_ask_currency);

                    db_tx.set_order_at_height(*order_id, &order, block_height).await?;
                }
                AccountCommand::ConcludeOrder(order_id) => {
                    let order = db_tx.get_order(*order_id).await?.expect("must exist");
                    let order = order.conclude();

                    db_tx.set_order_at_height(*order_id, &order, block_height).await?;
                }
            },
            TxInput::OrderAccountCommand(cmd) => match cmd {
                OrderAccountCommand::FillOrder(order_id, fill_amount_in_ask_currency, _) => {
                    let order = db_tx.get_order(*order_id).await?.expect("must exist");
                    let order =
                        order.fill(&chain_config, block_height, *fill_amount_in_ask_currency);

                    db_tx.set_order_at_height(*order_id, &order, block_height).await?;
                }
                OrderAccountCommand::ConcludeOrder(order_id) => {
                    let order = db_tx.get_order(*order_id).await?.expect("must exist");
                    let order = order.conclude();

                    db_tx.set_order_at_height(*order_id, &order, block_height).await?;
                }
                OrderAccountCommand::FreezeOrder(order_id) => {
                    let order = db_tx.get_order(*order_id).await?.expect("must exist");
                    let order = order.freeze();

                    db_tx.set_order_at_height(*order_id, &order, block_height).await?;
                }
            },
            TxInput::Account(outpoint) => {
                match outpoint.account() {
                    AccountSpending::DelegationBalance(delegation_id, amount) => {
                        // Update delegation pledge

                        //TODO: optimize into a single query when amount is a number in the DB
                        let delegation = db_tx
                            .get_delegation(*delegation_id)
                            .await
                            .expect("Unable to get delegation")
                            .expect("Delegation should exist");

                        let new_delegation = delegation.spend_share(*amount, outpoint.nonce());

                        db_tx
                            .set_delegation_at_height(*delegation_id, &new_delegation, block_height)
                            .await
                            .expect("Unable to update delegation");

                        let pool_id = *new_delegation.pool_id();
                        let pool_data = db_tx
                            .get_pool_data(pool_id)
                            .await
                            .expect("unable to get pool data")
                            .expect("must exist");
                        let new_pool_data = pool_data.decrease_delegation_balance(*amount);

                        db_tx
                            .set_pool_data_at_height(pool_id, &new_pool_data, block_height)
                            .await
                            .expect("unable to update pool data");
                        decrease_statistic_amount(
                            db_tx,
                            CoinOrTokenStatistic::Staked,
                            amount,
                            CoinOrTokenId::Coin,
                            block_height,
                        )
                        .await;
                    }
                }
            }
            TxInput::Utxo(outpoint) => match outpoint.source_id() {
                OutPointSourceId::BlockReward(_) => {
                    let utxo = db_tx.get_utxo(outpoint.clone()).await?.expect("must be present");
                    set_utxo(
                        outpoint.clone(),
                        utxo.output(),
                        utxo.utxo_with_extra_info().token_decimals,
                        db_tx,
                        block_height,
                        true,
                        &chain_config,
                    )
                    .await;

                    match utxo.into_output() {
                        TxOutput::Burn(_)
                        | TxOutput::Transfer(_, _)
                        | TxOutput::LockThenTransfer(_, _, _)
                        | TxOutput::IssueNft(_, _, _)
                        | TxOutput::DataDeposit(_)
                        | TxOutput::CreateDelegationId(_, _)
                        | TxOutput::DelegateStaking(_, _)
                        | TxOutput::IssueFungibleToken(_)
                        | TxOutput::Htlc(_, _)
                        | TxOutput::CreateOrder(_) => {}
                        TxOutput::CreateStakePool(pool_id, _)
                        | TxOutput::ProduceBlockFromStake(_, pool_id) => {
                            let pool_data = db_tx
                                .get_pool_data(pool_id)
                                .await?
                                .expect("pool data should exist")
                                .decommission_pool();

                            db_tx
                                .set_pool_data_at_height(pool_id, &pool_data, block_height)
                                .await
                                .expect("unable to update pool data");

                            let address = Address::<Destination>::new(
                                &chain_config,
                                pool_data.decommission_destination().clone(),
                            )
                            .expect("Unable to encode destination");

                            address_transactions
                                .entry(address.clone())
                                .or_default()
                                .insert(tx.get_id());
                            decrease_statistic_amount(
                                db_tx,
                                CoinOrTokenStatistic::Staked,
                                &pool_data.pledge_amount(),
                                CoinOrTokenId::Coin,
                                block_height,
                            )
                            .await;
                        }
                    }
                }
                OutPointSourceId::Transaction(_) => {
                    let utxo = db_tx.get_utxo(outpoint.clone()).await?.expect("must be present");
                    set_utxo(
                        outpoint.clone(),
                        utxo.output(),
                        utxo.utxo_with_extra_info().token_decimals,
                        db_tx,
                        block_height,
                        true,
                        &chain_config,
                    )
                    .await;

                    match utxo.into_output() {
                        TxOutput::Burn(_)
                        | TxOutput::CreateDelegationId(_, _)
                        | TxOutput::DelegateStaking(_, _)
                        | TxOutput::DataDeposit(_)
                        | TxOutput::IssueFungibleToken(_)
                        | TxOutput::CreateOrder(_) => {}
                        TxOutput::CreateStakePool(pool_id, _)
                        | TxOutput::ProduceBlockFromStake(_, pool_id) => {
                            let pool_data = db_tx
                                .get_pool_data(pool_id)
                                .await?
                                .expect("pool data should exist")
                                .decommission_pool();

                            db_tx
                                .set_pool_data_at_height(pool_id, &pool_data, block_height)
                                .await
                                .expect("unable to update pool data");
                            decrease_statistic_amount(
                                db_tx,
                                CoinOrTokenStatistic::Staked,
                                &pool_data.pledge_amount(),
                                CoinOrTokenId::Coin,
                                block_height,
                            )
                            .await;
                        }
                        TxOutput::IssueNft(token_id, _, destination) => {
                            let address = Address::<Destination>::new(&chain_config, destination)
                                .expect("Unable to encode destination");

                            address_transactions
                                .entry(address.clone())
                                .or_default()
                                .insert(tx.get_id());

                            decrease_address_amount(
                                db_tx,
                                address,
                                &Amount::from_atoms(1),
                                CoinOrTokenId::TokenId(token_id),
                                block_height,
                            )
                            .await;
                        }
                        TxOutput::Htlc(_, htlc) => {
                            let address =
                                Address::<Destination>::new(&chain_config, htlc.spend_key)
                                    .expect("Unable to encode destination");

                            address_transactions
                                .entry(address.clone())
                                .or_default()
                                .insert(tx.get_id());
                        }
                        TxOutput::LockThenTransfer(output_value, destination, _)
                        | TxOutput::Transfer(output_value, destination) => {
                            let address = Address::<Destination>::new(&chain_config, destination)
                                .expect("Unable to encode destination");

                            address_transactions
                                .entry(address.clone())
                                .or_default()
                                .insert(tx.get_id());

                            match output_value {
                                OutputValue::TokenV0(_) => {}
                                OutputValue::TokenV1(token_id, amount) => {
                                    decrease_address_amount(
                                        db_tx,
                                        address,
                                        &amount,
                                        CoinOrTokenId::TokenId(token_id),
                                        block_height,
                                    )
                                    .await;
                                }
                                OutputValue::Coin(amount) => {
                                    decrease_address_amount(
                                        db_tx,
                                        address,
                                        &amount,
                                        CoinOrTokenId::Coin,
                                        block_height,
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                }
            },
        }
    }

    for address_transaction in address_transactions {
        db_tx
            .set_address_transactions_at_height(
                address_transaction.0.as_str(),
                address_transaction.1.into_iter().collect(),
                block_height,
            )
            .await
            .map_err(|_| {
                ApiServerStorageError::LowLevelStorageError(
                    "Unable to set address transactions".to_string(),
                )
            })?;
    }

    Ok(())
}

async fn update_tables_from_transaction_outputs<T: ApiServerStorageWrite>(
    chain_config: Arc<ChainConfig>,
    db_tx: &mut T,
    (block_height, block_timestamp): (BlockHeight, BlockTimestamp),
    median_time: BlockTimestamp,
    transaction_id: Id<Transaction>,
    inputs: &[TxInput],
    outputs: &[TxOutput],
) -> Result<(), ApiServerStorageError> {
    let mut address_transactions: BTreeMap<Address<Destination>, BTreeSet<Id<Transaction>>> =
        BTreeMap::new();

    for (idx, output) in outputs.iter().enumerate() {
        let outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(transaction_id), idx as u32);
        match output {
            TxOutput::Burn(value) => {
                let (coin_or_token_id, amount) = match value {
                    OutputValue::Coin(amount) => (CoinOrTokenId::Coin, amount),
                    OutputValue::TokenV0(_) => {
                        continue;
                    }
                    OutputValue::TokenV1(token_id, amount) => {
                        (CoinOrTokenId::TokenId(*token_id), amount)
                    }
                };

                increase_statistic_amount(
                    db_tx,
                    CoinOrTokenStatistic::Burned,
                    amount,
                    coin_or_token_id,
                    block_height,
                )
                .await;
                decrease_statistic_amount(
                    db_tx,
                    CoinOrTokenStatistic::CirculatingSupply,
                    amount,
                    coin_or_token_id,
                    block_height,
                )
                .await;
            }
            TxOutput::DataDeposit(_) => {
                let amount = chain_config.data_deposit_fee(block_height);
                increase_statistic_amount(
                    db_tx,
                    CoinOrTokenStatistic::Burned,
                    &amount,
                    CoinOrTokenId::Coin,
                    block_height,
                )
                .await;
                decrease_statistic_amount(
                    db_tx,
                    CoinOrTokenStatistic::CirculatingSupply,
                    &amount,
                    CoinOrTokenId::Coin,
                    block_height,
                )
                .await;
            }
            TxOutput::IssueFungibleToken(issuance) => {
                let token_id = make_token_id(inputs).expect("should not fail");
                let issuance = match issuance.as_ref() {
                    TokenIssuance::V1(issuance) => FungibleTokenData {
                        token_ticker: issuance.token_ticker.clone(),
                        number_of_decimals: issuance.number_of_decimals,
                        metadata_uri: issuance.metadata_uri.clone(),
                        circulating_supply: Amount::ZERO,
                        total_supply: issuance.total_supply,
                        is_locked: false,
                        frozen: IsTokenFrozen::No(issuance.is_freezable),
                        authority: issuance.authority.clone(),
                    },
                };
                db_tx.set_fungible_token_issuance(token_id, block_height, issuance).await?;
                let amount = chain_config.fungible_token_issuance_fee();
                increase_statistic_amount(
                    db_tx,
                    CoinOrTokenStatistic::Burned,
                    &amount,
                    CoinOrTokenId::Coin,
                    block_height,
                )
                .await;
                decrease_statistic_amount(
                    db_tx,
                    CoinOrTokenStatistic::CirculatingSupply,
                    &amount,
                    CoinOrTokenId::Coin,
                    block_height,
                )
                .await;
            }
            TxOutput::IssueNft(token_id, issuance, destination) => {
                let address = Address::<Destination>::new(&chain_config, destination.clone())
                    .expect("Unable to encode destination");
                address_transactions.entry(address.clone()).or_default().insert(transaction_id);

                db_tx
                    .set_nft_token_issuance(*token_id, block_height, *issuance.clone(), destination)
                    .await?;

                increase_address_amount(
                    db_tx,
                    &address,
                    &Amount::from_atoms(1),
                    CoinOrTokenId::TokenId(*token_id),
                    block_height,
                )
                .await;
                increase_statistic_amount(
                    db_tx,
                    CoinOrTokenStatistic::CirculatingSupply,
                    &Amount::from_atoms(1),
                    CoinOrTokenId::TokenId(*token_id),
                    block_height,
                )
                .await;
                let amount = chain_config.nft_issuance_fee(block_height);
                increase_statistic_amount(
                    db_tx,
                    CoinOrTokenStatistic::Burned,
                    &amount,
                    CoinOrTokenId::Coin,
                    block_height,
                )
                .await;
                decrease_statistic_amount(
                    db_tx,
                    CoinOrTokenStatistic::CirculatingSupply,
                    &amount,
                    CoinOrTokenId::Coin,
                    block_height,
                )
                .await;

                set_utxo(
                    outpoint,
                    output,
                    None,
                    db_tx,
                    block_height,
                    false,
                    &chain_config,
                )
                .await;
            }
            TxOutput::ProduceBlockFromStake(_, _) => {}
            TxOutput::CreateDelegationId(destination, pool_id) => {
                if let Some(input0_outpoint) = inputs.iter().find_map(|input| input.utxo_outpoint())
                {
                    db_tx
                        .set_delegation_at_height(
                            make_delegation_id(input0_outpoint),
                            &Delegation::new(
                                block_height,
                                destination.clone(),
                                *pool_id,
                                Amount::ZERO,
                                AccountNonce::new(0),
                            ),
                            block_height,
                        )
                        .await
                        .expect("Unable to set delegation data");
                }
            }
            TxOutput::CreateStakePool(pool_id, stake_pool_data) => {
                // Create pool pledge
                let new_pool_data =
                    PoolDataWithExtraInfo::new(stake_pool_data.as_ref().clone().into());

                db_tx
                    .set_pool_data_at_height(*pool_id, &new_pool_data, block_height)
                    .await
                    .expect("Unable to update pool balance");
                increase_statistic_amount(
                    db_tx,
                    CoinOrTokenStatistic::Staked,
                    &stake_pool_data.pledge(),
                    CoinOrTokenId::Coin,
                    block_height,
                )
                .await;
                set_utxo(
                    outpoint,
                    output,
                    None,
                    db_tx,
                    block_height,
                    false,
                    &chain_config,
                )
                .await;
                let address = Address::<Destination>::new(
                    &chain_config,
                    stake_pool_data.decommission_key().clone(),
                )
                .expect("Unable to encode address");
                address_transactions.entry(address.clone()).or_default().insert(transaction_id);

                let staker_address =
                    Address::<Destination>::new(&chain_config, stake_pool_data.staker().clone())
                        .expect("Unable to encode address");
                address_transactions.entry(staker_address).or_default().insert(transaction_id);
            }
            TxOutput::DelegateStaking(amount, delegation_id) => {
                // Update delegation pledge

                let delegation = db_tx
                    .get_delegation(*delegation_id)
                    .await
                    .expect("Unable to get delegation")
                    .expect("Delegation should exist");

                let new_delegation = delegation.stake(*amount);

                db_tx
                    .set_delegation_at_height(*delegation_id, &new_delegation, block_height)
                    .await
                    .expect("Unable to update delegation");
                increase_statistic_amount(
                    db_tx,
                    CoinOrTokenStatistic::Staked,
                    amount,
                    CoinOrTokenId::Coin,
                    block_height,
                )
                .await;

                let pool_id = *new_delegation.pool_id();
                let pool_data = db_tx
                    .get_pool_data(pool_id)
                    .await
                    .expect("unable to get pool data")
                    .expect("must exist");
                let new_pool_data = pool_data.increase_delegation_balance(*amount);

                db_tx
                    .set_pool_data_at_height(pool_id, &new_pool_data, block_height)
                    .await
                    .expect("unable to update pool data");

                let address = Address::<Destination>::new(
                    &chain_config,
                    new_delegation.spend_destination().clone(),
                )
                .expect("Unable to encode address");
                address_transactions.entry(address.clone()).or_default().insert(transaction_id);
            }
            TxOutput::Transfer(output_value, destination) => {
                let address = Address::<Destination>::new(&chain_config, destination.clone())
                    .expect("Unable to encode destination");

                address_transactions.entry(address.clone()).or_default().insert(transaction_id);

                let token_decimals = match output_value {
                    OutputValue::TokenV0(_) => None,
                    OutputValue::TokenV1(token_id, amount) => {
                        increase_address_amount(
                            db_tx,
                            &address,
                            amount,
                            CoinOrTokenId::TokenId(*token_id),
                            block_height,
                        )
                        .await;
                        Some(token_decimals(*token_id, &BTreeMap::new(), db_tx).await?.1)
                    }
                    OutputValue::Coin(amount) => {
                        increase_address_amount(
                            db_tx,
                            &address,
                            amount,
                            CoinOrTokenId::Coin,
                            block_height,
                        )
                        .await;
                        None
                    }
                };

                let outpoint =
                    UtxoOutPoint::new(OutPointSourceId::Transaction(transaction_id), idx as u32);
                let utxo = Utxo::new(output.clone(), token_decimals, false);
                db_tx
                    .set_utxo_at_height(outpoint, utxo, address.as_str(), block_height)
                    .await
                    .expect("Unable to set utxo");
            }
            TxOutput::LockThenTransfer(output_value, destination, lock) => {
                let address = Address::<Destination>::new(&chain_config, destination.clone())
                    .expect("Unable to encode destination");

                address_transactions.entry(address.clone()).or_default().insert(transaction_id);
                let outpoint =
                    UtxoOutPoint::new(OutPointSourceId::Transaction(transaction_id), idx as u32);

                let already_unlocked = tx_verifier::timelock_check::check_timelock(
                    &block_height,
                    &block_timestamp,
                    lock,
                    &block_height,
                    &median_time,
                    &outpoint,
                )
                .is_ok();

                let token_decimals = match output_value {
                    OutputValue::Coin(amount) => {
                        if already_unlocked {
                            increase_address_amount(
                                db_tx,
                                &address,
                                amount,
                                CoinOrTokenId::Coin,
                                block_height,
                            )
                            .await;
                        } else {
                            increase_locked_address_amount(
                                db_tx,
                                &address,
                                amount,
                                CoinOrTokenId::Coin,
                                block_height,
                            )
                            .await;
                        }
                        None
                    }
                    OutputValue::TokenV0(_) => None,
                    OutputValue::TokenV1(token_id, amount) => {
                        if already_unlocked {
                            increase_address_amount(
                                db_tx,
                                &address,
                                amount,
                                CoinOrTokenId::TokenId(*token_id),
                                block_height,
                            )
                            .await;
                        } else {
                            increase_locked_address_amount(
                                db_tx,
                                &address,
                                amount,
                                CoinOrTokenId::TokenId(*token_id),
                                block_height,
                            )
                            .await;
                        }
                        Some(token_decimals(*token_id, &BTreeMap::new(), db_tx).await?.1)
                    }
                };

                if already_unlocked {
                    let utxo = Utxo::new(output.clone(), token_decimals, false);
                    db_tx
                        .set_utxo_at_height(outpoint, utxo, address.as_str(), block_height)
                        .await
                        .expect("Unable to set utxo");
                } else {
                    let lock = UtxoLock::from_output_lock(*lock, block_timestamp, block_height);
                    let utxo = LockedUtxo::new(output.clone(), token_decimals, lock);
                    db_tx
                        .set_locked_utxo_at_height(outpoint, utxo, address.as_str(), block_height)
                        .await
                        .expect("Unable to set locked utxo");
                }
            }
            TxOutput::Htlc(output_value, htlc) => {
                let address = Address::<Destination>::new(&chain_config, htlc.spend_key.clone())
                    .expect("Unable to encode destination");

                address_transactions.entry(address.clone()).or_default().insert(transaction_id);

                let token_decimals = match output_value {
                    OutputValue::Coin(_) | OutputValue::TokenV0(_) => None,
                    OutputValue::TokenV1(token_id, _) => {
                        Some(token_decimals(*token_id, &BTreeMap::new(), db_tx).await?.1)
                    }
                };

                let outpoint =
                    UtxoOutPoint::new(OutPointSourceId::Transaction(transaction_id), idx as u32);
                let utxo = Utxo::new(output.clone(), token_decimals, false);
                db_tx
                    .set_utxo_at_height(outpoint, utxo, address.as_str(), block_height)
                    .await
                    .expect("Unable to set utxo");
            }
            TxOutput::CreateOrder(order_data) => {
                if let Some(input0_outpoint) = inputs.iter().find_map(|input| input.utxo_outpoint())
                {
                    let amount_and_currency = |v: &OutputValue| match v {
                        OutputValue::Coin(amount) => (CoinOrTokenId::Coin, *amount),
                        OutputValue::TokenV1(id, amount) => (CoinOrTokenId::TokenId(*id), *amount),
                        OutputValue::TokenV0(_) => panic!("unsupported token"),
                    };

                    let (ask_currency, ask_balance) = amount_and_currency(order_data.ask());
                    let (give_currency, give_balance) = amount_and_currency(order_data.give());

                    let order = Order {
                        creation_block_height: block_height,
                        conclude_destination: order_data.conclude_key().clone(),
                        initially_asked: ask_balance,
                        initially_given: give_balance,
                        ask_balance,
                        ask_currency,
                        give_balance,
                        give_currency,
                        is_frozen: false,
                        next_nonce: AccountNonce::new(0),
                    };

                    db_tx
                        .set_order_at_height(make_order_id(input0_outpoint), &order, block_height)
                        .await
                        .expect("Unable to set delegation data");
                }
            }
        }
    }

    for address_transaction in address_transactions {
        db_tx
            .set_address_transactions_at_height(
                address_transaction.0.as_str(),
                address_transaction.1,
                block_height,
            )
            .await
            .map_err(|_| {
                ApiServerStorageError::LowLevelStorageError(
                    "Unable to set address transactions".to_string(),
                )
            })?;
    }

    Ok(())
}

async fn increase_statistic_amount<T: ApiServerStorageWrite>(
    db_tx: &mut T,
    statistic: CoinOrTokenStatistic,
    amount: &Amount,
    coin_or_token_id: CoinOrTokenId,
    block_height: BlockHeight,
) {
    let current_balance = db_tx
        .get_statistic(statistic, coin_or_token_id)
        .await
        .expect("Unable to get statistic")
        .unwrap_or(Amount::ZERO);

    let new_amount = current_balance.add(*amount).expect("Balance should not overflow");

    db_tx
        .set_statistic(statistic, coin_or_token_id, block_height, new_amount)
        .await
        .expect("Unable to update statistic")
}

async fn decrease_statistic_amount<T: ApiServerStorageWrite>(
    db_tx: &mut T,
    statistic: CoinOrTokenStatistic,
    amount: &Amount,
    coin_or_token_id: CoinOrTokenId,
    block_height: BlockHeight,
) {
    let current_balance = db_tx
        .get_statistic(statistic, coin_or_token_id)
        .await
        .expect("Unable to get statistic")
        .unwrap_or(Amount::ZERO);

    let new_amount = current_balance.sub(*amount).expect("Balance should not underflow");

    db_tx
        .set_statistic(statistic, coin_or_token_id, block_height, new_amount)
        .await
        .expect("Unable to update statistic")
}

async fn increase_address_amount<T: ApiServerStorageWrite>(
    db_tx: &mut T,
    address: &Address<Destination>,
    amount: &Amount,
    coin_or_token_id: CoinOrTokenId,
    block_height: BlockHeight,
) {
    let current_balance = db_tx
        .get_address_balance(address.as_str(), coin_or_token_id)
        .await
        .expect("Unable to get balance")
        .unwrap_or(Amount::ZERO);

    let new_amount = current_balance.add(*amount).expect("Balance should not overflow");

    db_tx
        .set_address_balance_at_height(address, new_amount, coin_or_token_id, block_height)
        .await
        .expect("Unable to update balance")
}

async fn increase_locked_address_amount<T: ApiServerStorageWrite>(
    db_tx: &mut T,
    address: &Address<Destination>,
    amount: &Amount,
    coin_or_token_id: CoinOrTokenId,
    block_height: BlockHeight,
) {
    let current_balance = db_tx
        .get_address_locked_balance(address.as_str(), coin_or_token_id)
        .await
        .expect("Unable to get balance")
        .unwrap_or(Amount::ZERO);

    let new_amount = current_balance.add(*amount).expect("Balance should not overflow");

    db_tx
        .set_address_locked_balance_at_height(address, new_amount, coin_or_token_id, block_height)
        .await
        .expect("Unable to update balance")
}

async fn decrease_address_amount<T: ApiServerStorageWrite>(
    db_tx: &mut T,
    address: Address<Destination>,
    amount: &Amount,
    coin_or_token_id: CoinOrTokenId,
    block_height: BlockHeight,
) {
    let current_balance = db_tx
        .get_address_balance(address.as_str(), coin_or_token_id)
        .await
        .expect("Unable to get balance")
        .unwrap_or(Amount::ZERO);

    let new_amount = current_balance.sub(*amount).unwrap_or_else(|| {
        panic!(
            "Balance should not overflow {:?} {:?} {:?}",
            coin_or_token_id, current_balance, *amount
        )
    });

    db_tx
        .set_address_balance_at_height(&address, new_amount, coin_or_token_id, block_height)
        .await
        .expect("Unable to update balance")
}

async fn decrease_address_locked_amount<T: ApiServerStorageWrite>(
    db_tx: &mut T,
    address: Address<Destination>,
    amount: &Amount,
    coin_or_token_id: CoinOrTokenId,
    block_height: BlockHeight,
) {
    let current_balance = db_tx
        .get_address_locked_balance(address.as_str(), coin_or_token_id)
        .await
        .expect("Unable to get balance")
        .unwrap_or(Amount::ZERO);

    let new_amount = current_balance.sub(*amount).unwrap_or_else(|| {
        panic!(
            "Balance should not overflow {:?} {:?} {:?}",
            coin_or_token_id, current_balance, *amount
        )
    });

    db_tx
        .set_address_locked_balance_at_height(&address, new_amount, coin_or_token_id, block_height)
        .await
        .expect("Unable to update balance")
}

async fn set_utxo<T: ApiServerStorageWrite>(
    outpoint: UtxoOutPoint,
    output: &TxOutput,
    token_decimals: Option<u8>,
    db_tx: &mut T,
    block_height: BlockHeight,
    spent: bool,
    chain_config: &ChainConfig,
) {
    let utxo = Utxo::new(output.clone(), token_decimals, spent);
    if let Some(destination) = get_tx_output_destination(output) {
        let address = Address::<Destination>::new(chain_config, destination.clone())
            .expect("Unable to encode destination");
        db_tx
            .set_utxo_at_height(outpoint, utxo, address.as_str(), block_height)
            .await
            .expect("Unable to set utxo");
    }
}

fn get_tx_output_destination(txo: &TxOutput) -> Option<&Destination> {
    match txo {
        TxOutput::Transfer(_, d)
        | TxOutput::LockThenTransfer(_, d, _)
        | TxOutput::CreateDelegationId(d, _)
        | TxOutput::IssueNft(_, _, d)
        | TxOutput::ProduceBlockFromStake(d, _) => Some(d),
        TxOutput::CreateStakePool(_, data) => Some(data.decommission_key()),
        TxOutput::Htlc(_, htlc) => Some(&htlc.spend_key),
        TxOutput::IssueFungibleToken(_)
        | TxOutput::Burn(_)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::DataDeposit(_)
        | TxOutput::CreateOrder(_) => None,
    }
}
