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
    ApiServerTransactionRw, Delegation, FungibleTokenData, LockedUtxo, TransactionInfo,
    TxAdditionalInfo, Utxo, UtxoLock,
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
        output_value::OutputValue,
        tokens::{make_token_id, IsTokenFrozen, TokenIssuance},
        transaction::OutPointSourceId,
        AccountCommand, AccountNonce, AccountSpending, Block, DelegationId, Destination, GenBlock,
        Genesis, PoolId, SignedTransaction, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{id::WithId, Amount, BlockHeight, CoinOrTokenId, Fee, Id, Idable},
};
use futures::{stream::FuturesOrdered, TryStreamExt};
use pos_accounting::{make_delegation_id, PoSAccountingView, PoolData};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::{Add, Sub},
    sync::Arc,
};
use tx_verifier::transaction_verifier::{
    calculate_tokens_burned_in_outputs, distribute_pos_reward,
};

use self::adapter::PoSAdapter;

mod adapter;

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

            let (total_fees, tx_additional_infos) =
                calculate_fees(&self.chain_config, &mut db_tx, &block, block_height).await?;

            let block_id = block.get_id();

            let block_with_extras = BlockWithExtraData {
                block: WithId::take(block),
                tx_additional_infos,
            };
            db_tx
                .set_mainchain_block(block_id, block_height, &block_with_extras)
                .await
                .expect("Unable to set block");

            db_tx
                .set_block_aux_data(
                    block_id,
                    &BlockAuxData::new(block_id.into(), block_height, block_timestamp),
                )
                .await
                .expect("Unable to set block aux data");

            let BlockWithExtraData {
                block,
                tx_additional_infos,
            } = block_with_extras;

            for (tx, additinal_info) in block.transactions().iter().zip(tx_additional_infos.iter())
            {
                update_tables_from_transaction(
                    Arc::clone(&self.chain_config),
                    &mut db_tx,
                    block_height,
                    new_median_time,
                    tx,
                )
                .await
                .expect("Unable to update tables from transaction");

                let tx_info = TransactionInfo {
                    tx: tx.clone(),
                    additinal_info: additinal_info.clone(),
                };
                db_tx
                    .set_transaction(tx.transaction().get_id(), Some(block.get_id()), &tx_info)
                    .await
                    .expect("Unable to set transaction");
            }

            update_tables_from_block(
                Arc::clone(&self.chain_config),
                &mut db_tx,
                block_height,
                &block,
                total_fees,
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
        set_utxo(
            outpoint.source_id(),
            outpoint.output_index() as usize,
            &locked_utxo,
            db_tx,
            block_height,
            false,
            chain_config,
        )
        .await;

        match &locked_utxo {
            TxOutput::LockThenTransfer(outvalue, destination, _) => {
                let address = Address::<Destination>::new(chain_config, destination)
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
                            CoinOrTokenId::Coin,
                            block_height,
                        )
                        .await;
                    }
                }
            }
            _ => panic!("locked utxo not lock then transfer output"),
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
    db_tx
        .del_address_balance_above_height(block_height)
        .await
        .expect("Unable to disconnect address balance");

    db_tx
        .del_address_locked_balance_above_height(block_height)
        .await
        .expect("Unable to disconnect address balance");

    db_tx
        .del_address_transactions_above_height(block_height)
        .await
        .expect("Unable to disconnect address transactions");

    db_tx
        .del_utxo_above_height(block_height)
        .await
        .expect("Unable to disconnect UTXOs");

    db_tx
        .del_locked_utxo_above_height(block_height)
        .await
        .expect("Unable to disconnect locked UTXOs");

    db_tx
        .del_delegations_above_height(block_height)
        .await
        .expect("Unable to disconnect address transactions");

    db_tx
        .del_pools_above_height(block_height)
        .await
        .expect("Unable to disconnect pool data");

    db_tx
        .del_token_issuance_above_height(block_height)
        .await
        .expect("Unable to disconnect token issuances");

    db_tx
        .del_nft_issuance_above_height(block_height)
        .await
        .expect("Unable to disconnect nft issuances");

    db_tx
        .del_main_chain_blocks_above_height(block_height)
        .await
        .expect("Unable to disconnect block");

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
        match output {
            TxOutput::Burn(_)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DataDeposit(_)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _) => {}
            TxOutput::ProduceBlockFromStake(_, _) => {
                set_utxo(
                    OutPointSourceId::BlockReward(block_id),
                    idx,
                    output,
                    db_tx,
                    block_height,
                    false,
                    &chain_config,
                )
                .await;
            }
            TxOutput::CreateStakePool(pool_id, pool_data) => {
                let pool_data: PoolData = pool_data.as_ref().clone().into();

                db_tx
                    .set_pool_data_at_height(*pool_id, &pool_data, block_height)
                    .await
                    .expect("unable to update pool data");
                set_utxo(
                    OutPointSourceId::BlockReward(block_id),
                    idx,
                    output,
                    db_tx,
                    block_height,
                    false,
                    &chain_config,
                )
                .await;
            }
            TxOutput::Transfer(output_value, destination)
            | TxOutput::LockThenTransfer(output_value, destination, _) => match destination {
                Destination::PublicKey(_) | Destination::PublicKeyHash(_) => {
                    let address = Address::<Destination>::new(&chain_config, destination)
                        .expect("Unable to encode destination");
                    match output_value {
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
                        }
                    }
                    set_utxo(
                        OutPointSourceId::BlockReward(block_id),
                        idx,
                        output,
                        db_tx,
                        block_height,
                        false,
                        &chain_config,
                    )
                    .await;
                }
                Destination::AnyoneCanSpend => {
                    // for tests
                    set_utxo(
                        OutPointSourceId::BlockReward(block_id),
                        idx,
                        output,
                        db_tx,
                        block_height,
                        false,
                        &chain_config,
                    )
                    .await;
                }
                Destination::ClassicMultisig(_) | Destination::ScriptHash(_) => {}
            },
        }
    }

    Ok(())
}

async fn calculate_fees<T: ApiServerStorageWrite>(
    chain_config: &ChainConfig,
    db_tx: &mut T,
    block: &Block,
    block_height: BlockHeight,
) -> Result<(Fee, Vec<TxAdditionalInfo>), ApiServerStorageError> {
    let new_outputs: BTreeMap<_, _> = block
        .transactions()
        .iter()
        .flat_map(|tx| {
            tx.outputs().iter().enumerate().map(|(idx, out)| {
                (
                    UtxoOutPoint::new(
                        OutPointSourceId::Transaction(tx.transaction().get_id()),
                        idx as u32,
                    ),
                    out,
                )
            })
        })
        .collect();

    let mut total_fees = AccumulatedFee::new();
    let mut tx_aditional_infos = vec![];
    for tx in block.transactions().iter() {
        let fee = tx_fees(chain_config, block_height, tx, db_tx, &new_outputs).await?;
        total_fees = total_fees.combine(fee.clone()).expect("no overflow");

        let input_tasks: FuturesOrdered<_> =
            tx.inputs().iter().map(|input| fetch_utxo(input, &new_outputs, db_tx)).collect();
        let input_utxos: Vec<Option<TxOutput>> = input_tasks.try_collect().await?;

        let tx_info = TxAdditionalInfo {
            fee: fee.map_into_block_fees(chain_config, block_height).expect("no overflow").0,
            input_utxos,
        };
        tx_aditional_infos.push(tx_info);
    }
    let total_fees =
        total_fees.map_into_block_fees(chain_config, block_height).expect("no overflow");

    Ok((total_fees, tx_aditional_infos))
}

async fn fetch_utxo<T: ApiServerStorageRead>(
    input: &TxInput,
    new_outputs: &BTreeMap<UtxoOutPoint, &TxOutput>,
    db_tx: &T,
) -> Result<Option<TxOutput>, ApiServerStorageError> {
    match input {
        TxInput::Utxo(outpoint) => {
            let utxo = if let Some(utxo) = new_outputs.get(outpoint) {
                (*utxo).clone()
            } else {
                db_tx
                    .get_utxo(outpoint.clone())
                    .await?
                    .map(|utxo| utxo.into_output())
                    .expect("must be present")
            };
            Ok(Some(utxo))
        }
        TxInput::Account(_) | TxInput::AccountCommand(_, _) => Ok(None),
    }
}

async fn tx_fees<T: ApiServerStorageWrite>(
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    tx: &SignedTransaction,
    db_tx: &mut T,
    new_outputs: &BTreeMap<UtxoOutPoint, &TxOutput>,
) -> Result<AccumulatedFee, ApiServerStorageError> {
    let inputs_utxos = collect_inputs_utxos(db_tx, tx.inputs(), new_outputs).await?;
    let pools = prefetch_pool_amounts(&inputs_utxos, db_tx).await?;

    let staker_balance_getter = |pool_id: PoolId| Ok(pools.get(&pool_id).cloned());
    // only used for checks for attempted to print money but we don't need to check that here
    let delegation_balance_getter = |_delegation_id: DelegationId| Ok(Some(Amount::MAX));

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        chain_config,
        block_height,
        staker_balance_getter,
        delegation_balance_getter,
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

async fn prefetch_pool_amounts<T: ApiServerStorageWrite>(
    inputs_utxos: &Vec<Option<TxOutput>>,
    db_tx: &mut T,
) -> Result<BTreeMap<PoolId, Amount>, ApiServerStorageError> {
    let mut pools = BTreeMap::new();
    for output in inputs_utxos {
        match output {
            Some(
                TxOutput::CreateStakePool(pool_id, _) | TxOutput::ProduceBlockFromStake(_, pool_id),
            ) => {
                let amount = db_tx
                    .get_pool_data(*pool_id)
                    .await?
                    .expect("should exist")
                    .staker_balance()
                    .expect("no overflow");
                pools.insert(*pool_id, amount);
            }
            Some(
                TxOutput::Burn(_)
                | TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::DataDeposit(_)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _)
                | TxOutput::IssueNft(_, _, _)
                | TxOutput::IssueFungibleToken(_),
            ) => {}
            None => {}
        }
    }
    Ok(pools)
}

async fn collect_inputs_utxos<T: ApiServerStorageWrite>(
    db_tx: &mut T,
    inputs: &[TxInput],
    new_outputs: &BTreeMap<UtxoOutPoint, &TxOutput>,
) -> Result<Vec<Option<TxOutput>>, ApiServerStorageError> {
    let mut outputs = Vec::with_capacity(inputs.len());
    for input in inputs {
        let output = match input {
            TxInput::Utxo(outpoint) => {
                if let Some(output) = new_outputs.get(outpoint) {
                    Some((*output).clone())
                } else {
                    db_tx.get_utxo(outpoint.clone()).await?.map(|utxo| utxo.into_output())
                }
            }
            TxInput::Account(_) | TxInput::AccountCommand(_, _) => None,
        };

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
                            outpoint.source_id(),
                            outpoint.output_index() as usize,
                            utxo.output(),
                            db_tx,
                            block_height,
                            true,
                            &chain_config,
                        )
                        .await;
                    }
                    TxInput::Account(_) | TxInput::AccountCommand(_, _) => {}
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
            let mut adapter = PoSAdapter::new(pool_id, pool_data, &delegation_shares);

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

            for (delegation_id, rewards) in adapter.rewards_per_delegation() {
                let delegation = delegation_shares.get(delegation_id).expect("must exist").clone();
                let updated_delegation = delegation.stake(*rewards);
                db_tx
                    .set_delegation_at_height(*delegation_id, &updated_delegation, block_height)
                    .await?;
            }

            let pool_data = adapter.get_pool_data(pool_id).expect("no error").expect("must exist");
            db_tx.set_pool_data_at_height(pool_id, &pool_data, block_height).await?;
        }
    }

    Ok(())
}

async fn update_tables_from_transaction<T: ApiServerStorageWrite>(
    chain_config: Arc<ChainConfig>,
    db_tx: &mut T,
    block_height: BlockHeight,
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
        block_height,
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
                    db_tx.set_fungible_token_issuance(*token_id, block_height, issuance).await?;
                }
                AccountCommand::UnmintTokens(token_id) => {
                    let total_burned =
                        calculate_tokens_burned_in_outputs(tx, token_id).expect("no overflow");

                    let issuance =
                        db_tx.get_fungible_token_issuance(*token_id).await?.expect("must exist");

                    let issuance = issuance.unmint_tokens(total_burned);
                    db_tx.set_fungible_token_issuance(*token_id, block_height, issuance).await?;
                }
                AccountCommand::FreezeToken(token_id, is_unfreezable) => {
                    let issuance =
                        db_tx.get_fungible_token_issuance(*token_id).await?.expect("must exist");

                    let issuance = issuance.freeze(*is_unfreezable);
                    db_tx.set_fungible_token_issuance(*token_id, block_height, issuance).await?;
                }
                AccountCommand::UnfreezeToken(token_id) => {
                    let issuance =
                        db_tx.get_fungible_token_issuance(*token_id).await?.expect("must exist");

                    let issuance = issuance.unfreeze();
                    db_tx.set_fungible_token_issuance(*token_id, block_height, issuance).await?;
                }
                AccountCommand::LockTokenSupply(token_id) => {
                    let issuance =
                        db_tx.get_fungible_token_issuance(*token_id).await?.expect("must exist");

                    let issuance = issuance.lock();
                    db_tx.set_fungible_token_issuance(*token_id, block_height, issuance).await?;
                }
                AccountCommand::ChangeTokenAuthority(token_id, destination) => {
                    let issuance =
                        db_tx.get_fungible_token_issuance(*token_id).await?.expect("must exist");

                    let issuance = issuance.change_authority(destination.clone());
                    db_tx.set_fungible_token_issuance(*token_id, block_height, issuance).await?;
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
                    }
                }
            }
            TxInput::Utxo(outpoint) => match outpoint.source_id() {
                OutPointSourceId::BlockReward(_) => {
                    let utxo = db_tx.get_utxo(outpoint.clone()).await?.expect("must be present");
                    set_utxo(
                        outpoint.source_id(),
                        outpoint.output_index() as usize,
                        utxo.output(),
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
                        | TxOutput::IssueFungibleToken(_) => {}
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
                                pool_data.decommission_destination(),
                            )
                            .expect("Unable to encode destination");

                            address_transactions
                                .entry(address.clone())
                                .or_default()
                                .insert(tx.get_id());
                        }
                    }
                }
                OutPointSourceId::Transaction(_) => {
                    let utxo = db_tx.get_utxo(outpoint.clone()).await?.expect("must be present");
                    set_utxo(
                        outpoint.source_id(),
                        outpoint.output_index() as usize,
                        utxo.output(),
                        db_tx,
                        block_height,
                        true,
                        &chain_config,
                    )
                    .await;

                    match utxo.into_output() {
                        TxOutput::CreateDelegationId(_, _)
                        | TxOutput::DelegateStaking(_, _)
                        | TxOutput::Burn(_)
                        | TxOutput::DataDeposit(_)
                        | TxOutput::IssueFungibleToken(_)
                        | TxOutput::CreateStakePool(_, _)
                        | TxOutput::ProduceBlockFromStake(_, _) => {}
                        TxOutput::IssueNft(token_id, _, destination) => match destination {
                            Destination::AnyoneCanSpend
                            | Destination::ClassicMultisig(_)
                            | Destination::ScriptHash(_) => {}
                            Destination::PublicKey(_) | Destination::PublicKeyHash(_) => {
                                let address =
                                    Address::<Destination>::new(&chain_config, &destination)
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
                        },
                        TxOutput::LockThenTransfer(output_value, destination, _)
                        | TxOutput::Transfer(output_value, destination) => match destination {
                            Destination::AnyoneCanSpend
                            | Destination::ClassicMultisig(_)
                            | Destination::ScriptHash(_) => {}
                            Destination::PublicKey(_) | Destination::PublicKeyHash(_) => {
                                let address =
                                    Address::<Destination>::new(&chain_config, &destination)
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
                        },
                    }
                }
            },
        }
    }

    for address_transaction in address_transactions {
        db_tx
            .set_address_transactions_at_height(
                address_transaction.0.get(),
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
    block_height: BlockHeight,
    median_time: BlockTimestamp,
    transaction_id: Id<Transaction>,
    inputs: &[TxInput],
    outputs: &[TxOutput],
) -> Result<(), ApiServerStorageError> {
    let mut address_transactions: BTreeMap<Address<Destination>, BTreeSet<Id<Transaction>>> =
        BTreeMap::new();

    for (idx, output) in outputs.iter().enumerate() {
        match output {
            TxOutput::Burn(_) | TxOutput::DataDeposit(_) => {}
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
            }
            TxOutput::IssueNft(token_id, issuance, _) => {
                db_tx.set_nft_token_issuance(*token_id, block_height, *issuance.clone()).await?;
                set_utxo(
                    OutPointSourceId::Transaction(transaction_id),
                    idx,
                    output,
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
                let new_pool_data: PoolData = stake_pool_data.as_ref().clone().into();

                db_tx
                    .set_pool_data_at_height(*pool_id, &new_pool_data, block_height)
                    .await
                    .expect("Unable to update pool balance");
                set_utxo(
                    OutPointSourceId::Transaction(transaction_id),
                    idx,
                    output,
                    db_tx,
                    block_height,
                    false,
                    &chain_config,
                )
                .await;
                let address =
                    Address::<Destination>::new(&chain_config, stake_pool_data.decommission_key())
                        .expect("Unable to encode address");
                address_transactions.entry(address.clone()).or_default().insert(transaction_id);

                let staker_address =
                    Address::<Destination>::new(&chain_config, stake_pool_data.staker())
                        .expect("Unable to encode address");
                address_transactions.entry(staker_address).or_default().insert(transaction_id);
            }
            | TxOutput::DelegateStaking(amount, delegation_id) => {
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

                let address =
                    Address::<Destination>::new(&chain_config, new_delegation.spend_destination())
                        .expect("Unable to encode address");
                address_transactions.entry(address.clone()).or_default().insert(transaction_id);
            }
            TxOutput::Transfer(output_value, destination) => match destination {
                Destination::PublicKey(_) | Destination::PublicKeyHash(_) => {
                    let address = Address::<Destination>::new(&chain_config, destination)
                        .expect("Unable to encode destination");

                    address_transactions.entry(address.clone()).or_default().insert(transaction_id);

                    match output_value {
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
                        }
                    }
                    set_utxo(
                        OutPointSourceId::Transaction(transaction_id),
                        idx,
                        output,
                        db_tx,
                        block_height,
                        false,
                        &chain_config,
                    )
                    .await;
                }
                Destination::AnyoneCanSpend => {
                    // for tests
                    set_utxo(
                        OutPointSourceId::Transaction(transaction_id),
                        idx,
                        output,
                        db_tx,
                        block_height,
                        false,
                        &chain_config,
                    )
                    .await;
                }
                Destination::ClassicMultisig(_) | Destination::ScriptHash(_) => {}
            },
            TxOutput::LockThenTransfer(output_value, destination, lock) => {
                let address = Address::<Destination>::new(&chain_config, destination)
                    .expect("Unable to encode destination");

                address_transactions.entry(address.clone()).or_default().insert(transaction_id);
                let outpoint =
                    UtxoOutPoint::new(OutPointSourceId::Transaction(transaction_id), idx as u32);

                let already_unlocked = tx_verifier::timelock_check::check_timelock(
                    &block_height,
                    &median_time,
                    lock,
                    &block_height,
                    &median_time,
                    &outpoint,
                )
                .is_ok();

                if already_unlocked {
                    let utxo = Utxo::new(output.clone(), false);
                    db_tx
                        .set_utxo_at_height(outpoint, utxo, address.get(), block_height)
                        .await
                        .expect("Unable to set utxo");
                } else {
                    let lock = UtxoLock::from_output_lock(*lock, median_time, block_height);
                    let utxo = LockedUtxo::new(output.clone(), lock);
                    db_tx
                        .set_locked_utxo_at_height(outpoint, utxo, address.get(), block_height)
                        .await
                        .expect("Unable to set locked utxo");
                }

                match output_value {
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
                    }
                    OutputValue::TokenV0(_) => {}
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
                    }
                }
            }
        }
    }

    for address_transaction in address_transactions {
        db_tx
            .set_address_transactions_at_height(
                address_transaction.0.get(),
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

async fn increase_address_amount<T: ApiServerStorageWrite>(
    db_tx: &mut T,
    address: &Address<Destination>,
    amount: &Amount,
    coin_or_token_id: CoinOrTokenId,
    block_height: BlockHeight,
) {
    let current_balance = db_tx
        .get_address_balance(address.get(), coin_or_token_id)
        .await
        .expect("Unable to get balance")
        .unwrap_or(Amount::ZERO);

    let new_amount = current_balance.add(*amount).expect("Balance should not overflow");

    db_tx
        .set_address_balance_at_height(address.get(), new_amount, coin_or_token_id, block_height)
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
        .get_address_locked_balance(address.get(), coin_or_token_id)
        .await
        .expect("Unable to get balance")
        .unwrap_or(Amount::ZERO);

    let new_amount = current_balance.add(*amount).expect("Balance should not overflow");

    db_tx
        .set_address_locked_balance_at_height(
            address.get(),
            new_amount,
            coin_or_token_id,
            block_height,
        )
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
        .get_address_balance(address.get(), coin_or_token_id)
        .await
        .expect("Unable to get balance")
        .unwrap_or(Amount::ZERO);

    let new_amount = current_balance.sub(*amount).expect("Balance should not overflow");

    db_tx
        .set_address_balance_at_height(address.get(), new_amount, coin_or_token_id, block_height)
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
        .get_address_locked_balance(address.get(), coin_or_token_id)
        .await
        .expect("Unable to get balance")
        .unwrap_or(Amount::ZERO);

    let new_amount = current_balance.sub(*amount).expect("Balance should not overflow");

    db_tx
        .set_address_locked_balance_at_height(
            address.get(),
            new_amount,
            coin_or_token_id,
            block_height,
        )
        .await
        .expect("Unable to update balance")
}

async fn set_utxo<T: ApiServerStorageWrite>(
    outpoint_source_id: OutPointSourceId,
    idx: usize,
    output: &TxOutput,
    db_tx: &mut T,
    block_height: BlockHeight,
    spent: bool,
    chain_config: &ChainConfig,
) {
    let outpoint = UtxoOutPoint::new(outpoint_source_id, idx as u32);
    let utxo = Utxo::new(output.clone(), spent);
    if let Some(destination) = get_tx_output_destination(output) {
        let address = Address::<Destination>::new(chain_config, destination)
            .expect("Unable to encode destination");
        db_tx
            .set_utxo_at_height(outpoint, utxo, address.get(), block_height)
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
        TxOutput::IssueFungibleToken(_)
        | TxOutput::Burn(_)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::DataDeposit(_) => None,
    }
}
