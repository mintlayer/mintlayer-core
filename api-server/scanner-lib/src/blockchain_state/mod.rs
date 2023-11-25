// Copyright (c) 2023 RBB S.r.l opensource@mintlayer.org
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
    block_aux_data::BlockAuxData, ApiServerStorage, ApiServerStorageError, ApiServerStorageRead,
    ApiServerStorageWrite, ApiServerTransactionRw, Delegation, Utxo,
};
use chainstate::{
    constraints_value_accumulator::{AccumulatedFee, ConstrainedValueAccumulator},
    tx_verifier::transaction_verifier::{
        calculate_pool_owner_reward, calculate_rewards_per_delegation,
    },
};
use common::{
    address::Address,
    chain::{
        block::ConsensusData, config::ChainConfig, output_value::OutputValue,
        transaction::OutPointSourceId, AccountSpending, Block, DelegationId, Destination, GenBlock,
        GenBlockId, PoolId, SignedTransaction, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{id::WithId, Amount, BlockHeight, Fee, Id, Idable},
};
use pos_accounting::{make_delegation_id, PoolData};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::{Add, Sub},
    sync::Arc,
};

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
}

#[async_trait::async_trait]
impl<S: ApiServerStorage + Send + Sync> LocalBlockchainState for BlockchainState<S> {
    type Error = BlockchainStateError;

    async fn best_block(&self) -> Result<(BlockHeight, Id<GenBlock>), Self::Error> {
        let db_tx = self.storage.transaction_ro().await.expect("Unable to connect to database");
        let best_block = db_tx.get_best_block().await.expect("Unable to get best block");
        Ok(best_block)
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

            logging::log::info!("Connected block: ({}, {})", block_height, block.get_id());

            update_tables_from_block(
                Arc::clone(&self.chain_config),
                &mut db_tx,
                block_height,
                &block,
            )
            .await
            .expect("Unable to update tables from block");

            for tx in block.transactions() {
                db_tx
                    .set_transaction(tx.transaction().get_id(), Some(block.get_id()), tx)
                    .await
                    .expect("Unable to set transaction");

                update_tables_from_transaction(
                    Arc::clone(&self.chain_config),
                    &mut db_tx,
                    block_height,
                    tx,
                )
                .await
                .expect("Unable to update tables from transaction");
            }

            let block_id = block.get_id();
            db_tx
                .set_mainchain_block(block_id, block_height, &block)
                .await
                .expect("Unable to set block");
            db_tx
                .set_block_aux_data(
                    block_id,
                    &BlockAuxData::new(block_id, block_height, block.timestamp()),
                )
                .await
                .expect("Unable to set block aux data");
        }

        db_tx.commit().await.expect("Unable to commit transaction");
        logging::log::info!("Database commit completed successfully");

        Ok(())
    }
}

async fn disconnect_tables_above_height<T: ApiServerStorageWrite>(
    db_tx: &mut T,
    block_height: BlockHeight,
) -> Result<(), ApiServerStorageError> {
    if db_tx.get_best_block().await.expect("Unable to get best block").0 > block_height {
        logging::log::info!("Disconnecting blocks above: {:?}", block_height);
        db_tx
            .del_main_chain_blocks_above_height(block_height)
            .await
            .expect("Unable to disconnect block");
    }

    db_tx
        .del_address_balance_above_height(block_height)
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
        .del_delegations_above_height(block_height)
        .await
        .expect("Unable to disconnect address transactions");

    db_tx
        .del_pools_above_height(block_height)
        .await
        .expect("Unable to disconnect address transactions");

    Ok(())
}

async fn update_tables_from_block<T: ApiServerStorageWrite>(
    chain_config: Arc<ChainConfig>,
    db_tx: &mut T,
    block_height: BlockHeight,
    block: &Block,
) -> Result<(), ApiServerStorageError> {
    update_tables_from_block_reward(chain_config.clone(), db_tx, block_height, block)
        .await
        .expect("Unable to update tables from block reward");

    update_tables_from_consensus_data(chain_config.clone(), db_tx, block_height, block)
        .await
        .expect("Unable to update tables from consensus data");

    Ok(())
}

async fn update_tables_from_block_reward<T: ApiServerStorageWrite>(
    chain_config: Arc<ChainConfig>,
    db_tx: &mut T,
    block_height: BlockHeight,
    block: &Block,
) -> Result<(), ApiServerStorageError> {
    for output in block.block_reward().outputs().iter() {
        match output {
            TxOutput::Burn(_)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::CreateStakePool(_, _)
            | TxOutput::DataDeposit(_)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::ProduceBlockFromStake(_, _) => {}
            TxOutput::Transfer(output_value, destination)
            | TxOutput::LockThenTransfer(output_value, destination, _) => match destination {
                Destination::PublicKey(_) | Destination::Address(_) => {
                    let address = Address::<Destination>::new(&chain_config, destination)
                        .expect("Unable to encode destination");

                    match output_value {
                        OutputValue::TokenV0(_) | OutputValue::TokenV1(_, _) => {}
                        OutputValue::Coin(amount) => {
                            increase_address_amount(db_tx, &address, amount, block_height).await;
                        }
                    }
                }
                Destination::AnyoneCanSpend
                | Destination::ClassicMultisig(_)
                | Destination::ScriptHash(_) => {}
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
) -> Result<Fee, ApiServerStorageError> {
    let mut total_fees = AccumulatedFee::new();
    for tx in block.transactions() {
        let fee = tx_fees(chain_config, block_height, tx, db_tx).await?;
        total_fees = total_fees.combine(fee).expect("no overflow");
    }

    Ok(total_fees.map_into_block_fees(chain_config, block_height).expect("no overflow"))
}

async fn tx_fees<T: ApiServerStorageWrite>(
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    tx: &SignedTransaction,
    db_tx: &mut T,
) -> Result<AccumulatedFee, ApiServerStorageError> {
    let inputs_utxos = collect_inputs_utxos(db_tx, tx.inputs()).await?;

    let pools = prefetch_pool_amounts(&inputs_utxos, db_tx).await?;

    let pledge_getter = |pool_id: PoolId| Ok(pools.get(&pool_id).cloned());
    // only used for checks for attempted to print money but we don't need to check that here
    let delegation_balance_getter = |_delegation_id: DelegationId| Ok(Some(Amount::MAX));

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        chain_config,
        block_height,
        pledge_getter,
        delegation_balance_getter,
        tx.inputs(),
        &inputs_utxos,
    )
    .expect("valid block");
    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(chain_config, tx.outputs()).expect("valid block");
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
                let amount =
                    db_tx.get_pool_data(*pool_id).await?.expect("should exist").pledge_amount();
                pools.insert(*pool_id, amount);
            }
            Some(
                TxOutput::Burn(_)
                | TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::DataDeposit(_)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _),
            ) => {}
            Some(TxOutput::IssueNft(_, _, _) | TxOutput::IssueFungibleToken(_)) => {
                //TODO: add when we support tokens
            }
            None => {}
        }
    }
    Ok(pools)
}

async fn collect_inputs_utxos<T: ApiServerStorageWrite>(
    db_tx: &mut T,
    inputs: &[TxInput],
) -> Result<Vec<Option<TxOutput>>, ApiServerStorageError> {
    let mut outputs = Vec::with_capacity(inputs.len());
    for input in inputs {
        let output = match input {
            TxInput::Utxo(outpoint) => {
                db_tx.get_utxo(outpoint.clone()).await?.map(|utxo| utxo.into_output())
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
) -> Result<(), ApiServerStorageError> {
    match block.consensus_data() {
        ConsensusData::None | ConsensusData::PoW(_) => {}
        ConsensusData::PoS(pos_data) => {
            let block_subsidy = chain_config.as_ref().block_subsidy_at_height(&block_height);

            let total_fees = calculate_fees(&chain_config, db_tx, block, block_height).await?;

            let total_reward =
                (block_subsidy + total_fees.0).expect("Block subsidy and fees should not overflow");

            let pool_id = *pos_data.stake_pool_id();
            let pool_data = db_tx
                .get_pool_data(pool_id)
                .await
                .expect("Unable to get pool data")
                .expect("Pool should exist");

            let pool_owner_reward = calculate_pool_owner_reward(
                total_reward,
                pool_data.cost_per_block(),
                pool_data.margin_ratio_per_thousand(),
            )
            .expect("Pool owner reward should not overflow");

            let total_delegations_reward =
                (total_reward - pool_owner_reward).expect("Total reward should not underflow");

            let delegation_shares = db_tx.get_pool_delegations(pool_id).await?;
            let total_delegation_balance: Amount = delegation_shares
                .values()
                .map(|delegation| *delegation.balance())
                .sum::<Option<Amount>>()
                .expect("no overflow");

            let unallocated_reward = if total_delegation_balance > Amount::ZERO {
                let rewards_per_delegation = calculate_rewards_per_delegation(
                    delegation_shares
                        .iter()
                        .map(|(delegation_id, delegation)| (delegation_id, delegation.balance())),
                    pool_id,
                    total_delegation_balance,
                    total_delegations_reward,
                )
                .expect("no overflow");

                let total_delegation_reward_distributed = rewards_per_delegation
                    .iter()
                    .map(|(_, rewards)| *rewards)
                    .sum::<Option<Amount>>()
                    .expect("no overflow");

                for (delegation_id, rewards) in rewards_per_delegation {
                    let delegation = delegation_shares.get(&delegation_id).expect("must exist");
                    let delegation = delegation.add_pledge(rewards);
                    db_tx
                        .set_delegation_at_height(delegation_id, &delegation, block_height)
                        .await?;
                    let address =
                        Address::<Destination>::new(&chain_config, delegation.spend_destination())
                            .expect("Unable to encode address");
                    increase_address_amount(db_tx, &address, &rewards, block_height).await;
                }

                (total_delegations_reward - total_delegation_reward_distributed)
                    .expect("no underflow")
            } else {
                total_delegations_reward
            };

            let total_owner_reward = (pool_owner_reward + unallocated_reward).expect("no overflow");
            let pool_data = PoolData::new(
                pool_data.decommission_destination().clone(),
                (pool_data.pledge_amount() + total_owner_reward).expect("no overflow"),
                pool_data.vrf_public_key().clone(),
                pool_data.margin_ratio_per_thousand(),
                pool_data.cost_per_block(),
            );
            db_tx.set_pool_data_at_height(pool_id, &pool_data, block_height).await?;
        }
    }

    Ok(())
}

async fn update_tables_from_transaction<T: ApiServerStorageWrite>(
    chain_config: Arc<ChainConfig>,
    db_tx: &mut T,
    block_height: BlockHeight,
    transaction: &SignedTransaction,
) -> Result<(), ApiServerStorageError> {
    update_tables_from_transaction_inputs(
        Arc::clone(&chain_config),
        db_tx,
        block_height,
        transaction.transaction().inputs(),
        transaction.transaction().get_id(),
    )
    .await
    .expect("Unable to update tables from transaction inputs");

    update_tables_from_transaction_outputs(
        Arc::clone(&chain_config),
        db_tx,
        block_height,
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
    tx_id: Id<Transaction>,
) -> Result<(), ApiServerStorageError> {
    let mut address_transactions: BTreeMap<Address<Destination>, BTreeSet<Id<Transaction>>> =
        BTreeMap::new();

    for input in inputs {
        match input {
            // TODO: update token states
            | TxInput::AccountCommand(_, _) => {}
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

                        let new_delegation = delegation.sub_pledge(*amount);

                        db_tx
                            .set_delegation_at_height(*delegation_id, &new_delegation, block_height)
                            .await
                            .expect("Unable to update delegation");
                        let address = Address::<Destination>::new(
                            &chain_config,
                            delegation.spend_destination(),
                        )
                        .expect("Unable to encode address");
                        decrease_address_amount(db_tx, address, amount, block_height).await;
                    }
                }
            }
            TxInput::Utxo(outpoint) => match outpoint.source_id() {
                OutPointSourceId::BlockReward(block_id) => {
                    let utxo = match block_id.classify(&chain_config) {
                        GenBlockId::Genesis(_) => chain_config.genesis_block().utxos()
                            [outpoint.output_index() as usize]
                            .clone(),
                        GenBlockId::Block(block_id) => db_tx
                            .get_block(block_id)
                            .await?
                            .expect("cannot find block")
                            .block_reward()
                            .outputs()[outpoint.output_index() as usize]
                            .clone(),
                    };

                    set_utxo(
                        outpoint.source_id(),
                        outpoint.output_index() as usize,
                        &utxo,
                        db_tx,
                        block_height,
                        true,
                        &chain_config,
                    )
                    .await;

                    match utxo {
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
                        }
                    }
                }
                OutPointSourceId::Transaction(transaction_id) => {
                    let input_transaction = db_tx
                        .get_transaction(transaction_id)
                        .await?
                        .expect("Transaction should exist")
                        .1;

                    let output = &input_transaction.transaction().outputs()
                        [outpoint.output_index() as usize];

                    set_utxo(
                        outpoint.source_id(),
                        outpoint.output_index() as usize,
                        output,
                        db_tx,
                        block_height,
                        true,
                        &chain_config,
                    )
                    .await;

                    match output {
                        TxOutput::CreateDelegationId(_, _)
                        | TxOutput::DelegateStaking(_, _)
                        | TxOutput::Burn(_)
                        | TxOutput::DataDeposit(_)
                        | TxOutput::IssueFungibleToken(_)
                        | TxOutput::CreateStakePool(_, _)
                        | TxOutput::ProduceBlockFromStake(_, _) => {}
                        TxOutput::IssueNft(_, _, destination) => match destination {
                            Destination::AnyoneCanSpend
                            | Destination::ClassicMultisig(_)
                            | Destination::ScriptHash(_) => {}
                            Destination::PublicKey(_) | Destination::Address(_) => {
                                let address =
                                    Address::<Destination>::new(&chain_config, destination)
                                        .expect("Unable to encode destination");

                                address_transactions
                                    .entry(address.clone())
                                    .or_default()
                                    .insert(tx_id);

                                // TODO: update nft/token balance for address
                            }
                        },
                        TxOutput::LockThenTransfer(output_value, destination, _)
                        | TxOutput::Transfer(output_value, destination) => match destination {
                            Destination::AnyoneCanSpend
                            | Destination::ClassicMultisig(_)
                            | Destination::ScriptHash(_) => {}
                            Destination::PublicKey(_) | Destination::Address(_) => {
                                let address =
                                    Address::<Destination>::new(&chain_config, destination)
                                        .expect("Unable to encode destination");

                                address_transactions
                                    .entry(address.clone())
                                    .or_default()
                                    .insert(tx_id);

                                match output_value {
                                    OutputValue::TokenV0(_) | OutputValue::TokenV1(_, _) => {}
                                    OutputValue::Coin(amount) => {
                                        decrease_address_amount(
                                            db_tx,
                                            address,
                                            amount,
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
    transaction_id: Id<Transaction>,
    inputs: &[TxInput],
    outputs: &[TxOutput],
) -> Result<(), ApiServerStorageError> {
    let mut address_transactions: BTreeMap<Address<Destination>, BTreeSet<Id<Transaction>>> =
        BTreeMap::new();

    for (idx, output) in outputs.iter().enumerate() {
        match output {
            TxOutput::Burn(_) | TxOutput::DataDeposit(_) | TxOutput::IssueFungibleToken(_) => {}
            TxOutput::ProduceBlockFromStake(_, _) | TxOutput::IssueNft(_, _, _) => {
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
            TxOutput::CreateDelegationId(destination, pool_id) => {
                if let Some(input0_outpoint) = inputs.iter().find_map(|input| input.utxo_outpoint())
                {
                    db_tx
                        .set_delegation_at_height(
                            make_delegation_id(input0_outpoint),
                            &Delegation::new(destination.clone(), *pool_id, Amount::ZERO),
                            block_height,
                        )
                        .await
                        .expect("Unable to set delegation data");
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
            }
            TxOutput::CreateStakePool(pool_id, stake_pool_data) => {
                // Create pool pledge

                let new_pool_data = PoolData::new(
                    stake_pool_data.decommission_key().clone(),
                    stake_pool_data.value(),
                    stake_pool_data.vrf_public_key().clone(),
                    stake_pool_data.margin_ratio_per_thousand(),
                    stake_pool_data.cost_per_block(),
                );

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
                increase_address_amount(db_tx, &address, &stake_pool_data.value(), block_height)
                    .await;
            }
            | TxOutput::DelegateStaking(amount, delegation_id) => {
                // Update delegation pledge

                let delegation = db_tx
                    .get_delegation(*delegation_id)
                    .await
                    .expect("Unable to get delegation")
                    .expect("Delegation should exist");

                let new_delegation = delegation.add_pledge(*amount);

                db_tx
                    .set_delegation_at_height(*delegation_id, &new_delegation, block_height)
                    .await
                    .expect("Unable to update delegation");

                let address =
                    Address::<Destination>::new(&chain_config, new_delegation.spend_destination())
                        .expect("Unable to encode address");
                increase_address_amount(db_tx, &address, amount, block_height).await;

                address_transactions.entry(address.clone()).or_default().insert(transaction_id);

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
            TxOutput::Transfer(output_value, destination)
            | TxOutput::LockThenTransfer(output_value, destination, _) => match destination {
                Destination::PublicKey(_) | Destination::Address(_) => {
                    let address = Address::<Destination>::new(&chain_config, destination)
                        .expect("Unable to encode destination");

                    address_transactions.entry(address.clone()).or_default().insert(transaction_id);

                    match output_value {
                        OutputValue::TokenV0(_) | OutputValue::TokenV1(_, _) => {}
                        OutputValue::Coin(amount) => {
                            increase_address_amount(db_tx, &address, amount, block_height).await;
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
                Destination::AnyoneCanSpend
                | Destination::ClassicMultisig(_)
                | Destination::ScriptHash(_) => {}
            },
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
    block_height: BlockHeight,
) {
    let current_balance = db_tx
        .get_address_balance(address.get())
        .await
        .expect("Unable to get balance")
        .unwrap_or(Amount::ZERO);

    let new_amount = current_balance.add(*amount).expect("Balance should not overflow");

    db_tx
        .set_address_balance_at_height(address.get(), new_amount, block_height)
        .await
        .expect("Unable to update balance")
}

async fn decrease_address_amount<T: ApiServerStorageWrite>(
    db_tx: &mut T,
    address: Address<Destination>,
    amount: &Amount,
    block_height: BlockHeight,
) {
    let current_balance = db_tx
        .get_address_balance(address.get())
        .await
        .expect("Unable to get balance")
        .unwrap_or(Amount::ZERO);

    let new_amount = current_balance.sub(*amount).expect("Balance should not overflow");

    db_tx
        .set_address_balance_at_height(address.get(), new_amount, block_height)
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
        TxOutput::CreateStakePool(_, data) => Some(data.staker()),
        TxOutput::IssueFungibleToken(_)
        | TxOutput::Burn(_)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::DataDeposit(_) => None,
    }
}
