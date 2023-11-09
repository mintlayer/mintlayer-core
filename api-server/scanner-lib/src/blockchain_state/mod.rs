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
    ApiServerStorageWrite, ApiServerTransactionRw, Delegation,
};
use common::{
    address::Address,
    chain::{
        block::ConsensusData, config::ChainConfig, output_value::OutputValue,
        transaction::OutPointSourceId, AccountSpending, Block, Destination, GenBlock,
        SignedTransaction, Transaction, TxInput, TxOutput,
    },
    primitives::{id::WithId, Amount, BlockHeight, Id, Idable},
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

    // TODO: cleanup pool data
    // TODO: cleanup delegations

    Ok(())
}

async fn update_tables_from_block<T: ApiServerStorageWrite>(
    chain_config: Arc<ChainConfig>,
    db_tx: &mut T,
    block_height: BlockHeight,
    block: &Block,
) -> Result<(), ApiServerStorageError> {
    update_tables_from_block_reward(Arc::clone(&chain_config), db_tx, block_height, block)
        .await
        .expect("Unable to update tables from block reward");

    update_tables_from_consensus_data(Arc::clone(&chain_config), db_tx, block_height, block)
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
                            let current_balance = db_tx
                                .get_address_balance(address.get())
                                .await
                                .expect("Unable to get balance")
                                .unwrap_or(Amount::ZERO);

                            let new_amount =
                                current_balance.add(*amount).expect("Balance should not overflow");

                            db_tx
                                .set_address_balance_at_height(
                                    address.get(),
                                    new_amount,
                                    block_height,
                                )
                                .await
                                .expect("Unable to update balance")
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

            // TODO: calculate fees like in connect_block_reward()
            let total_fees = Amount::ZERO;

            let total_reward =
                (block_subsidy + total_fees).expect("Block subsidy and fees should not overflow");

            let pool_data = db_tx
                .get_pool_data(*pos_data.stake_pool_id())
                .await
                .expect("Unable to get pool data")
                .expect("Pool should exist");

            let pool_owner_reward = match total_reward - pool_data.cost_per_block() {
                Some(reward) => (reward * pool_data.margin_ratio_per_thousand().value().into())
                    .and_then(|v| v / 1000)
                    .and_then(|v| v + pool_data.cost_per_block())
                    .expect("Pool owner reward should not overflow"),
                None => total_reward,
            };

            let _total_delgations_reward =
                (total_reward - pool_owner_reward).expect("Total reward should not underflow");

            // TODO: distribute reward to delegators
            // <-- distribute_pos_reward()

            // let delegation_shares = pool_delegations_shares(pool_id)
            // let total_delegations_balance = delegation_shares.sum()
            // if total_delegation_balance > 0 {
            //   let rewards_per_delegation = calculate_rewards_per_delegation(
            //     delegation_shares,
            //     pool_id,
            //     total_delegation_balance,
            //     total_delegation_reward,
            //   );
            //
            //   rewards_per_delegation.iter().for_each(|(delegation_id, reward)| {
            //     delegate_staking(delegation_id, reward)
            //   }
            //
            //   total_delegation_reward_distributed = rewards_per_delegation.sum()
            //
            //   unallocated_reward = total_delegations_reward - total_delegation_reward_distributed
            // } else {
            //   unallocated_reward = total_delegations_reward
            // }
            //
            // total_owner_reward = (pool_owner_reward + unallocated_reward)
            // increase_pool_pledge(pool_id, total_owner_reward)
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
            | TxInput::AccountCommand(_, _) => {}
            TxInput::Account(outpoint) => {
                match outpoint.account() {
                    AccountSpending::DelegationBalance(delegation_id, amount) => {
                        // Update delegation pledge

                        let delegation = db_tx
                            .get_delegation(*delegation_id)
                            .await
                            .expect("Unable to get delegation")
                            .expect("Delegation should exist");

                        let new_pledge_amount = delegation
                            .pledge_amount()
                            .sub(*amount)
                            .expect("Delegation pledge should not underflow");

                        db_tx
                            .set_delegation_at_height(
                                *delegation_id,
                                &Delegation::new(
                                    delegation.spend_destination().clone(),
                                    *delegation.pool_id(),
                                    new_pledge_amount,
                                ),
                                block_height,
                            )
                            .await
                            .expect("Unable to update delegation");

                        // Update pool pledge

                        let pool_id = delegation.pool_id();

                        let current_pool_data = db_tx
                            .get_pool_data(*pool_id)
                            .await
                            .expect("Unable to get pool data")
                            .filter(|c| c.pledge_amount() > Amount::ZERO);

                        if let Some(current_pool_data) = current_pool_data {
                            let new_pool_pledge = current_pool_data
                                .pledge_amount()
                                .sub(*amount)
                                .expect("Pool pledge should not underflow");

                            let new_pool_data = PoolData::new(
                                current_pool_data.decommission_destination().clone(),
                                new_pool_pledge,
                                current_pool_data.vrf_public_key().clone(),
                                current_pool_data.margin_ratio_per_thousand(),
                                current_pool_data.cost_per_block(),
                            );

                            db_tx
                                .set_pool_data_at_height(*pool_id, &new_pool_data, block_height)
                                .await
                                .expect("Unable to update pool data")
                        }
                    }
                }
            }
            TxInput::Utxo(outpoint) => {
                match outpoint.source_id() {
                    OutPointSourceId::BlockReward(_block_id) => {
                        // TODO: duplicate LockThenTransfer and Transfer when done
                        //       (opposite of update_tables_from_reward())
                    }
                    OutPointSourceId::Transaction(transaction_id) => {
                        let input_transaction = db_tx
                            .get_transaction(transaction_id)
                            .await?
                            .expect("Transaction should exist");

                        assert!(
                            input_transaction.1.transaction().outputs().len()
                                > outpoint.output_index() as usize
                        );

                        match &input_transaction.1.transaction().outputs()
                            [outpoint.output_index() as usize]
                        {
                            TxOutput::Burn(_)
                            | TxOutput::CreateDelegationId(_, _)
                            | TxOutput::DataDeposit(_)
                            | TxOutput::DelegateStaking(_, _)
                            | TxOutput::IssueFungibleToken(_)
                            | TxOutput::IssueNft(_, _, _) => {}
                            TxOutput::CreateStakePool(pool_id, _)
                            | TxOutput::ProduceBlockFromStake(_, pool_id) => {
                                let pool_data = db_tx
                                    .get_pool_data(*pool_id)
                                    .await
                                    .expect("Unable to get pool data")
                                    .expect("Pool should exist");

                                let zero_pool_data = PoolData::new(
                                    pool_data.decommission_destination().clone(),
                                    Amount::ZERO,
                                    pool_data.vrf_public_key().clone(),
                                    pool_data.margin_ratio_per_thousand(),
                                    pool_data.cost_per_block(),
                                );

                                db_tx
                                    .set_pool_data_at_height(
                                        *pool_id,
                                        &zero_pool_data,
                                        block_height,
                                    )
                                    .await
                                    .expect("Unable to update pool balance");
                            }
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
                                        OutputValue::TokenV0(_) => { /* ignore */ }
                                        OutputValue::TokenV1(_, _) => {
                                            // TODO
                                        }
                                        OutputValue::Coin(amount) => {
                                            let current_balance = db_tx
                                                .get_address_balance(address.get())
                                                .await
                                                .expect("Unable to get balance")
                                                .unwrap_or(Amount::ZERO);

                                            let new_amount = current_balance
                                                .sub(*amount)
                                                .expect("Balance should not underflow");

                                            db_tx
                                                .set_address_balance_at_height(
                                                    address.get(),
                                                    new_amount,
                                                    block_height,
                                                )
                                                .await
                                                .expect("Unable to update balance")
                                        }
                                    }
                                }
                            },
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

    for output in outputs {
        match output {
            TxOutput::Burn(_)
            | TxOutput::DataDeposit(_)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::ProduceBlockFromStake(_, _) => {}
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
                }
            }
            TxOutput::CreateStakePool(pool_id, stake_pool_data) => {
                // Subtract from staker's address balance

                let staker_address =
                    Address::<Destination>::new(&chain_config, stake_pool_data.staker())
                        .expect("Unable to encode staker");

                address_transactions
                    .entry(staker_address.clone())
                    .or_default()
                    .insert(transaction_id);

                let current_address_balance = db_tx
                    .get_address_balance(staker_address.get())
                    .await
                    .expect("Unable to get address balance")
                    .unwrap_or(Amount::ZERO);

                let new_address_balance = current_address_balance
                    .sub(stake_pool_data.value())
                    .expect("Address balance should not underflow");

                db_tx
                    .set_address_balance_at_height(
                        staker_address.get(),
                        new_address_balance,
                        block_height,
                    )
                    .await
                    .expect("Unable to update address balance");

                // Create pool pledge

                let current_pool_data = db_tx
                    .get_pool_data(*pool_id)
                    .await
                    .expect("Unable to get pool data")
                    .unwrap_or(PoolData::new(
                        stake_pool_data.decommission_key().clone(),
                        stake_pool_data.value(),
                        stake_pool_data.vrf_public_key().clone(),
                        stake_pool_data.margin_ratio_per_thousand(),
                        stake_pool_data.cost_per_block(),
                    ));

                let new_pool_pledge = current_pool_data
                    .pledge_amount()
                    .add(stake_pool_data.value())
                    .expect("Pool balance should not overflow");

                let new_pool_data = PoolData::new(
                    stake_pool_data.decommission_key().clone(),
                    new_pool_pledge,
                    stake_pool_data.vrf_public_key().clone(),
                    stake_pool_data.margin_ratio_per_thousand(),
                    stake_pool_data.cost_per_block(),
                );

                db_tx
                    .set_pool_data_at_height(*pool_id, &new_pool_data, block_height)
                    .await
                    .expect("Unable to update pool balance")
            }
            | TxOutput::DelegateStaking(amount, delegation_id) => {
                // Update delegation pledge

                let delegation = db_tx
                    .get_delegation(*delegation_id)
                    .await
                    .expect("Unable to get delegation")
                    .expect("Delegation should exist");

                let new_pledge_amount = delegation
                    .pledge_amount()
                    .add(*amount)
                    .expect("Delegation pledge should not overflow");

                db_tx
                    .set_delegation_at_height(
                        *delegation_id,
                        &Delegation::new(
                            delegation.spend_destination().clone(),
                            *delegation.pool_id(),
                            new_pledge_amount,
                        ),
                        block_height,
                    )
                    .await
                    .expect("Unable to update delegation");

                // Update pool pledge

                let pool_id = delegation.pool_id();

                let current_pool_data = db_tx
                    .get_pool_data(*pool_id)
                    .await
                    .expect("Unable to get pool data")
                    .expect("Pool should exist");

                let new_pool_pledge = current_pool_data
                    .pledge_amount()
                    .add(*amount)
                    .expect("Pool pledge should not overflow");

                let new_pool_data = PoolData::new(
                    current_pool_data.decommission_destination().clone(),
                    new_pool_pledge,
                    current_pool_data.vrf_public_key().clone(),
                    current_pool_data.margin_ratio_per_thousand(),
                    current_pool_data.cost_per_block(),
                );

                db_tx
                    .set_pool_data_at_height(*pool_id, &new_pool_data, block_height)
                    .await
                    .expect("Unable to update pool data");

                // TODO: address transaction history
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
                            let current_balance = db_tx
                                .get_address_balance(address.get())
                                .await
                                .expect("Unable to get balance")
                                .unwrap_or(Amount::ZERO);

                            let new_amount =
                                current_balance.add(*amount).expect("Balance should not overflow");

                            db_tx
                                .set_address_balance_at_height(
                                    address.get(),
                                    new_amount,
                                    block_height,
                                )
                                .await
                                .expect("Unable to update balance")
                        }
                    }
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
