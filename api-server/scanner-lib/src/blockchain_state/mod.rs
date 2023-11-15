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
    block_aux_data::BlockAuxData, ApiServerStorage, ApiServerStorageError, ApiServerStorageRead,
    ApiServerStorageWrite, ApiServerTransactionRw,
};
use common::{
    address::Address,
    chain::{
        config::ChainConfig, output_value::OutputValue, transaction::OutPointSourceId, Block,
        Destination, GenBlock, Transaction, TxInput, TxOutput,
    },
    primitives::{id::WithId, Amount, BlockHeight, Id, Idable},
};
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
        let best_block = db_tx
            .get_best_block()
            .await
            .expect("Unable to get best block")
            .unwrap_or_else(|| (BlockHeight::new(0), self.chain_config.genesis_block_id()));
        Ok(best_block)
    }

    async fn scan_blocks(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
    ) -> Result<(), Self::Error> {
        let mut db_tx = self.storage.transaction_rw().await.expect("Unable to connect to database");

        // Disconnect blocks from main-chain
        db_tx
            .del_main_chain_blocks_above_height(common_block_height)
            .await
            .expect("Unable to disconnect block");

        // Disconnect address balances
        db_tx
            .del_address_balance_above_height(common_block_height)
            .await
            .expect("Unable to disconnect address balance");

        db_tx
            .del_address_transactions_above_height(common_block_height)
            .await
            .expect("Unable to disconnect address transactions");

        // Connect the new blocks in the new chain
        for (index, block) in blocks.into_iter().map(WithId::new).enumerate() {
            let block_height = BlockHeight::new(common_block_height.into_int() + index as u64 + 1);

            logging::log::info!("Connected block: ({}, {})", block_height, block.get_id());

            update_address_tables_from_outputs(
                Arc::clone(&self.chain_config),
                &mut db_tx,
                None,
                block_height,
                block.block_reward().outputs(),
            )
            .await
            .expect("Unable to update balances from block reward outputs");

            for tx in block.transactions() {
                db_tx
                    .set_transaction(tx.transaction().get_id(), Some(block.get_id()), tx)
                    .await
                    .expect("Unable to set transaction");

                update_address_tables_from_inputs(
                    Arc::clone(&self.chain_config),
                    &mut db_tx,
                    block_height,
                    tx.inputs(),
                )
                .await
                .expect("Unable to update balances from inputs");

                update_address_tables_from_outputs(
                    Arc::clone(&self.chain_config),
                    &mut db_tx,
                    Some(tx.transaction().get_id()),
                    block_height,
                    tx.outputs(),
                )
                .await
                .expect("Unable to update balances from transaction outputs");
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

async fn update_address_tables_from_inputs<T: ApiServerStorageWrite>(
    chain_config: Arc<ChainConfig>,
    db_tx: &mut T,
    block_height: BlockHeight,
    inputs: &[TxInput],
) -> Result<(), ApiServerStorageError> {
    let mut address_transactions: BTreeMap<Address<Destination>, BTreeSet<Id<Transaction>>> =
        BTreeMap::new();

    for input in inputs {
        match input {
            TxInput::Account(_) | TxInput::AccountCommand(_, _) => {
                // TODO
            }
            TxInput::Utxo(outpoint) => {
                match outpoint.source_id() {
                    OutPointSourceId::BlockReward(_block_id) => {
                        // TODO
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
                            | TxOutput::CreateStakePool(_, _)
                            | TxOutput::DataDeposit(_)
                            | TxOutput::DelegateStaking(_, _)
                            | TxOutput::IssueFungibleToken(_)
                            | TxOutput::IssueNft(_, _, _)
                            | TxOutput::ProduceBlockFromStake(_, _) => {}
                            TxOutput::LockThenTransfer(output_value, destination, _)
                            | TxOutput::Transfer(output_value, destination) => {
                                match destination {
                                    Destination::PublicKey(_) | Destination::Address(_) => {
                                        let address =
                                            Address::<Destination>::new(&chain_config, destination)
                                                .expect("Unable to encode destination");

                                        address_transactions
                                            .entry(address.clone())
                                            .or_default()
                                            .insert(transaction_id);

                                        match output_value {
                                            OutputValue::TokenV0(_)
                                            | OutputValue::TokenV1(_, _) => {
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
                                    Destination::AnyoneCanSpend
                                    | Destination::ClassicMultisig(_)
                                    | Destination::ScriptHash(_) => {}
                                }
                            }
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

async fn update_address_tables_from_outputs<T: ApiServerStorageWrite>(
    chain_config: Arc<ChainConfig>,
    db_tx: &mut T,
    transaction_id_maybe: Option<Id<Transaction>>,
    block_height: BlockHeight,
    outputs: &[TxOutput],
) -> Result<(), ApiServerStorageError> {
    let mut address_transactions: BTreeMap<Address<Destination>, BTreeSet<Id<Transaction>>> =
        BTreeMap::new();

    for output in outputs {
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
            | TxOutput::LockThenTransfer(output_value, destination, _) => {
                match destination {
                    Destination::PublicKey(_) | Destination::Address(_) => {
                        let address = Address::<Destination>::new(&chain_config, destination)
                            .expect("Unable to encode destination");

                        transaction_id_maybe.map(|transaction_id| {
                            address_transactions
                                .entry(address.clone())
                                .or_default()
                                .insert(transaction_id)
                        });

                        match output_value {
                            OutputValue::TokenV0(_) | OutputValue::TokenV1(_, _) => {
                                // TODO
                            }
                            OutputValue::Coin(amount) => {
                                let current_balance = db_tx
                                    .get_address_balance(address.get())
                                    .await
                                    .expect("Unable to get balance")
                                    .unwrap_or(Amount::ZERO);

                                let new_amount = current_balance
                                    .add(*amount)
                                    .expect("Balance should not overflow");

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
