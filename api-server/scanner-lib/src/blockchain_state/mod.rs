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
    ApiServerStorage, ApiServerStorageError, ApiServerStorageRead, ApiServerStorageWrite,
    ApiServerTransactionRw,
};
use common::{
    chain::{
        output_value::OutputValue, transaction::OutPointSourceId, Block, GenBlock, TxInput,
        TxOutput,
    },
    primitives::{id::WithId, BlockHeight, Id, Idable},
};
use std::ops::{Add, Sub};

#[derive(Debug, thiserror::Error)]
pub enum BlockchainStateError {
    #[error("Unexpected storage error: {0}")]
    StorageError(#[from] ApiServerStorageError),
}

pub struct BlockchainState<S: ApiServerStorage> {
    storage: S,
}

impl<S: ApiServerStorage> BlockchainState<S> {
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }
}

#[async_trait::async_trait]
impl<S: ApiServerStorage + Send + Sync> LocalBlockchainState for BlockchainState<S> {
    type Error = BlockchainStateError;

    async fn best_block(&self) -> Result<(BlockHeight, Id<GenBlock>), Self::Error> {
        let db_tx = self.storage.transaction_ro().await?;
        let best_block = db_tx.get_best_block().await?;
        Ok(best_block)
    }

    async fn scan_blocks(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
    ) -> Result<(), Self::Error> {
        let mut db_tx = self.storage.transaction_rw().await?;

        // Disconnect blocks from main-chain
        while db_tx.get_best_block().await?.0 > common_block_height {
            let current_best = db_tx.get_best_block().await?;
            logging::log::info!("Disconnecting block: {:?}", current_best);
            db_tx.del_main_chain_block_id(current_best.0).await?;
        }

        // Disconnect address balances
        db_tx.del_address_balance_above_height(common_block_height).await?;
        // TODO delete token balances

        // Connect the new blocks in the new chain
        for (index, block) in blocks.into_iter().map(WithId::new).enumerate() {
            let block_height = BlockHeight::new(common_block_height.into_int() + index as u64 + 1);

            db_tx.set_main_chain_block_id(block_height, block.get_id()).await?;
            logging::log::info!("Connected block: ({}, {})", block_height, block.get_id());

            update_balances_from_outputs(&mut db_tx, block_height, block.block_reward().outputs())
                .await?;

            for tx in block.transactions() {
                db_tx
                    .set_transaction(tx.transaction().get_id(), Some(block.get_id()), tx)
                    .await?;

                update_balances_from_inputs(&mut db_tx, block_height, tx.inputs()).await?;
                update_balances_from_outputs(&mut db_tx, block_height, tx.outputs()).await?;
            }

            db_tx.set_block(block.get_id(), &block).await?;
            db_tx.set_best_block(block_height, block.get_id().into()).await?;
        }

        db_tx.commit().await?;

        logging::log::info!("Database commit completed successfully");

        Ok(())
    }
}

async fn update_balances_from_inputs<T: ApiServerStorageWrite>(
    db_tx: &mut T,
    block_height: BlockHeight,
    inputs: &[TxInput],
) -> Result<(), ApiServerStorageError> {
    for input in inputs {
        match input {
            TxInput::Account(_) => {
                // TODO
            }
            TxInput::Utxo(outpoint) => {
                let address = "TODO";

                match outpoint.source_id() {
                    OutPointSourceId::BlockReward(_block_id) => {}
                    OutPointSourceId::Transaction(transaction_id) => {
                        let input_transaction =
                            db_tx.get_transaction(transaction_id).await?.expect("");

                        match &input_transaction.1.transaction().outputs()
                            [outpoint.output_index() as usize]
                        {
                            TxOutput::Burn(_)
                            | TxOutput::CreateDelegationId(_, _)
                            | TxOutput::CreateStakePool(_, _)
                            | TxOutput::DelegateStaking(_, _)
                            | TxOutput::IssueFungibleToken(_)
                            | TxOutput::IssueNft(_, _, _)
                            | TxOutput::ProduceBlockFromStake(_, _) => {}
                            TxOutput::LockThenTransfer(output_value, _destination, _)
                            | TxOutput::Transfer(output_value, _destination) => {
                                match output_value {
                                    OutputValue::Coin(amount) => {
                                        let current_balance =
                                            db_tx.get_address_balance(address).await?.expect("");

                                        let new_amount = current_balance.sub(*amount).expect("");

                                        db_tx
                                            .set_address_balance_at_height(
                                                address,
                                                new_amount,
                                                block_height,
                                            )
                                            .await?;
                                    }
                                    OutputValue::TokenV0(_) => {
                                        // TODO
                                    }
                                    OutputValue::TokenV1(_, _) => {
                                        // TODO
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

async fn update_balances_from_outputs<T: ApiServerStorageWrite>(
    db_tx: &mut T,
    block_height: BlockHeight,
    outputs: &[TxOutput],
) -> Result<(), ApiServerStorageError> {
    let address = "TODO";

    for output in outputs {
        match output {
            TxOutput::Burn(_)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::CreateStakePool(_, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::ProduceBlockFromStake(_, _) => {}
            TxOutput::Transfer(output_value, _destination)
            | TxOutput::LockThenTransfer(output_value, _destination, _) => {
                match output_value {
                    OutputValue::TokenV0(_) => {
                        // TODO
                    }
                    OutputValue::TokenV1(_, _) => {
                        // TODO
                    }
                    OutputValue::Coin(amount) => {
                        let current_balance = db_tx.get_address_balance(address).await?.expect("");
                        let new_amount = current_balance.add(*amount).expect("");

                        db_tx
                            .set_address_balance_at_height(address, new_amount, block_height)
                            .await?;
                    }
                }
            }
        }
    }

    Ok(())
}
