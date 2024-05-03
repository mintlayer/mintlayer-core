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

use chainstate_types::block_index_ancestor_getter;
use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        signature::{verify_signature, Signable, Transactable},
        ChainConfig, GenBlock, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{BlockHeight, Id},
};
use itertools::Itertools;

use crate::TransactionVerifierStorageRef;

use super::{
    error::ConnectTransactionError, signature_destination_getter::SignatureDestinationGetter,
    TransactionSourceForConnect,
};

pub struct BlockVerificationContext<'a> {
    chain_config: &'a ChainConfig,
    destination_getter: SignatureDestinationGetter<'a>,
    spending_time: BlockTimestamp,
    spending_height: BlockHeight,
    tip: Id<GenBlock>,
}

impl<'a> BlockVerificationContext<'a> {
    // TODO(PR): Make the timelock-only property compile time checked
    pub fn for_timelock_check_only(
        chain_config: &'a ChainConfig,
        spend_time: BlockTimestamp,
        spend_height: BlockHeight,
        tip: Id<GenBlock>,
    ) -> Self {
        let dest_getter = SignatureDestinationGetter::new_custom(Box::new(|_| {
            panic!("Signature getter called from timelock-only context")
        }));
        Self::custom(chain_config, dest_getter, spend_time, spend_height, tip)
    }

    pub fn from_source(
        chain_config: &'a ChainConfig,
        destination_getter: SignatureDestinationGetter<'a>,
        spending_time: BlockTimestamp,
        tx_source: &TransactionSourceForConnect,
    ) -> Self {
        let tip = match tx_source {
            TransactionSourceForConnect::Chain { new_block_index } => {
                (*new_block_index.block_id()).into()
            }
            TransactionSourceForConnect::Mempool {
                current_best,
                effective_height: _,
            } => current_best.block_id(),
        };

        Self::custom(
            chain_config,
            destination_getter,
            spending_time,
            tx_source.expected_block_height(),
            tip,
        )
    }

    pub fn custom(
        chain_config: &'a ChainConfig,
        destination_getter: SignatureDestinationGetter<'a>,
        spending_time: BlockTimestamp,
        spending_height: BlockHeight,
        tip: Id<GenBlock>,
    ) -> Self {
        Self {
            chain_config,
            destination_getter,
            spending_time,
            spending_height,
            tip,
        }
    }
}

struct UtxoInputSpendingInfo {
    timestamp: BlockTimestamp,
    height: BlockHeight,
}

enum InputSpendingInfo {
    Utxo(UtxoInputSpendingInfo),
    Account,
    AccountCommand,
}

impl InputSpendingInfo {
    fn as_utxo(&self) -> Option<&UtxoInputSpendingInfo> {
        match self {
            Self::Utxo(info) => Some(info),
            Self::AccountCommand | Self::Account => None,
        }
    }
}

pub struct TransactionVerificationContext<'a, T> {
    block_ctx: &'a BlockVerificationContext<'a>,
    transactable: &'a T,
    spent_outputs: Vec<Option<TxOutput>>,
    spent_infos: Vec<InputSpendingInfo>,
}

impl<'a, T: Signable + Transactable> TransactionVerificationContext<'a, T> {
    pub fn new<U: utxo::UtxosView, S: TransactionVerifierStorageRef>(
        block_ctx: &'a BlockVerificationContext<'a>,
        utxo_view: &U,
        transactable: &'a T,
        storage: &S,
    ) -> Result<Self, ConnectTransactionError> {
        let inputs = transactable.inputs().unwrap_or(&[]);

        let (spent_outputs, spent_infos): (Vec<_>, Vec<_>) = inputs
            .iter()
            .map(|input| {
                let utxo_and_info = match input {
                    TxInput::Utxo(outpoint) => {
                        let utxo =
                            utxo_view.utxo(outpoint).map_err(|_| utxo::Error::ViewRead)?.ok_or(
                                ConnectTransactionError::MissingOutputOrSpent(outpoint.clone()),
                            )?;

                        let (height, timestamp) = match utxo.source() {
                            utxo::UtxoSource::Blockchain(height) => {
                                let block_index_getter = |db_tx: &S, _cc: &ChainConfig, id: &Id<GenBlock>| {
                                    db_tx.get_gen_block_index(id)
                                };

                                let source_block_index = block_index_ancestor_getter(
                                    block_index_getter,
                                    storage,
                                    block_ctx.chain_config,
                                    (&block_ctx.tip).into(),
                                    *height,
                                )
                                .map_err(|e| {
                                    ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoadedFromHeight(
                                        e, *height,
                                    )
                                })?;

                                (*height, source_block_index.block_timestamp())
                            }
                            utxo::UtxoSource::Mempool => {
                                (block_ctx.spending_height, block_ctx.spending_time)
                            }
                        };

                        let info = UtxoInputSpendingInfo { timestamp, height };
                        (Some(utxo.take_output()), InputSpendingInfo::Utxo(info))
                    }
                    TxInput::Account(..) => (None, InputSpendingInfo::Account),
                    TxInput::AccountCommand(..) => (None, InputSpendingInfo::AccountCommand),
                };
                Ok(utxo_and_info)
            })
            .collect::<Result<Vec<_>, ConnectTransactionError>>()?.into_iter().unzip();

        Ok(Self {
            block_ctx,
            transactable,
            spent_outputs,
            spent_infos,
        })
    }

    pub fn inputs(&self) -> &[TxInput] {
        self.transactable.inputs().unwrap_or(&[])
    }

    fn try_for_each_input<E>(
        &self,
        mut func: impl FnMut(InputVerificationContext<T>) -> Result<(), E>,
    ) -> Result<(), E> {
        (0..self.spent_outputs.len())
            .try_for_each(|input_index| func(InputVerificationContext::new(self, input_index)))
    }

    pub fn verify_inputs(&self) -> Result<(), ConnectTransactionError> {
        self.try_for_each_input(|input_ctx| input_ctx.verify_input())
    }

    pub fn verify_input_timelocks(&self) -> Result<(), ConnectTransactionError> {
        self.try_for_each_input(|input_ctx| input_ctx.check_timelock())
    }
}

struct InputVerificationContext<'a, T> {
    transaction_ctx: &'a TransactionVerificationContext<'a, T>,
    input_index: usize,
    info: InputVerificationInfo<'a>,
}

enum InputVerificationInfo<'a> {
    Utxo(UtxoInputVerificationInfo<'a>),
    Account,
    AccountCommand,
}

struct UtxoInputVerificationInfo<'a> {
    output: &'a TxOutput,
    spending_info: &'a UtxoInputSpendingInfo,
    outpoint: &'a UtxoOutPoint,
}

impl<'a, T: Signable + Transactable> InputVerificationContext<'a, T> {
    fn new(transaction_ctx: &'a TransactionVerificationContext<'a, T>, input_index: usize) -> Self {
        assert!(input_index < transaction_ctx.spent_infos.len());

        let info = match &transaction_ctx.inputs()[input_index] {
            TxInput::Utxo(outpoint) => {
                let output = &transaction_ctx.spent_outputs[input_index]
                    .as_ref()
                    .expect("Already checked on construction");
                let spending_info = transaction_ctx.spent_infos[input_index]
                    .as_utxo()
                    .expect("Already checked on construction");
                let info = UtxoInputVerificationInfo {
                    output,
                    spending_info,
                    outpoint,
                };
                InputVerificationInfo::Utxo(info)
            }
            TxInput::Account(_outpoint) => InputVerificationInfo::Account,
            TxInput::AccountCommand(_nonce, _command) => InputVerificationInfo::AccountCommand,
        };

        Self {
            transaction_ctx,
            input_index,
            info,
        }
    }

    fn input(&self) -> &TxInput {
        &self.transaction_ctx.inputs()[self.input_index]
    }

    fn verify_input(&self) -> Result<(), ConnectTransactionError> {
        self.check_timelock()?;
        self.check_signatures()?;
        Ok(())
    }

    fn check_timelock(&self) -> Result<(), ConnectTransactionError> {
        match &self.info {
            InputVerificationInfo::Utxo(info) => {
                let timelock = match info.output.timelock() {
                    Some(timelock) => timelock,
                    None => return Ok(()),
                };
                super::timelock_check::check_timelock(
                    &info.spending_info.height,
                    &info.spending_info.timestamp,
                    timelock,
                    &self.transaction_ctx.block_ctx.spending_height,
                    &self.transaction_ctx.block_ctx.spending_time,
                    info.outpoint,
                )
            }
            InputVerificationInfo::Account => Ok(()),
            InputVerificationInfo::AccountCommand => Ok(()),
        }
    }

    fn check_signatures(&self) -> Result<(), ConnectTransactionError> {
        let block_ctx = self.transaction_ctx.block_ctx;
        let spent_inputs =
            self.transaction_ctx.spent_outputs.iter().map(|o| o.as_ref()).collect_vec();
        verify_signature(
            block_ctx.chain_config,
            &block_ctx.destination_getter.call(self.input())?,
            self.transaction_ctx.transactable,
            &spent_inputs,
            self.input_index,
        )
        .map_err(ConnectTransactionError::SignatureVerificationFailed)
    }
}
