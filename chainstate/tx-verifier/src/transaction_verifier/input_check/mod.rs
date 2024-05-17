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
        signature::{inputsig::InputWitness, Signable, Transactable},
        ChainConfig, GenBlock, TxInput, TxOutput,
    },
    primitives::{BlockHeight, Id},
};
use mintscript::{InputInfo, SignatureContext, TimelockContext};

use crate::TransactionVerifierStorageRef;

use super::{error::ConnectTransactionError, TransactionSourceForConnect};

// TODO(PR): Maybe fuse block and transaction contexts into one
pub struct BlockVerificationContext<'a, S, AW> {
    chain_config: &'a ChainConfig,
    spending_time: BlockTimestamp,
    spending_height: BlockHeight,
    tip: Id<GenBlock>,
    storage: &'a S,
    pos_accounting: &'a AW,
}

impl<'a, S, AW> BlockVerificationContext<'a, S, AW> {
    pub fn from_source(
        chain_config: &'a ChainConfig,
        spending_time: BlockTimestamp,
        tx_source: &TransactionSourceForConnect,
        storage: &'a S,
        pos_accounting: &'a AW,
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
            spending_time,
            tx_source.expected_block_height(),
            tip,
            storage,
            pos_accounting,
        )
    }

    pub fn custom(
        chain_config: &'a ChainConfig,
        spending_time: BlockTimestamp,
        spending_height: BlockHeight,
        tip: Id<GenBlock>,
        storage: &'a S,
        pos_accounting: &'a AW,
    ) -> Self {
        Self {
            chain_config,
            spending_time,
            spending_height,
            tip,
            storage,
            pos_accounting,
        }
    }
}

pub struct TransactionVerificationContext<'a, T, S, AW> {
    block_ctx: &'a BlockVerificationContext<'a, S, AW>,
    transactable: &'a T,
    inputs_and_sigs: Vec<(InputInfo<'a>, &'a InputWitness)>,
}

impl<'a, T: Signable + Transactable, S, AW> TransactionVerificationContext<'a, T, S, AW> {
    pub fn new<UW: utxo::UtxosView>(
        block_ctx: &'a BlockVerificationContext<'a, S, AW>,
        utxo_view: &UW,
        transactable: &'a T,
    ) -> Result<Self, ConnectTransactionError> {
        let inputs = transactable.inputs().unwrap_or_default();
        let sigs = transactable.signatures().unwrap_or_default();

        // TODO(PR): Should this be a proper check rather than an assertion? Is it correct?
        assert_eq!(inputs.len(), sigs.len());

        let inputs_and_sigs = inputs
            .iter()
            .zip(sigs.iter())
            .map(|(input, sig)| {
                let info = match input {
                    TxInput::Utxo(outpoint) => {
                        let err_f =
                            || ConnectTransactionError::MissingOutputOrSpent(outpoint.clone());
                        let utxo = utxo_view
                            .utxo(outpoint)
                            .map_err(|_| utxo::Error::ViewRead)?
                            .ok_or_else(err_f)?;
                        InputInfo::Utxo { outpoint, utxo }
                    }
                    TxInput::Account(outpoint) => InputInfo::Account { outpoint },
                    TxInput::AccountCommand(_, command) => InputInfo::AccountCommand { command },
                };
                Ok((info, sig))
            })
            .collect::<Result<Vec<_>, ConnectTransactionError>>()?;

        Ok(Self {
            block_ctx,
            transactable,
            inputs_and_sigs,
        })
    }
}

pub struct CachedInputList<'a, T, S, AW> {
    tx_ctx: &'a TransactionVerificationContext<'a, T, S, AW>,
    spent_outputs: Vec<Option<&'a TxOutput>>,
}

impl<'a, T, S, A> CachedInputList<'a, T, S, A> {
    pub fn new(tx_ctx: &'a TransactionVerificationContext<'a, T, S, A>) -> Self {
        CachedInputList {
            tx_ctx,
            spent_outputs: tx_ctx.inputs_and_sigs.iter().map(|(i, _)| i.as_utxo_output()).collect(),
        }
    }

    fn try_for_each_input<E>(
        &self,
        mut func: impl FnMut(InputVerificationContext<T, S, A>) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut ins = self.tx_ctx.inputs_and_sigs.iter().enumerate();
        ins.try_for_each(|(n, (inp, wit))| func(InputVerificationContext::new(self, n, inp, wit)))
    }
}

impl<'a, T, S, AW> CachedInputList<'a, T, S, AW>
where
    T: Signable + Transactable + mintscript::TranslateInput,
    S: TransactionVerifierStorageRef,
    AW: pos_accounting::PoSAccountingView<Error = pos_accounting::Error>,
{
    pub fn verify_inputs(&self) -> Result<(), ConnectTransactionError> {
        self.try_for_each_input(|ctx| Ok(mintscript::verify(ctx)?))
    }
}

struct InputVerificationContext<'a, T, S, AW> {
    tx_ctx_with_cache: &'a CachedInputList<'a, T, S, AW>,
    input_num: usize,
    info: &'a InputInfo<'a>,
    witness: &'a InputWitness,
}

impl<'a, T, S, AW> InputVerificationContext<'a, T, S, AW> {
    fn new(
        tx_ctx_with_cache: &'a CachedInputList<'a, T, S, AW>,
        input_num: usize,
        info: &'a InputInfo<'a>,
        witness: &'a InputWitness,
    ) -> Self {
        Self {
            tx_ctx_with_cache,
            input_num,
            info,
            witness,
        }
    }

    fn tx_ctx(&self) -> &TransactionVerificationContext<'a, T, S, AW> {
        self.tx_ctx_with_cache.tx_ctx
    }

    fn block_ctx(&self) -> &BlockVerificationContext<'a, S, AW> {
        self.tx_ctx().block_ctx
    }
}

impl<T, S: TransactionVerifierStorageRef, AW> TimelockContext
    for InputVerificationContext<'_, T, S, AW>
{
    type Error = ConnectTransactionError;

    fn spending_height(&self) -> BlockHeight {
        self.block_ctx().spending_height
    }

    fn spending_time(&self) -> BlockTimestamp {
        self.block_ctx().spending_time
    }

    fn source_height(&self) -> Result<BlockHeight, Self::Error> {
        match self.info {
            InputInfo::Utxo { outpoint: _, utxo } => match utxo.source() {
                utxo::UtxoSource::Blockchain(height) => Ok(*height),
                utxo::UtxoSource::Mempool => Ok(self.block_ctx().spending_height),
            },
            InputInfo::Account { .. } | InputInfo::AccountCommand { .. } => {
                todo!("account timelock height")
            }
        }
    }

    fn source_time(&self) -> Result<BlockTimestamp, Self::Error> {
        match self.info {
            InputInfo::Utxo { outpoint: _, utxo } => match utxo.source() {
                utxo::UtxoSource::Blockchain(height) => {
                    let block_index_getter = |db_tx: &S, _: &ChainConfig, id: &Id<GenBlock>| {
                        db_tx.get_gen_block_index(id)
                    };

                    let source_block_index = block_index_ancestor_getter(
                        block_index_getter,
                        self.block_ctx().storage,
                        self.block_ctx().chain_config,
                        (&self.block_ctx().tip).into(),
                        *height,
                    )
                    .map_err(|e| {
                        ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoadedFromHeight(
                            e, *height,
                        )
                    })?;

                    Ok(source_block_index.block_timestamp())
                }
                utxo::UtxoSource::Mempool => Ok(self.block_ctx().spending_time),
            },
            InputInfo::Account { .. } | InputInfo::AccountCommand { .. } => {
                todo!("account timelock timestamp")
            }
        }
    }
}

impl<T: Signable + Transactable, S, AW> SignatureContext
    for InputVerificationContext<'_, T, S, AW>
{
    type Tx = T;

    fn chain_config(&self) -> &ChainConfig {
        self.block_ctx().chain_config
    }

    fn transaction(&self) -> &Self::Tx {
        self.tx_ctx().transactable
    }

    fn input_utxos(&self) -> &[Option<&common::chain::TxOutput>] {
        &self.tx_ctx_with_cache.spent_outputs
    }

    fn input_num(&self) -> usize {
        self.input_num
    }
}

impl<'a, T, S, AW> mintscript::translate::TranslationContext
    for InputVerificationContext<'a, T, S, AW>
where
    AW: pos_accounting::PoSAccountingView<Error = pos_accounting::Error>,
{
    type Accounting = &'a AW;

    type Tokens = ();

    fn pos_accounting(&self) -> Self::Accounting {
        self.block_ctx().pos_accounting
    }

    fn tokens(&self) -> Self::Tokens {
        todo!("get tokens accounting")
    }

    fn input_info(&self) -> &InputInfo {
        &self.info
    }

    fn witness(&self) -> &InputWitness {
        &self.witness
    }
}
