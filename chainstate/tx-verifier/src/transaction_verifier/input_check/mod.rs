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
        signature::{inputsig::InputWitness, Transactable},
        ChainConfig, GenBlock, TxInput, TxOutput,
    },
    primitives::{BlockHeight, Id},
};
use mintscript::{
    translate::InputInfoProvider, InputInfo, SignatureContext, TimelockContext, TranslateInput,
    WitnessScript,
};

use crate::TransactionVerifierStorageRef;

use super::{error::ConnectTransactionError, TransactionSourceForConnect};

pub struct PerInputData<'a> {
    input: InputInfo<'a>,
    witness: &'a InputWitness,
}

impl<'a> PerInputData<'a> {
    fn new(input: InputInfo<'a>, witness: &'a InputWitness) -> Self {
        Self { input, witness }
    }

    fn from_input<UW: utxo::UtxosView>(
        utxo_view: &UW,
        input: &'a TxInput,
        witness: &'a InputWitness,
    ) -> Result<Self, ConnectTransactionError> {
        let info = match input {
            TxInput::Utxo(outpoint) => {
                let err_f = || ConnectTransactionError::MissingOutputOrSpent(outpoint.clone());
                let utxo = utxo_view
                    .utxo(outpoint)
                    .map_err(|_| utxo::Error::ViewRead)?
                    .ok_or_else(err_f)?;
                InputInfo::Utxo { outpoint, utxo }
            }
            TxInput::Account(outpoint) => InputInfo::Account { outpoint },
            TxInput::AccountCommand(_, command) => InputInfo::AccountCommand { command },
        };
        Ok(Self::new(info, witness))
    }
}

impl mintscript::translate::InputInfoProvider for PerInputData<'_> {
    fn input_info(&self) -> &InputInfo {
        &self.input
    }

    fn witness(&self) -> &InputWitness {
        &self.witness
    }
}

pub struct TranslationContextFull<'a, AW, TW> {
    // Sources of additional information, should it be required.
    pos_accounting: AW,
    tokens_accounting: TW,

    // Information about the input
    input: &'a PerInputData<'a>,
}

impl<'a, AW, TW> TranslationContextFull<'a, AW, TW> {
    fn new(pos_accounting: AW, tokens_accounting: TW, input: &'a PerInputData<'a>) -> Self {
        Self {
            pos_accounting,
            tokens_accounting,
            input,
        }
    }
}

impl<AW, TW> mintscript::translate::InputInfoProvider for TranslationContextFull<'_, AW, TW> {
    fn input_info(&self) -> &InputInfo {
        self.input.input_info()
    }

    fn witness(&self) -> &InputWitness {
        self.input.witness()
    }
}

impl<AW, TW> mintscript::translate::SignatureInfoProvider for TranslationContextFull<'_, AW, TW>
where
    AW: pos_accounting::PoSAccountingView<Error = pos_accounting::Error>,
    TW: tokens_accounting::TokensAccountingView<Error = tokens_accounting::Error>,
{
    type Accounting = AW;
    type Tokens = TW;

    fn pos_accounting(&self) -> &Self::Accounting {
        &self.pos_accounting
    }

    fn tokens(&self) -> &Self::Tokens {
        &self.tokens_accounting
    }
}

impl<AW, TW> TranslationContextFull<'_, AW, TW>
where
    AW: pos_accounting::PoSAccountingView<Error = pos_accounting::Error>,
    TW: tokens_accounting::TokensAccountingView<Error = tokens_accounting::Error>,
{
    fn to_script<T: TranslateInput<Self>>(&self) -> Result<WitnessScript, ConnectTransactionError> {
        Ok(T::translate_input(self)?)
    }
}

// Shared context data used for almost everything
pub struct CoreContext<'a> {
    inputs_and_sigs: Vec<PerInputData<'a>>,
}

impl<'a> CoreContext<'a> {
    fn new<T: Transactable, UW: utxo::UtxosView>(
        utxo_view: &UW,
        transaction: &'a T,
    ) -> Result<Self, ConnectTransactionError> {
        let inputs = transaction.inputs().unwrap_or_default();
        let sigs = transaction.signatures().unwrap_or_default();

        assert_eq!(inputs.len(), sigs.len());

        let inputs_and_sigs = inputs
            .iter()
            .zip(sigs.iter())
            .map(|(input, sig)| PerInputData::from_input(utxo_view, input, sig))
            .collect::<Result<_, _>>()?;

        Ok(Self { inputs_and_sigs })
    }

    fn input_data(&self, n: usize) -> &PerInputData {
        &self.inputs_and_sigs[n]
    }

    fn inputs_iter(&self) -> impl Iterator<Item = (usize, &PerInputData)> + ExactSizeIterator {
        self.inputs_and_sigs.iter().enumerate()
    }
}

// Context shared between timelock and full verification.
struct VerifyContextTimelock<'a, S> {
    // Information about the chain
    chain_config: &'a ChainConfig,

    // Storage. Used to look up block indices
    storage: &'a S,

    // The current tip. Used to look up transaction ancestors.
    tip: Id<GenBlock>,

    // Information about current spending height / time.
    spending_time: BlockTimestamp,
    spending_height: BlockHeight,

    // Pre-calculated information about the inputs
    core_ctx: &'a CoreContext<'a>,
}

impl<'a, S> VerifyContextTimelock<'a, S> {
    fn custom(
        chain_config: &'a ChainConfig,
        storage: &'a S,
        tip: Id<GenBlock>,
        spending_time: BlockTimestamp,
        spending_height: BlockHeight,
        core_ctx: &'a CoreContext<'a>,
    ) -> Self {
        Self {
            chain_config,
            storage,
            tip,
            spending_time,
            spending_height,
            core_ctx,
        }
    }

    fn for_verifier(
        chain_config: &'a ChainConfig,
        storage: &'a S,
        tx_source: &TransactionSourceForConnect,
        spending_time: BlockTimestamp,
        core_ctx: &'a CoreContext<'a>,
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
            storage,
            tip,
            spending_time,
            tx_source.expected_block_height(),
            core_ctx,
        )
    }
}

struct InputVerifyContextTimelock<'a, S> {
    ctx: &'a VerifyContextTimelock<'a, S>,
    input_num: usize,
}

impl<'a, S> InputVerifyContextTimelock<'a, S> {
    fn new(ctx: &'a VerifyContextTimelock<'a, S>, input_num: usize) -> Self {
        Self { ctx, input_num }
    }

    fn info(&self) -> &InputInfo {
        &self.ctx.core_ctx.input_data(self.input_num).input_info()
    }
}

impl<S: TransactionVerifierStorageRef> TimelockContext for InputVerifyContextTimelock<'_, S> {
    type Error = ConnectTransactionError;

    fn spending_height(&self) -> BlockHeight {
        self.ctx.spending_height
    }

    fn spending_time(&self) -> BlockTimestamp {
        self.ctx.spending_time
    }

    fn source_height(&self) -> Result<BlockHeight, Self::Error> {
        match self.info() {
            InputInfo::Utxo { outpoint: _, utxo } => match utxo.source() {
                utxo::UtxoSource::Blockchain(height) => Ok(*height),
                utxo::UtxoSource::Mempool => Ok(self.ctx.spending_height),
            },
            InputInfo::Account { .. } | InputInfo::AccountCommand { .. } => {
                todo!("account timelock height")
            }
        }
    }

    fn source_time(&self) -> Result<BlockTimestamp, Self::Error> {
        match self.info() {
            InputInfo::Utxo { outpoint: _, utxo } => match utxo.source() {
                utxo::UtxoSource::Blockchain(height) => {
                    let block_index_getter = |db_tx: &S, _: &ChainConfig, id: &Id<GenBlock>| {
                        db_tx.get_gen_block_index(id)
                    };

                    let source_block_index = block_index_ancestor_getter(
                        block_index_getter,
                        self.ctx.storage,
                        self.ctx.chain_config,
                        (&self.ctx.tip).into(),
                        *height,
                    )
                    .map_err(|e| {
                        ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoadedFromHeight(
                            e, *height,
                        )
                    })?;

                    Ok(source_block_index.block_timestamp())
                }
                utxo::UtxoSource::Mempool => Ok(self.ctx.spending_time),
            },
            InputInfo::Account { .. } | InputInfo::AccountCommand { .. } => {
                todo!("account timelock timestamp")
            }
        }
    }
}

struct VerifyContextFull<'a, T, S> {
    // Here we need more information about the transaction
    transaction: &'a T,
    spent_utxos: Vec<Option<&'a TxOutput>>,

    // And the part of the context that's shared with timelock verification
    sub_ctx: &'a VerifyContextTimelock<'a, S>,
}

impl<'a, T, S> VerifyContextFull<'a, T, S> {
    fn new(transaction: &'a T, sub_ctx: &'a VerifyContextTimelock<'a, S>) -> Self {
        let inp_iter = sub_ctx.core_ctx.inputs_and_sigs.iter();
        let spent_utxos = inp_iter.map(|d| d.input_info().as_utxo_output()).collect();

        Self {
            transaction,
            spent_utxos,
            sub_ctx,
        }
    }
}

struct InputVerifyContextFull<'a, T, S> {
    ctx: &'a VerifyContextFull<'a, T, S>,
    input_num: usize,
}

impl<'a, T, S> InputVerifyContextFull<'a, T, S> {
    fn new(ctx: &'a VerifyContextFull<'a, T, S>, input_num: usize) -> Self {
        Self { ctx, input_num }
    }

    fn sub_ctx(&self) -> InputVerifyContextTimelock<'a, S> {
        InputVerifyContextTimelock::new(self.ctx.sub_ctx, self.input_num)
    }
}

impl<T, S: TransactionVerifierStorageRef> TimelockContext for InputVerifyContextFull<'_, T, S> {
    type Error = ConnectTransactionError;

    fn spending_height(&self) -> BlockHeight {
        self.sub_ctx().spending_height()
    }

    fn spending_time(&self) -> BlockTimestamp {
        self.sub_ctx().spending_time()
    }

    fn source_height(&self) -> Result<BlockHeight, Self::Error> {
        self.sub_ctx().source_height()
    }

    fn source_time(&self) -> Result<BlockTimestamp, Self::Error> {
        self.sub_ctx().source_time()
    }
}

impl<T: Transactable, S> SignatureContext for InputVerifyContextFull<'_, T, S> {
    type Tx = T;

    fn chain_config(&self) -> &ChainConfig {
        &self.ctx.sub_ctx.chain_config
    }

    fn transaction(&self) -> &Self::Tx {
        &self.ctx.transaction
    }

    fn input_utxos(&self) -> &[Option<&TxOutput>] {
        &self.ctx.spent_utxos
    }

    fn input_num(&self) -> usize {
        self.input_num
    }
}

pub fn verify_full<T, S, UW, AW, TW>(
    transaction: &T,
    chain_config: &ChainConfig,
    utxos_view: &UW,
    pos_accounting: &AW,
    tokens_accounting: &TW,
    storage: &S,
    tx_source: &TransactionSourceForConnect,
    spending_time: BlockTimestamp,
) -> Result<(), ConnectTransactionError>
where
    T: Transactable,
    T: for<'a> TranslateInput<TranslationContextFull<'a, &'a AW, &'a TW>>,
    S: TransactionVerifierStorageRef,
    UW: utxo::UtxosView,
    AW: pos_accounting::PoSAccountingView<Error = pos_accounting::Error>,
    TW: tokens_accounting::TokensAccountingView<Error = tokens_accounting::Error>,
{
    let core_ctx = CoreContext::new(utxos_view, transaction)?;
    let tl_ctx = VerifyContextTimelock::for_verifier(
        chain_config,
        storage,
        tx_source,
        spending_time,
        &core_ctx,
    );
    let ctx = VerifyContextFull::new(transaction, &tl_ctx);

    for (n, inp) in core_ctx.inputs_iter() {
        let script =
            TranslationContextFull::new(pos_accounting, tokens_accounting, inp).to_script::<T>()?;
        let mut checker = mintscript::ScriptChecker::full(InputVerifyContextFull::new(&ctx, n));
        script.verify(&mut checker)?;
    }

    Ok(())
}

pub fn verify_timelocks<T, S, UW>(
    transaction: &T,
    chain_config: &ChainConfig,
    utxos_view: &UW,
    storage: &S,
    tip: Id<GenBlock>,
    spending_height: BlockHeight,
    spending_time: BlockTimestamp,
) -> Result<(), ConnectTransactionError>
where
    T: Transactable,
    mintscript::translate::TimelockOnly: for<'a> TranslateInput<PerInputData<'a>>,
    S: TransactionVerifierStorageRef,
    UW: utxo::UtxosView,
{
    let core_ctx = CoreContext::new(utxos_view, transaction)?;
    let ctx = VerifyContextTimelock::custom(
        chain_config,
        storage,
        tip,
        spending_time,
        spending_height,
        &core_ctx,
    );

    for (n, inp) in core_ctx.inputs_iter() {
        let script = mintscript::translate::TimelockOnly::translate_input(inp)?;
        let mut checker =
            mintscript::ScriptChecker::timelock_only(InputVerifyContextTimelock::new(&ctx, n));
        script.verify(&mut checker)?;
    }

    Ok(())
}
