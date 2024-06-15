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

use std::convert::Infallible;

use chainstate_types::block_index_ancestor_getter;
use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        signature::{inputsig::InputWitness, DestinationSigError, Transactable},
        ChainConfig, GenBlock, TxInput, TxOutput,
    },
    primitives::{BlockHeight, Id},
};
use mintscript::{
    translate::InputInfoProvider, InputInfo, SignatureContext, TimelockContext, TranslateInput,
    WitnessScript,
};

use crate::TransactionVerifierStorageRef;

use super::TransactionSourceForConnect;

pub type TimelockError = mintscript::checker::TimelockError<TimelockContextError>;
pub type ScriptError = mintscript::script::ScriptError<DestinationSigError, TimelockError>;

#[derive(PartialEq, Eq, Clone, thiserror::Error, Debug)]
pub enum InputCheckErrorPayload {
    #[error("Utxo {0:?} missing or spent")]
    MissingUtxo(common::chain::UtxoOutPoint),

    #[error("Utxo view error: {0}")]
    UtxoView(#[from] utxo::Error),

    #[error(transparent)]
    Translation(#[from] mintscript::translate::TranslationError),

    #[error(transparent)]
    Verification(#[from] ScriptError),
}

impl From<mintscript::script::ScriptError<Infallible, TimelockError>> for InputCheckErrorPayload {
    fn from(value: mintscript::script::ScriptError<Infallible, TimelockError>) -> Self {
        Self::Verification(value.errs_into())
    }
}

#[derive(PartialEq, Eq, Clone, thiserror::Error, Debug)]
#[error("Error verifying input #{input_num}: {error}")]
pub struct InputCheckError {
    input_num: usize,
    error: InputCheckErrorPayload,
}

impl InputCheckError {
    pub fn new(input_num: usize, error: impl Into<InputCheckErrorPayload>) -> Self {
        let error = error.into();
        Self { input_num, error }
    }

    pub fn error(&self) -> &InputCheckErrorPayload {
        &self.error
    }
}

#[derive(PartialEq, Eq, Clone, thiserror::Error, Debug)]
pub enum TimelockContextError {
    #[error("Timelocks on accounts not supported")]
    TimelockedAccount,

    #[error("Loading ancestor header at height {1} failed: {0}")]
    HeaderLoad(chainstate_types::GetAncestorError, BlockHeight),
}

pub struct PerInputData<'a> {
    input: InputInfo<'a>,
    witness: &'a InputWitness,
}

impl<'a> PerInputData<'a> {
    fn new(input: InputInfo<'a>, witness: &'a InputWitness) -> Self {
        Self { input, witness }
    }

    fn from_input<UV: utxo::UtxosView>(
        utxo_view: &UV,
        input_num: usize,
        input: &'a TxInput,
        witness: &'a InputWitness,
    ) -> Result<Self, InputCheckError> {
        let info = match input {
            TxInput::Utxo(outpoint) => {
                let utxo = utxo_view
                    .utxo(outpoint)
                    .map_err(|_| InputCheckError::new(input_num, utxo::Error::ViewRead))?
                    .ok_or_else(|| {
                        let err = InputCheckErrorPayload::MissingUtxo(outpoint.clone());
                        InputCheckError::new(input_num, err)
                    })?;
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
        self.witness
    }
}

pub struct TranslationContextFull<'a, AV, TV> {
    // Sources of additional information, should it be required.
    pos_accounting: AV,
    tokens_accounting: TV,

    // Information about the input
    input: &'a PerInputData<'a>,
}

impl<'a, AV, TV> TranslationContextFull<'a, AV, TV> {
    fn new(pos_accounting: AV, tokens_accounting: TV, input: &'a PerInputData<'a>) -> Self {
        Self {
            pos_accounting,
            tokens_accounting,
            input,
        }
    }
}

impl<AV, TV> mintscript::translate::InputInfoProvider for TranslationContextFull<'_, AV, TV> {
    fn input_info(&self) -> &InputInfo {
        self.input.input_info()
    }

    fn witness(&self) -> &InputWitness {
        self.input.witness()
    }
}

impl<AV, TV> mintscript::translate::SignatureInfoProvider for TranslationContextFull<'_, AV, TV>
where
    AV: pos_accounting::PoSAccountingView<Error = pos_accounting::Error>,
    TV: tokens_accounting::TokensAccountingView<Error = tokens_accounting::Error>,
{
    type PoSAccounting = AV;
    type Tokens = TV;

    fn pos_accounting(&self) -> &Self::PoSAccounting {
        &self.pos_accounting
    }

    fn tokens(&self) -> &Self::Tokens {
        &self.tokens_accounting
    }
}

impl<AV, TV> TranslationContextFull<'_, AV, TV>
where
    AV: pos_accounting::PoSAccountingView<Error = pos_accounting::Error>,
    TV: tokens_accounting::TokensAccountingView<Error = tokens_accounting::Error>,
{
    fn to_script<T: TranslateInput<Self>>(&self) -> Result<WitnessScript, InputCheckErrorPayload> {
        Ok(T::translate_input(self)?)
    }
}

// Shared context data used for almost everything
pub struct CoreContext<'a> {
    inputs_and_sigs: Vec<PerInputData<'a>>,
}

impl<'a> CoreContext<'a> {
    fn new<T: Transactable, UV: utxo::UtxosView>(
        utxo_view: &UV,
        transaction: &'a T,
    ) -> Result<Self, InputCheckError> {
        let inputs = transaction.inputs().unwrap_or_default();
        let sigs = transaction.signatures().unwrap_or_default();

        assert_eq!(inputs.len(), sigs.len());

        let inputs_and_sigs = inputs
            .iter()
            .zip(sigs.iter())
            .enumerate()
            .map(|(n, (input, sig))| PerInputData::from_input(utxo_view, n, input, sig))
            .collect::<Result<_, _>>()?;

        Ok(Self { inputs_and_sigs })
    }

    fn input_data(&self, n: usize) -> &PerInputData {
        &self.inputs_and_sigs[n]
    }

    fn inputs_iter(&self) -> impl ExactSizeIterator<Item = (usize, &PerInputData)> {
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
        self.ctx.core_ctx.input_data(self.input_num).input_info()
    }
}

impl<S: TransactionVerifierStorageRef> TimelockContext for InputVerifyContextTimelock<'_, S> {
    type Error = TimelockContextError;

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
                Err(TimelockContextError::TimelockedAccount)
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
                    .map_err(|e| TimelockContextError::HeaderLoad(e, *height))?;

                    Ok(source_block_index.block_timestamp())
                }
                utxo::UtxoSource::Mempool => Ok(self.ctx.spending_time),
            },
            InputInfo::Account { .. } | InputInfo::AccountCommand { .. } => {
                Err(TimelockContextError::TimelockedAccount)
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
    type Error = TimelockContextError;

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
        self.ctx.sub_ctx.chain_config
    }

    fn transaction(&self) -> &Self::Tx {
        self.ctx.transaction
    }

    fn input_utxos(&self) -> &[Option<&TxOutput>] {
        &self.ctx.spent_utxos
    }

    fn input_num(&self) -> usize {
        self.input_num
    }
}

pub trait FullyVerifiable<AV, TV>:
    Transactable + for<'a> TranslateInput<TranslationContextFull<'a, &'a AV, &'a TV>>
{
}

impl<T, AV, TV> FullyVerifiable<AV, TV> for T where
    T: Transactable + for<'a> TranslateInput<TranslationContextFull<'a, &'a AV, &'a TV>>
{
}

/// Perform full verification of given input.
#[allow(clippy::too_many_arguments)]
pub fn verify_full<T, S, UV, AV, TV>(
    transaction: &T,
    chain_config: &ChainConfig,
    utxos_view: &UV,
    pos_accounting: &AV,
    tokens_accounting: &TV,
    storage: &S,
    tx_source: &TransactionSourceForConnect,
    spending_time: BlockTimestamp,
) -> Result<(), InputCheckError>
where
    T: FullyVerifiable<AV, TV>,
    S: TransactionVerifierStorageRef,
    UV: utxo::UtxosView,
    AV: pos_accounting::PoSAccountingView<Error = pos_accounting::Error>,
    TV: tokens_accounting::TokensAccountingView<Error = tokens_accounting::Error>,
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
        let script = TranslationContextFull::new(pos_accounting, tokens_accounting, inp)
            .to_script::<T>()
            .map_err(|e| InputCheckError::new(n, e))?;
        let mut checker = mintscript::ScriptChecker::full(InputVerifyContextFull::new(&ctx, n));
        script.verify(&mut checker).map_err(|e| InputCheckError::new(n, e))?;
    }

    Ok(())
}

/// Verify timelocks of given inputs.
///
/// This is used only in mempool. The full check also checks timelocks, no need to call this in
/// addition to the full check. This method exists just to re-check timelocks in case the tip
/// moves, where some timelocks may become valid (or invalid if reorg happened). Signatures and
/// hashlocks are not affected by moving tip.
///
/// While it would be cleaner for this function to be private to mempool, it currently uses parts
/// of code that are shared with the full check in a way that makes it somewhat difficult to factor
/// out without making some support types public.
pub fn verify_timelocks<T, S, UV>(
    transaction: &T,
    chain_config: &ChainConfig,
    utxos_view: &UV,
    storage: &S,
    tip: Id<GenBlock>,
    spending_height: BlockHeight,
    spending_time: BlockTimestamp,
) -> Result<(), InputCheckError>
where
    T: Transactable,
    mintscript::translate::TimelockOnly: for<'a> TranslateInput<PerInputData<'a>>,
    S: TransactionVerifierStorageRef,
    UV: utxo::UtxosView,
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
        let script = mintscript::translate::TimelockOnly::translate_input(inp)
            .map_err(|e| InputCheckError::new(n, e))?;
        let mut checker =
            mintscript::ScriptChecker::timelock_only(InputVerifyContextTimelock::new(&ctx, n));
        script.verify(&mut checker).map_err(|e| InputCheckError::new(n, e))?;
    }

    Ok(())
}