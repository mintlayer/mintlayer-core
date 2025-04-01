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
        block::{timestamp::BlockTimestamp, BlockRewardTransactable},
        signature::{
            inputsig::InputWitness, sighash::SighashInputInfo, DestinationSigError, Signable,
            Transactable,
        },
        tokens::TokenId,
        ChainConfig, DelegationId, Destination, GenBlock, OrderAccountCommand, PoolId,
        SignedTransaction, TxInput, TxOutput,
    },
    primitives::{BlockHeight, Id},
};
use mintscript::{
    translate::InputInfoProvider, InputInfo, SignatureContext, TimelockContext, TranslateInput,
    WitnessScript,
};

use crate::TransactionVerifierStorageRef;

use super::TransactionSourceForConnect;

pub mod signature_only_check;

pub type HashlockError = mintscript::checker::HashlockError;
pub type TimelockError = mintscript::checker::TimelockError<TimelockContextError>;
pub type ScriptError =
    mintscript::script::ScriptError<DestinationSigError, TimelockError, HashlockError>;

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

impl From<mintscript::script::ScriptError<Infallible, TimelockError, Infallible>>
    for InputCheckErrorPayload
{
    fn from(value: mintscript::script::ScriptError<Infallible, TimelockError, Infallible>) -> Self {
        Self::Verification(value.errs_into())
    }
}

impl From<mintscript::script::ScriptError<DestinationSigError, Infallible, Infallible>>
    for InputCheckErrorPayload
{
    fn from(
        value: mintscript::script::ScriptError<DestinationSigError, Infallible, Infallible>,
    ) -> Self {
        let err = match value {
            mintscript::script::ScriptError::Signature(e) => ScriptError::Signature(e),
            mintscript::script::ScriptError::Timelock(_e) => unreachable!(),
            mintscript::script::ScriptError::Hashlock(e) => ScriptError::Hashlock(e.into()),
            mintscript::script::ScriptError::Threshold(e) => ScriptError::Threshold(e),
        };
        Self::Verification(err)
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

    #[error("Utxo source is missing")]
    MissingUtxoSource,

    #[error("Loading ancestor header at height {1} failed: {0}")]
    HeaderLoad(chainstate_types::GetAncestorError, BlockHeight),
}

pub struct PerInputData<'a> {
    input: InputInfo<'a>,
    witness: InputWitness,
}

impl<'a> PerInputData<'a> {
    fn new(input: InputInfo<'a>, witness: InputWitness) -> Self {
        Self { input, witness }
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

pub struct TranslationContextFull<'a, AV, TV, OV> {
    // Sources of additional information, should it be required.
    pos_accounting: AV,
    tokens_accounting: TV,
    orders_accounting: OV,

    // Information about the input
    input: &'a PerInputData<'a>,
}

impl<'a, AV, TV, OV> TranslationContextFull<'a, AV, TV, OV> {
    fn new(
        pos_accounting: AV,
        tokens_accounting: TV,
        orders_accounting: OV,
        input: &'a PerInputData<'a>,
    ) -> Self {
        Self {
            pos_accounting,
            tokens_accounting,
            orders_accounting,
            input,
        }
    }
}

impl<AV, TV, OV> mintscript::translate::InputInfoProvider
    for TranslationContextFull<'_, AV, TV, OV>
{
    fn input_info(&self) -> &InputInfo {
        self.input.input_info()
    }

    fn witness(&self) -> &InputWitness {
        self.input.witness()
    }
}

impl<AV, TV, OV> mintscript::translate::SignatureInfoProvider
    for TranslationContextFull<'_, AV, TV, OV>
where
    AV: pos_accounting::PoSAccountingView<Error = pos_accounting::Error>,
    TV: tokens_accounting::TokensAccountingView<Error = tokens_accounting::Error>,
    OV: orders_accounting::OrdersAccountingView<Error = orders_accounting::Error>,
{
    fn get_pool_decommission_destination(
        &self,
        pool_id: &PoolId,
    ) -> Result<Option<Destination>, pos_accounting::Error> {
        Ok(self
            .pos_accounting
            .get_pool_data(*pool_id)?
            .map(|pool| pool.decommission_destination().clone()))
    }

    fn get_delegation_spend_destination(
        &self,
        delegation_id: &DelegationId,
    ) -> Result<Option<Destination>, pos_accounting::Error> {
        Ok(self
            .pos_accounting
            .get_delegation_data(*delegation_id)?
            .map(|delegation| delegation.spend_destination().clone()))
    }

    fn get_tokens_authority(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<Destination>, tokens_accounting::Error> {
        Ok(
            self.tokens_accounting.get_token_data(token_id)?.map(|token| match token {
                tokens_accounting::TokenData::FungibleToken(data) => data.authority().clone(),
            }),
        )
    }

    fn get_orders_conclude_destination(
        &self,
        order_id: &common::chain::OrderId,
    ) -> Result<Option<Destination>, orders_accounting::Error> {
        Ok(self
            .orders_accounting
            .get_order_data(order_id)?
            .map(|data| data.conclude_key().clone()))
    }
}

impl<AV, TV, OV> TranslationContextFull<'_, AV, TV, OV>
where
    AV: pos_accounting::PoSAccountingView<Error = pos_accounting::Error>,
    TV: tokens_accounting::TokensAccountingView<Error = tokens_accounting::Error>,
    OV: orders_accounting::OrdersAccountingView<Error = orders_accounting::Error>,
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
    fn from_transaction(
        utxo_view: &impl utxo::UtxosView,
        pos_accounting_view: &impl pos_accounting::PoSAccountingView,
        order_accounting_view: &impl orders_accounting::OrdersAccountingView,
        tx: &'a SignedTransaction,
    ) -> Result<Self, InputCheckError> {
        assert_eq!(tx.inputs().len(), tx.signatures().len());

        let inputs_and_sigs = tx
            .inputs()
            .iter()
            .zip(tx.signatures().iter())
            .enumerate()
            .map(|(n, (input, sig))| {
                let info = match input {
                    TxInput::Utxo(outpoint) => {
                        let utxo = utxo_view
                            .utxo(outpoint)
                            .map_err(|_| InputCheckError::new(n, utxo::Error::ViewRead))?
                            .ok_or_else(|| {
                                let err = InputCheckErrorPayload::MissingUtxo(outpoint.clone());
                                InputCheckError::new(n, err)
                            })?;
                        let pool_data = match utxo.output() {
                            TxOutput::Transfer(..)
                            | TxOutput::LockThenTransfer(..)
                            | TxOutput::Burn(..)
                            | TxOutput::CreateDelegationId(..)
                            | TxOutput::DelegateStaking(..)
                            | TxOutput::IssueFungibleToken(..)
                            | TxOutput::IssueNft(..)
                            | TxOutput::DataDeposit(..)
                            | TxOutput::Htlc(..)
                            | TxOutput::CreateOrder(..) => None,
                            TxOutput::CreateStakePool(id, _)
                            | TxOutput::ProduceBlockFromStake(_, id) => {
                                pos_accounting_view.get_pool_data(*id).unwrap()
                            }
                        };
                        InputInfo::Utxo {
                            outpoint,
                            utxo_source: Some(utxo.source().clone()),
                            utxo: utxo.take_output(),
                            pool_data,
                        }
                    }
                    TxInput::Account(outpoint) => InputInfo::Account { outpoint },
                    TxInput::AccountCommand(_, command) => InputInfo::AccountCommand { command },
                    TxInput::OrderAccountCommand(command) => {
                        let order_data = match command {
                            OrderAccountCommand::FillOrder(order_id, _, _)
                            | OrderAccountCommand::ConcludeOrder {
                                order_id,
                                filled_amount: _,
                                remaining_give_amount: _,
                            } => order_accounting_view.get_order_data(order_id).unwrap(),
                            OrderAccountCommand::FreezeOrder(_) => None,
                        };
                        InputInfo::OrderAccountCommand {
                            command,
                            order_data,
                        }
                    }
                };
                Ok(PerInputData::new(info, sig.clone()))
            })
            .collect::<Result<_, _>>()?;

        Ok(Self { inputs_and_sigs })
    }

    fn from_block_reward<UV: utxo::UtxosView>(
        utxo_view: &UV,
        reward: &'a BlockRewardTransactable,
    ) -> Result<Self, InputCheckError> {
        let inputs = reward.inputs().unwrap_or_default();
        let sigs = reward.signatures();

        assert_eq!(inputs.len(), sigs.len());

        let inputs_and_sigs = inputs
            .iter()
            .zip(sigs.iter())
            .enumerate()
            .map(|(n, (input, sig))| {
                let witness = sig.clone().ok_or_else(|| {
                    InputCheckError::new(
                        n,
                        ScriptError::Signature(DestinationSigError::SignatureNotFound),
                    )
                })?;

                let info = match input {
                    TxInput::Utxo(outpoint) => {
                        let utxo = utxo_view
                            .utxo(outpoint)
                            .map_err(|_| InputCheckError::new(n, utxo::Error::ViewRead))?
                            .ok_or_else(|| {
                                let err = InputCheckErrorPayload::MissingUtxo(outpoint.clone());
                                InputCheckError::new(n, err)
                            })?;
                        InputInfo::Utxo {
                            outpoint,
                            utxo_source: Some(utxo.source().clone()),
                            utxo: utxo.take_output(),
                            pool_data: None,
                        }
                    }
                    TxInput::Account(_)
                    | TxInput::AccountCommand(..)
                    | TxInput::OrderAccountCommand(..) => {
                        return Err(InputCheckError::new(
                            n,
                            InputCheckErrorPayload::Translation(
                                mintscript::translate::TranslationError::IllegalAccountSpend,
                            ),
                        ))
                    }
                };
                Ok(PerInputData::new(info, witness))
            })
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
            InputInfo::Utxo {
                outpoint: _,
                utxo: _,
                utxo_source,
                pool_data: _,
            } => match utxo_source.as_ref().ok_or(TimelockContextError::MissingUtxoSource)? {
                utxo::UtxoSource::Blockchain(height) => Ok(*height),
                utxo::UtxoSource::Mempool => Ok(self.ctx.spending_height),
            },
            InputInfo::Account { .. }
            | InputInfo::AccountCommand { .. }
            | InputInfo::OrderAccountCommand { .. } => Err(TimelockContextError::TimelockedAccount),
        }
    }

    fn source_time(&self) -> Result<BlockTimestamp, Self::Error> {
        match self.info() {
            InputInfo::Utxo {
                outpoint: _,
                utxo: _,
                utxo_source,
                pool_data: _,
            } => match utxo_source.as_ref().ok_or(TimelockContextError::MissingUtxoSource)? {
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
            InputInfo::Account { .. }
            | InputInfo::AccountCommand { .. }
            | InputInfo::OrderAccountCommand { .. } => Err(TimelockContextError::TimelockedAccount),
        }
    }
}

struct VerifyContextFull<'a, T, S> {
    // Here we need more information about the transaction
    transaction: &'a T,
    sighash_inputs_info: Vec<SighashInputInfo<'a>>,

    // And the part of the context that's shared with timelock verification
    sub_ctx: &'a VerifyContextTimelock<'a, S>,
}

impl<'a, T, S> VerifyContextFull<'a, T, S> {
    fn new(transaction: &'a T, sub_ctx: &'a VerifyContextTimelock<'a, S>) -> Self {
        let inp_iter = sub_ctx.core_ctx.inputs_and_sigs.iter();
        let sighash_inputs_info = inp_iter
            .map(|d| match d.input_info() {
                InputInfo::Utxo {
                    outpoint,
                    utxo,
                    utxo_source,
                    pool_data,
                } => todo!(),
                InputInfo::Account { .. } | InputInfo::AccountCommand { .. } => {
                    SighashInputInfo::None
                }
                InputInfo::OrderAccountCommand {
                    command,
                    order_data,
                } => todo!(),
            })
            .collect();

        Self {
            transaction,
            sighash_inputs_info,
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

    fn sighash_inputs_info(&self) -> &[SighashInputInfo] {
        &self.ctx.sighash_inputs_info
    }

    fn input_num(&self) -> usize {
        self.input_num
    }
}

pub trait FullyVerifiable<AV, TV, OV>:
    Transactable + for<'a> TranslateInput<TranslationContextFull<'a, &'a AV, &'a TV, &'a OV>>
{
}

impl<T, AV, TV, OV> FullyVerifiable<AV, TV, OV> for T where
    T: Transactable + for<'a> TranslateInput<TranslationContextFull<'a, &'a AV, &'a TV, &'a OV>>
{
}

// FIXME:  CoreContextConstructable collect info differently for Reward and Tx to handle decommission pool case properly.
// But it should also check height and version for fork activation, because older signatures must be verified
// with just None|Utxo (i.e. no SighashInputInfo::OrderData|DecommissionPool)
pub trait CoreContextConstructable<'a, UV, AV, OV> {
    fn new(
        &'a self,
        utxo_view: &UV,
        pos_accounting_view: &AV,
        order_accounting_view: &OV,
    ) -> Result<CoreContext<'a>, InputCheckError>;
}

impl<'a, UV, AV, OV> CoreContextConstructable<'a, UV, AV, OV> for SignedTransaction
where
    UV: utxo::UtxosView,
    AV: pos_accounting::PoSAccountingView,
    OV: orders_accounting::OrdersAccountingView,
{
    fn new(
        &'a self,
        utxo_view: &UV,
        pos_accounting_view: &AV,
        order_accounting_view: &OV,
    ) -> Result<CoreContext<'a>, InputCheckError> {
        CoreContext::from_transaction(utxo_view, pos_accounting_view, order_accounting_view, self)
    }
}

impl<'a, UV, AV, OV> CoreContextConstructable<'a, UV, AV, OV> for BlockRewardTransactable<'a>
where
    UV: utxo::UtxosView,
    AV: pos_accounting::PoSAccountingView,
    OV: orders_accounting::OrdersAccountingView,
{
    fn new(
        &'a self,
        utxo_view: &UV,
        _pos_accounting_view: &AV,
        _order_accounting_view: &OV,
    ) -> Result<CoreContext<'a>, InputCheckError> {
        CoreContext::from_block_reward(utxo_view, self)
    }
}

/// Perform full verification of given input.
#[allow(clippy::too_many_arguments)]
pub fn verify_full<'a, T, S, UV, AV, TV, OV>(
    transaction: &'a T,
    chain_config: &ChainConfig,
    utxos_view: &UV,
    pos_accounting: &AV,
    tokens_accounting: &TV,
    orders_accounting: &OV,
    storage: &S,
    tx_source: &TransactionSourceForConnect,
    spending_time: BlockTimestamp,
) -> Result<(), InputCheckError>
where
    T: FullyVerifiable<AV, TV, OV> + CoreContextConstructable<'a, UV, AV, OV>,
    S: TransactionVerifierStorageRef,
    UV: utxo::UtxosView,
    AV: pos_accounting::PoSAccountingView<Error = pos_accounting::Error>,
    TV: tokens_accounting::TokensAccountingView<Error = tokens_accounting::Error>,
    OV: orders_accounting::OrdersAccountingView<Error = orders_accounting::Error>,
{
    let core_ctx =
        CoreContextConstructable::new(transaction, utxos_view, pos_accounting, orders_accounting)?;
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
            TranslationContextFull::new(pos_accounting, tokens_accounting, orders_accounting, inp)
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
pub fn verify_timelocks<'a, T, S, UV, AV, OV>(
    transaction: &'a T,
    chain_config: &ChainConfig,
    utxos_view: &UV,
    pos_accounting: &AV,
    orders_accounting: &OV,
    storage: &S,
    tip: Id<GenBlock>,
    spending_height: BlockHeight,
    spending_time: BlockTimestamp,
) -> Result<(), InputCheckError>
where
    T: Transactable + CoreContextConstructable<'a, UV, AV, OV>,
    mintscript::translate::TimelockOnly: for<'b> TranslateInput<PerInputData<'b>>,
    S: TransactionVerifierStorageRef,
    UV: utxo::UtxosView,
    AV: pos_accounting::PoSAccountingView,
    OV: orders_accounting::OrdersAccountingView,
{
    let core_ctx =
        CoreContextConstructable::new(transaction, utxos_view, pos_accounting, orders_accounting)?;
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
