// Copyright (c) 2021-2025 RBB S.r.l
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

use std::{borrow::Cow, collections::BTreeMap};

use serialization::Encode;

use crate::{
    chain::{
        output_value::OutputValue, AccountCommand, ChainConfig, OrderAccountCommand, OrderId,
        PoolId, SighashInputCommitmentVersion, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight},
};

/// Extra data related to an input to which we commit when signing a transaction.
///
/// This allows to verify input amounts when the input transactions and account states are not available
/// (e.g. in a hardware wallet).
///
/// Note:
/// 1) Originally, this was `Option<&TxOutput>`, but `SighashInputCommitment` is encode-compatible
///    with the `Option`, provided that only `None` and `Utxo` variants are used.
/// 2) The `ProduceBlockFromStakeUtxo`, `FillOrderAccountCommand` and `ConcludeOrderAccountCommand`
///    commitments are enabled since `SighashInputCommitmentVersion::V1`.
#[derive(Clone, Debug, Encode)]
pub enum SighashInputCommitment<'a> {
    /// No extra commitment.
    ///
    /// In V0 this is used for all account-based inputs.
    /// In V1, it's used for all account-based inputs except for FillOrder and ConcludeOrder.
    #[codec(index = 0)]
    None,

    /// Commit to the entire UTXO.
    ///
    /// In V0, this is used for all UTXO-based inputs (which is redundant in many cases,
    /// but this is how it was implemented initially, for simplicity).
    /// In V1, this is used for all UTXO-based inputs except for ProduceBlockFromStake.
    #[codec(index = 1)]
    Utxo(Cow<'a, TxOutput>),

    /// Below are the V1-specific commitments.

    /// When decommissioning a pool, we want to commit to the resulting staker balance.
    ///
    /// Note: the utxos consumed during pool decommissioning are `TxOutput::CreateStakePool` and
    /// `ProduceBlockFromStake`. If the former is consumed, then the pool hasn't staked yet,
    /// so committing to `TxOutput` is enough, which is covered by the `Utxo` case.
    #[codec(index = 2)]
    ProduceBlockFromStakeUtxo { staker_balance: Amount },

    /// For FillOrder we want to commit to the initial balances, which are used to calculate
    /// the exchange ratio in orders V1.
    ///
    /// Note that we do NOT want to commit to the current balances here, because this would make
    /// FillOrder transactions non-commutative.
    #[codec(index = 3)]
    FillOrderAccountCommand {
        initially_asked: OutputValue,
        initially_given: OutputValue,
    },

    /// For ConcludeOrder we want to commit to the current balances.
    #[codec(index = 4)]
    ConcludeOrderAccountCommand {
        ask_balance: Amount,
        give_balance: Amount,
    },
    // Note: we don't commit to anything for FreezeOrder:
    // a) Committing to the initial balances would be redundant.
    // b) Committing to the current balances would be WRONG, because this would allow a malicious
    // actor to disrupt the order owner's FreezeOrder txs by constantly sending FillOrder txs
    // for some small amounts (note that such a disruption is possible for ConcludeOrder if the
    // order is not frozen; FreezeOrder's purpose is to prevent situations like this).
}

// FIXME: move infos and providers into a separate submodule.

#[derive(Debug, Clone)]
pub struct PoolInfo {
    pub staker_balance: Amount,
}

#[derive(Debug, Clone)]
pub struct OrderInfo {
    pub initially_asked: OutputValue,
    pub initially_given: OutputValue,
    pub ask_balance: Amount,
    pub give_balance: Amount,
}

pub trait UtxoProvider<'a> {
    type Error: std::error::Error;

    fn get_utxo(
        &self,
        tx_input_index: usize,
        outpoint: &UtxoOutPoint,
    ) -> Result<Option<Cow<'a, TxOutput>>, Self::Error>;
}

pub struct TrivialUtxoProvider<'a>(pub &'a [Option<TxOutput>]);

impl<'a> UtxoProvider<'a> for TrivialUtxoProvider<'a> {
    type Error = std::convert::Infallible;

    fn get_utxo(
        &self,
        tx_input_index: usize,
        _outpoint: &UtxoOutPoint,
    ) -> Result<Option<Cow<'a, TxOutput>>, Self::Error> {
        Ok(self.0.get(tx_input_index).and_then(|utxo| utxo.as_ref().map(Cow::Borrowed)))
    }
}

pub trait PoolInfoProvider {
    type Error: std::error::Error;

    fn get_pool_info(&self, pool_id: &PoolId) -> Result<Option<PoolInfo>, Self::Error>;
}

impl PoolInfoProvider for BTreeMap<PoolId, PoolInfo> {
    type Error = std::convert::Infallible;

    fn get_pool_info(&self, pool_id: &PoolId) -> Result<Option<PoolInfo>, Self::Error> {
        Ok(self.get(pool_id).cloned())
    }
}

pub trait OrderInfoProvider {
    type Error: std::error::Error;

    fn get_order_info(&self, order_id: &OrderId) -> Result<Option<OrderInfo>, Self::Error>;
}

impl OrderInfoProvider for BTreeMap<OrderId, OrderInfo> {
    type Error = std::convert::Infallible;

    fn get_order_info(&self, order_id: &OrderId) -> Result<Option<OrderInfo>, Self::Error> {
        Ok(self.get(order_id).cloned())
    }
}

pub fn make_sighash_input_commitments_for_kernel_input_utxos(
    kernel_input_utxos: &'_ [TxOutput],
) -> Vec<SighashInputCommitment<'_>> {
    kernel_input_utxos
        .iter()
        .map(|utxo| SighashInputCommitment::Utxo(Cow::Borrowed(utxo)))
        .collect()
}

pub fn make_sighash_input_commitments_for_kernel_inputs<'a, UP>(
    kernel_inputs: &[TxInput],
    utxo_provider: &UP,
) -> Result<
    Vec<SighashInputCommitment<'a>>,
    SighashInputCommitmentCreationError<
        <UP as UtxoProvider<'a>>::Error,
        std::convert::Infallible,
        std::convert::Infallible,
    >,
>
where
    UP: UtxoProvider<'a>,
{
    kernel_inputs
        .iter()
        .enumerate()
        .map(|(idx, input)| match input {
            TxInput::Utxo(outpoint) => {
                let utxo = utxo_provider
                    .get_utxo(idx, outpoint)
                    .map_err(|err| {
                        SighashInputCommitmentCreationError::UtxoProviderError(err, idx)
                    })?
                    .ok_or_else(|| {
                        SighashInputCommitmentCreationError::UtxoNotFound(outpoint.clone(), idx)
                    })?;
                Ok(SighashInputCommitment::Utxo(utxo))
            }
            TxInput::Account(_)
            | TxInput::AccountCommand(_, _)
            | TxInput::OrderAccountCommand(_) => Err(
                SighashInputCommitmentCreationError::NonUtxoKernelInput(input.clone(), idx),
            ),
        })
        .collect::<Result<_, _>>()
}

#[allow(clippy::type_complexity)]
pub fn make_sighash_input_commitments_for_transaction_inputs<'a, UP, PP, OP>(
    tx_inputs: &[TxInput],
    utxo_provider: &UP,
    pool_info_provider: &PP,
    order_info_provider: &OP,
    chain_config: &ChainConfig,
    block_height: BlockHeight,
) -> Result<
    Vec<SighashInputCommitment<'a>>,
    SighashInputCommitmentCreationError<
        <UP as UtxoProvider<'a>>::Error,
        <PP as PoolInfoProvider>::Error,
        <OP as OrderInfoProvider>::Error,
    >,
>
where
    UP: UtxoProvider<'a>,
    PP: PoolInfoProvider,
    OP: OrderInfoProvider,
{
    let input_commitment_version = chain_config
        .chainstate_upgrades()
        .version_at_height(block_height)
        .1
        .sighash_input_commitment_version();

    let commitments = match input_commitment_version {
        SighashInputCommitmentVersion::V0 => tx_inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| match input {
                TxInput::Utxo(outpoint) => {
                    let utxo = utxo_provider
                        .get_utxo(idx, outpoint)
                        .map_err(|err| {
                            SighashInputCommitmentCreationError::UtxoProviderError(err, idx)
                        })?
                        .ok_or_else(|| {
                            SighashInputCommitmentCreationError::UtxoNotFound(outpoint.clone(), idx)
                        })?;
                    Ok(SighashInputCommitment::Utxo(utxo))
                }
                TxInput::Account(_)
                | TxInput::AccountCommand(_, _)
                | TxInput::OrderAccountCommand(_) => Ok(SighashInputCommitment::None),
            })
            .collect::<Result<_, _>>()?,
        SighashInputCommitmentVersion::V1 => {
            let get_order_info = |order_id, input_idx| {
                order_info_provider
                    .get_order_info(order_id)
                    .map_err(|err| {
                        SighashInputCommitmentCreationError::OrderInfoProviderError(err, input_idx)
                    })?
                    .ok_or_else(|| {
                        SighashInputCommitmentCreationError::OrderNotFound(*order_id, input_idx)
                    })
            };

            tx_inputs
                .iter()
                .enumerate()
                .map(|(idx, input)| match input {
                    TxInput::Utxo(outpoint) => {
                        let utxo = utxo_provider
                            .get_utxo(idx, outpoint)
                            .map_err(|err| {
                                SighashInputCommitmentCreationError::UtxoProviderError(err, idx)
                            })?
                            .ok_or_else(|| {
                                SighashInputCommitmentCreationError::UtxoNotFound(
                                    outpoint.clone(),
                                    idx,
                                )
                            })?;
                        match utxo.as_ref() {
                            TxOutput::ProduceBlockFromStake(_, pool_id) => {
                                let pool_info = pool_info_provider
                                    .get_pool_info(pool_id)
                                    .map_err(|err| {
                                        SighashInputCommitmentCreationError::PoolInfoProviderError(
                                            err, idx,
                                        )
                                    })?
                                    .ok_or_else(|| {
                                        SighashInputCommitmentCreationError::PoolNotFound(
                                            *pool_id, idx,
                                        )
                                    })?;

                                Ok(SighashInputCommitment::ProduceBlockFromStakeUtxo {
                                    staker_balance: pool_info.staker_balance,
                                })
                            }
                            TxOutput::Transfer(_, _)
                            | TxOutput::LockThenTransfer(_, _, _)
                            | TxOutput::Burn(_)
                            | TxOutput::CreateStakePool(_, _)
                            | TxOutput::CreateDelegationId(_, _)
                            | TxOutput::DelegateStaking(_, _)
                            | TxOutput::IssueFungibleToken(_)
                            | TxOutput::IssueNft(_, _, _)
                            | TxOutput::DataDeposit(_)
                            | TxOutput::Htlc(_, _)
                            | TxOutput::CreateOrder(_) => Ok(SighashInputCommitment::Utxo(utxo)),
                        }
                    }
                    TxInput::Account(_) => Ok(SighashInputCommitment::None),
                    TxInput::AccountCommand(_, command) => match command {
                        AccountCommand::ConcludeOrder(order_id) => {
                            let order_info = get_order_info(order_id, idx)?;

                            Ok(SighashInputCommitment::ConcludeOrderAccountCommand {
                                ask_balance: order_info.ask_balance,
                                give_balance: order_info.give_balance,
                            })
                        }
                        AccountCommand::FillOrder(order_id, _, _) => {
                            let order_info = get_order_info(order_id, idx)?;

                            Ok(SighashInputCommitment::FillOrderAccountCommand {
                                initially_asked: order_info.initially_asked,
                                initially_given: order_info.initially_given,
                            })
                        }
                        AccountCommand::MintTokens(_, _)
                        | AccountCommand::UnmintTokens(_)
                        | AccountCommand::LockTokenSupply(_)
                        | AccountCommand::FreezeToken(_, _)
                        | AccountCommand::UnfreezeToken(_)
                        | AccountCommand::ChangeTokenAuthority(_, _)
                        | AccountCommand::ChangeTokenMetadataUri(_, _) => {
                            Ok(SighashInputCommitment::None)
                        }
                    },
                    | TxInput::OrderAccountCommand(command) => match command {
                        OrderAccountCommand::FillOrder(order_id, _, _) => {
                            let order_info = get_order_info(order_id, idx)?;

                            Ok(SighashInputCommitment::FillOrderAccountCommand {
                                initially_asked: order_info.initially_asked,
                                initially_given: order_info.initially_given,
                            })
                        }
                        OrderAccountCommand::ConcludeOrder(order_id) => {
                            let order_info = get_order_info(order_id, idx)?;

                            Ok(SighashInputCommitment::ConcludeOrderAccountCommand {
                                ask_balance: order_info.ask_balance,
                                give_balance: order_info.give_balance,
                            })
                        }
                        | OrderAccountCommand::FreezeOrder(_) => Ok(SighashInputCommitment::None),
                    },
                })
                .collect::<Result<_, _>>()?
        }
    };

    Ok(commitments)
}

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq)]
pub enum SighashInputCommitmentCreationError<UPE, PIPE, OIPE>
where
    UPE: std::error::Error,
    PIPE: std::error::Error,
    OIPE: std::error::Error,
{
    #[error("Utxo provider error: {0} (input index: {1})")]
    UtxoProviderError(UPE, /*input index*/ usize),

    #[error("Pool info provider error: {0} (input index: {1})")]
    PoolInfoProviderError(PIPE, /*input index*/ usize),

    #[error("Order info provider error: {0} (input index: {1})")]
    OrderInfoProviderError(OIPE, /*input index*/ usize),

    #[error("Non-utxo kernel input: {0:?} (input index: {1})")]
    NonUtxoKernelInput(TxInput, /*input index*/ usize),

    #[error("Utxo not found: {0:?} (input index: {1})")]
    UtxoNotFound(UtxoOutPoint, /*input index*/ usize),

    #[error("Pool not found: {0} (input index: {1})")]
    PoolNotFound(PoolId, /*input index*/ usize),

    #[error("Order not found: {0} (input index: {1})")]
    OrderNotFound(OrderId, /*input index*/ usize),
}
