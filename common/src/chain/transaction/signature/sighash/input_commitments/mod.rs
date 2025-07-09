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

mod info_providers;

use std::borrow::Cow;

use strum::{EnumDiscriminants, EnumIter};

use serialization::{Decode, Encode};
use utils::cow_utils::CowUtils as _;

use crate::{
    chain::{
        output_value::OutputValue, AccountCommand, ChainConfig, OrderAccountCommand, OrderId,
        PoolId, SighashInputCommitmentVersion, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight},
};

pub use info_providers::{
    OrderInfo, OrderInfoProvider, PoolInfo, PoolInfoProvider, TrivialUtxoProvider, UtxoProvider,
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
#[derive(Clone, Debug, Encode, Decode, Eq, PartialEq, EnumDiscriminants)]
#[strum_discriminants(name(SighashInputCommitmentTag), derive(EnumIter))]
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

    /// V1 only. When decommissioning a pool, we want to commit to the resulting staker balance.
    ///
    /// Note: the UTXOs consumed during pool decommissioning are `TxOutput::CreateStakePool` and
    /// `ProduceBlockFromStake`. If the former is consumed, then the pool hasn't staked yet,
    /// so committing to `TxOutput` is enough, which is covered by the `Utxo` case.
    ///
    /// Also note that in the `ProduceBlockFromStake` case we still commit to the UTXO, because:
    /// 1) it's useful to commit to the pool id, which is inside the `TxOutput`;
    /// 2) we don't want to "relax" the commitments in V1 compared to V0.
    #[codec(index = 2)]
    ProduceBlockFromStakeUtxo {
        utxo: Cow<'a, TxOutput>,
        staker_balance: Amount,
    },

    /// V1 only. For FillOrder we want to commit to the initial balances, which are used to calculate
    /// the exchange ratio in orders V1.
    ///
    /// Note that we do NOT want to commit to the current balances here, because this would make
    /// FillOrder transactions non-commutative.
    #[codec(index = 3)]
    FillOrderAccountCommand {
        initially_asked: OutputValue,
        initially_given: OutputValue,
    },

    /// V1 only. For ConcludeOrder we want to commit to the initial and final "ask" balances, as well
    /// as the final give balance. Committing to the initial "give" balance is not necessary, but
    /// we do it for completeness.
    #[codec(index = 4)]
    ConcludeOrderAccountCommand {
        initially_asked: OutputValue,
        initially_given: OutputValue,
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

impl SighashInputCommitment<'_> {
    pub fn deep_clone(&self) -> SighashInputCommitment<'static> {
        match self {
            SighashInputCommitment::None => SighashInputCommitment::None,
            SighashInputCommitment::Utxo(cow) => SighashInputCommitment::Utxo(cow.to_owned_cow()),
            SighashInputCommitment::ProduceBlockFromStakeUtxo {
                utxo,
                staker_balance,
            } => SighashInputCommitment::ProduceBlockFromStakeUtxo {
                utxo: utxo.to_owned_cow(),
                staker_balance: *staker_balance,
            },
            SighashInputCommitment::FillOrderAccountCommand {
                initially_asked,
                initially_given,
            } => SighashInputCommitment::FillOrderAccountCommand {
                initially_asked: initially_asked.clone(),
                initially_given: initially_given.clone(),
            },
            SighashInputCommitment::ConcludeOrderAccountCommand {
                initially_asked,
                initially_given,
                ask_balance,
                give_balance,
            } => SighashInputCommitment::ConcludeOrderAccountCommand {
                initially_asked: initially_asked.clone(),
                initially_given: initially_given.clone(),
                ask_balance: *ask_balance,
                give_balance: *give_balance,
            },
        }
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
pub fn make_sighash_input_commitments_for_transaction_inputs_at_height<'a, UP, PP, OP>(
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
    let version = chain_config
        .chainstate_upgrades()
        .version_at_height(block_height)
        .1
        .sighash_input_commitment_version();

    make_sighash_input_commitments_for_transaction_inputs(
        tx_inputs,
        utxo_provider,
        pool_info_provider,
        order_info_provider,
        version,
    )
}

#[allow(clippy::type_complexity)]
pub fn make_sighash_input_commitments_for_transaction_inputs<'a, UP, PP, OP>(
    tx_inputs: &[TxInput],
    utxo_provider: &UP,
    pool_info_provider: &PP,
    order_info_provider: &OP,
    version: SighashInputCommitmentVersion,
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
    let get_utxo = |outpoint: &UtxoOutPoint, input_idx| {
        utxo_provider
            .get_utxo(input_idx, outpoint)
            .map_err(|err| SighashInputCommitmentCreationError::UtxoProviderError(err, input_idx))?
            .ok_or_else(|| {
                SighashInputCommitmentCreationError::UtxoNotFound(outpoint.clone(), input_idx)
            })
    };
    let get_pool_info = |pool_id: &PoolId, input_idx| {
        pool_info_provider
            .get_pool_info(pool_id)
            .map_err(|err| {
                SighashInputCommitmentCreationError::PoolInfoProviderError(err, input_idx)
            })?
            .ok_or_else(|| SighashInputCommitmentCreationError::PoolNotFound(*pool_id, input_idx))
    };
    let get_order_info = |order_id: &OrderId, input_idx| {
        order_info_provider
            .get_order_info(order_id)
            .map_err(|err| {
                SighashInputCommitmentCreationError::OrderInfoProviderError(err, input_idx)
            })?
            .ok_or_else(|| SighashInputCommitmentCreationError::OrderNotFound(*order_id, input_idx))
    };

    let commitments = match version {
        SighashInputCommitmentVersion::V0 => tx_inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| {
                // Note: we want to make sure that the requirements for provider objects stay
                // the same for V0 and V1. So we simulate the creation of a V1 commitment in
                // the V0 case, to force the corresponding provider queries.
                // TODO: after the fork to V1 is complete, this can be removed.
                make_sighash_input_commitment_v1_for_one_transaction_input(
                    input,
                    idx,
                    &get_utxo,
                    &get_pool_info,
                    &get_order_info,
                )?;

                match input {
                    TxInput::Utxo(outpoint) => {
                        let utxo = get_utxo(outpoint, idx)?;

                        Ok(SighashInputCommitment::Utxo(utxo))
                    }
                    TxInput::Account(_)
                    | TxInput::AccountCommand(_, _)
                    | TxInput::OrderAccountCommand(_) => Ok(SighashInputCommitment::None),
                }
            })
            .collect::<Result<_, _>>()?,
        SighashInputCommitmentVersion::V1 => tx_inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| {
                make_sighash_input_commitment_v1_for_one_transaction_input(
                    input,
                    idx,
                    &get_utxo,
                    &get_pool_info,
                    &get_order_info,
                )
            })
            .collect::<Result<_, _>>()?,
    };

    Ok(commitments)
}

fn make_sighash_input_commitment_v1_for_one_transaction_input<'a, UG, PG, OG, E>(
    input: &TxInput,
    input_idx: usize,
    utxo_getter: &UG,
    pool_info_getter: &PG,
    order_info_getter: &OG,
) -> Result<SighashInputCommitment<'a>, E>
where
    UG: Fn(&UtxoOutPoint, /*input_idx*/ usize) -> Result<Cow<'a, TxOutput>, E>,
    PG: Fn(&PoolId, /*input_idx*/ usize) -> Result<PoolInfo, E>,
    OG: Fn(&OrderId, /*input_idx*/ usize) -> Result<OrderInfo, E>,
{
    match input {
        TxInput::Utxo(outpoint) => {
            let utxo = utxo_getter(outpoint, input_idx)?;

            match utxo.as_ref() {
                TxOutput::ProduceBlockFromStake(_, pool_id) => {
                    let pool_info = pool_info_getter(pool_id, input_idx)?;

                    Ok(SighashInputCommitment::ProduceBlockFromStakeUtxo {
                        utxo,
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
                let order_info = order_info_getter(order_id, input_idx)?;

                Ok(SighashInputCommitment::ConcludeOrderAccountCommand {
                    initially_asked: order_info.initially_asked,
                    initially_given: order_info.initially_given,
                    ask_balance: order_info.ask_balance,
                    give_balance: order_info.give_balance,
                })
            }
            AccountCommand::FillOrder(order_id, _, _) => {
                let order_info = order_info_getter(order_id, input_idx)?;

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
            | AccountCommand::ChangeTokenMetadataUri(_, _) => Ok(SighashInputCommitment::None),
        },
        | TxInput::OrderAccountCommand(command) => match command {
            OrderAccountCommand::FillOrder(order_id, _) => {
                let order_info = order_info_getter(order_id, input_idx)?;

                Ok(SighashInputCommitment::FillOrderAccountCommand {
                    initially_asked: order_info.initially_asked,
                    initially_given: order_info.initially_given,
                })
            }
            OrderAccountCommand::ConcludeOrder(order_id) => {
                let order_info = order_info_getter(order_id, input_idx)?;

                Ok(SighashInputCommitment::ConcludeOrderAccountCommand {
                    initially_asked: order_info.initially_asked,
                    initially_given: order_info.initially_given,
                    ask_balance: order_info.ask_balance,
                    give_balance: order_info.give_balance,
                })
            }
            | OrderAccountCommand::FreezeOrder(_) => Ok(SighashInputCommitment::None),
        },
    }
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
