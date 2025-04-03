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

use common::chain::{
    AccountCommand, AccountSpending, Destination, OrderAccountCommand, TxInput, TxOutput,
};
use orders_accounting::OrdersAccountingView;
use pos_accounting::PoSAccountingView;
use tokens_accounting::TokensAccountingView;
use tx_verifier::error::SignatureDestinationGetterError;
use utxo::UtxosView;

pub type SignatureDestinationGetterFn<'a> =
    dyn Fn(&TxInput) -> Result<Destination, SignatureDestinationGetterError> + 'a;

/// Given a signed transaction input, which spends an output of some type,
/// what is the destination of the output being spent, against which
/// signatures should be verified?
///
/// Generally speaking, there's no way to know. Hence, we create generic way
/// to do this. At the time of creating this struct, it was simple and mapping
/// from output type to destination was trivial, and only required distinguishing
/// between block reward and transaction outputs. In the future, this struct is
/// supposed to be extended to support more complex cases, where the caller can
/// request the correct mapping from output type to destination for signature
/// verification.
///
/// The errors returned in the functions based on the output type are generally
/// checked in other places, but this is just double-checking and ensuring sanity,
/// since there's close to zero harm doing it right anyway (e.g., pulling in more
/// dependencies).
pub struct SignatureDestinationGetter<'a> {
    f: Box<SignatureDestinationGetterFn<'a>>,
}

impl<'a> SignatureDestinationGetter<'a> {
    pub fn new_for_transaction<
        T: TokensAccountingView,
        P: PoSAccountingView,
        U: UtxosView,
        O: OrdersAccountingView,
    >(
        tokens_view: &'a T,
        accounting_view: &'a P,
        orders_view: &'a O,
        utxos_view: &'a U,
    ) -> Self {
        let destination_getter =
            |input: &TxInput| -> Result<Destination, SignatureDestinationGetterError> {
                match input {
                    TxInput::Utxo(outpoint) => {
                        let utxo = utxos_view
                            .utxo(outpoint)
                            .map_err(|_| {
                                SignatureDestinationGetterError::UtxoViewError(
                                    utxo::Error::ViewRead,
                                )
                            })?
                            .ok_or(SignatureDestinationGetterError::UtxoOutputNotFound(
                                outpoint.clone(),
                            ))?;

                        match utxo.output() {
                            TxOutput::Transfer(_, d) | TxOutput::LockThenTransfer(_, d, _) => {
                                Ok(d.clone())
                            }
                            TxOutput::CreateDelegationId(_, _)
                            | TxOutput::Burn(_)
                            | TxOutput::DataDeposit(_)
                            | TxOutput::CreateOrder(_) => {
                                // This error is emitted in other places for attempting to make this spend,
                                // but this is just a double-check.
                                Err(SignatureDestinationGetterError::SigVerifyOfNotSpendableOutput)
                            }
                            TxOutput::DelegateStaking(_, delegation_id) => Ok(accounting_view
                                .get_delegation_data(*delegation_id)
                                .map_err(|_| {
                                    SignatureDestinationGetterError::PoSAccountingViewError(
                                        pos_accounting::Error::ViewFail,
                                    )
                                })?
                                .ok_or(SignatureDestinationGetterError::DelegationDataNotFound(
                                    *delegation_id,
                                ))?
                                .spend_destination()
                                .clone()),
                            TxOutput::CreateStakePool(_, pool_data) => {
                                // Spending an output of a pool creation transaction is only allowed in a
                                // context of a transaction (as opposed to block reward) only if this pool
                                // is being decommissioned.
                                // If this rule is being invalidated, it will be detected in other parts
                                // of the code.
                                Ok(pool_data.decommission_key().clone())
                            }
                            TxOutput::ProduceBlockFromStake(_, pool_id) => {
                                // The only way we can spend this output in a transaction
                                // (as opposed to block reward), is if we're decommissioning a pool.
                                Ok(accounting_view
                                    .get_pool_data(*pool_id)
                                    .map_err(|_| {
                                        SignatureDestinationGetterError::PoSAccountingViewError(
                                            pos_accounting::Error::ViewFail,
                                        )
                                    })?
                                    .ok_or(SignatureDestinationGetterError::PoolDataNotFound(
                                        *pool_id,
                                    ))?
                                    .decommission_destination()
                                    .clone())
                            }
                            TxOutput::IssueNft(_, _, d) => Ok(d.clone()),
                            TxOutput::IssueFungibleToken(_) => {
                                // This error is emitted in other places for attempting to make this spend,
                                // but this is just a double-check.
                                Err(SignatureDestinationGetterError::SigVerifyOfNotSpendableOutput)
                            }
                            TxOutput::Htlc(_, htlc) => {
                                // TODO: consider spending with spend key + secret not only multisig
                                Ok(htlc.refund_key.clone())
                            }
                        }
                    }
                    TxInput::Account(outpoint) => match outpoint.account() {
                        AccountSpending::DelegationBalance(delegation_id, _) => Ok(accounting_view
                            .get_delegation_data(*delegation_id)
                            .map_err(|_| {
                                SignatureDestinationGetterError::PoSAccountingViewError(
                                    pos_accounting::Error::ViewFail,
                                )
                            })?
                            .ok_or(SignatureDestinationGetterError::DelegationDataNotFound(
                                *delegation_id,
                            ))?
                            .spend_destination()
                            .clone()),
                    },
                    TxInput::AccountCommand(_, account_op) => match account_op {
                        AccountCommand::MintTokens(token_id, _)
                        | AccountCommand::UnmintTokens(token_id)
                        | AccountCommand::LockTokenSupply(token_id)
                        | AccountCommand::FreezeToken(token_id, _)
                        | AccountCommand::UnfreezeToken(token_id)
                        | AccountCommand::ChangeTokenMetadataUri(token_id, _)
                        | AccountCommand::ChangeTokenAuthority(token_id, _) => {
                            let token_data = tokens_view
                                .get_token_data(token_id)
                                .map_err(|_| {
                                    SignatureDestinationGetterError::TokensAccountingViewError(
                                        tokens_accounting::Error::ViewFail,
                                    )
                                })?
                                .ok_or(SignatureDestinationGetterError::TokenDataNotFound(
                                    *token_id,
                                ))?;
                            let destination = match token_data {
                                tokens_accounting::TokenData::FungibleToken(data) => {
                                    data.authority().clone()
                                }
                            };
                            Ok(destination)
                        }
                        AccountCommand::ConcludeOrder(order_id) => {
                            let order_data = orders_view
                                .get_order_data(order_id)
                                .map_err(|_| {
                                    SignatureDestinationGetterError::OrdersAccountingViewError(
                                        orders_accounting::Error::ViewFail,
                                    )
                                })?
                                .ok_or(SignatureDestinationGetterError::OrderDataNotFound(
                                    *order_id,
                                ))?;
                            Ok(order_data.conclude_key().clone())
                        }
                        AccountCommand::FillOrder(_, _, d) => Ok(d.clone()),
                    },
                    TxInput::OrderAccountCommand(command) => match command {
                        OrderAccountCommand::FillOrder(_, _, d) => Ok(d.clone()),
                        OrderAccountCommand::ConcludeOrder(order_id) => {
                            let order_data = orders_view
                                .get_order_data(order_id)
                                .map_err(|_| {
                                    SignatureDestinationGetterError::OrdersAccountingViewError(
                                        orders_accounting::Error::ViewFail,
                                    )
                                })?
                                .ok_or(SignatureDestinationGetterError::OrderDataNotFound(
                                    *order_id,
                                ))?;
                            Ok(order_data.conclude_key().clone())
                        }
                    },
                }
            };

        Self {
            f: Box::new(destination_getter),
        }
    }

    #[allow(dead_code)]
    pub fn new_custom(f: Box<SignatureDestinationGetterFn<'a>>) -> Self {
        Self { f }
    }

    pub fn call(&self, input: &TxInput) -> Result<Destination, SignatureDestinationGetterError> {
        (self.f)(input)
    }
}

// TODO: tests
