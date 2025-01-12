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

pub mod currency_grouper;
mod output_cache;
pub mod transaction_list;
mod utxo_selector;

use common::address::pubkeyhash::PublicKeyHash;
use common::chain::block::timestamp::BlockTimestamp;
use common::chain::classic_multisig::ClassicMultisigChallenge;
use common::chain::htlc::HashedTimelockContract;
use common::chain::{AccountCommand, AccountOutPoint, AccountSpending, OrderId, RpcOrderInfo};
use common::primitives::id::WithId;
use common::primitives::{Idable, H256};
use common::size_estimation::{
    input_signature_size, input_signature_size_from_destination, tx_size_with_outputs,
    DestinationInfoProvider,
};
use common::Uint256;
use crypto::key::hdkd::child_number::ChildNumber;
use mempool::FeeRate;
use output_cache::OrderData;
use serialization::hex_encoded::HexEncoded;
use utils::ensure;
pub use utxo_selector::UtxoSelectorError;
use wallet_types::account_id::AccountPrefixedId;
use wallet_types::account_info::{StandaloneAddressDetails, StandaloneAddresses};
use wallet_types::partially_signed_transaction::{PartiallySignedTransaction, TxAdditionalInfo};
use wallet_types::with_locked::WithLocked;

use crate::account::utxo_selector::{select_coins, OutputGroup};
use crate::destination_getters::{get_tx_output_destination, HtlcSpendingCondition};
use crate::key_chain::{AccountKeyChains, KeyChainError, VRFAccountKeyChains};
use crate::send_request::{
    make_address_output, make_address_output_from_delegation, make_address_output_token,
    make_decommission_stake_pool_output, make_mint_token_outputs, make_stake_output,
    make_unmint_token_outputs, IssueNftArguments, SelectedInputs, StakePoolCreationArguments,
    StakePoolCreationResolvedArguments,
};
use crate::wallet::WalletPoolsFilter;
use crate::wallet_events::{WalletEvents, WalletEventsNoOp};
use crate::{SendRequest, WalletError, WalletResult};
use common::address::{Address, RpcAddress};
use common::chain::output_value::{OutputValue, RpcOutputValue};
use common::chain::tokens::{
    make_token_id, IsTokenUnfreezable, NftIssuance, NftIssuanceV0, RPCFungibleTokenInfo, TokenId,
    TokenIssuance,
};
use common::chain::{
    AccountNonce, Block, ChainConfig, DelegationId, Destination, GenBlock, PoolId,
    SignedTransaction, Transaction, TxInput, TxOutput, UtxoOutPoint,
};
use common::primitives::{Amount, BlockHeight, Id};
use consensus::PoSGenerateBlockInputData;
use crypto::key::hdkd::u31::U31;
use crypto::key::{PrivateKey, PublicKey};
use crypto::vrf::VRFPublicKey;
use itertools::{izip, Itertools};
use std::cmp::Reverse;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Add, Sub};
use std::sync::Arc;
use wallet_storage::{
    StoreTxRw, WalletStorageReadLocked, WalletStorageReadUnlocked, WalletStorageWriteLocked,
    WalletStorageWriteUnlocked,
};
use wallet_types::utxo_types::{get_utxo_type, UtxoState, UtxoStates, UtxoType, UtxoTypes};
use wallet_types::wallet_tx::{BlockData, TxData, TxState};
use wallet_types::{
    AccountId, AccountInfo, AccountWalletCreatedTxId, AccountWalletTxId, BlockInfo, Currency,
    KeyPurpose, KeychainUsageState, WalletTx,
};

pub use self::output_cache::{
    DelegationData, OwnFungibleTokenInfo, PoolData, TxInfo, UnconfirmedTokenInfo, UtxoWithTxOutput,
};
use self::output_cache::{OutputCache, TokenIssuanceData};
use self::transaction_list::{get_transaction_list, TransactionList};
use self::utxo_selector::PayFee;

pub use self::utxo_selector::CoinSelectionAlgo;

pub struct CurrentFeeRate {
    pub current_fee_rate: FeeRate,
    pub consolidate_fee_rate: FeeRate,
}

pub enum TransactionToSign {
    Tx(Transaction),
    Partial(PartiallySignedTransaction),
}

impl TransactionToSign {
    pub fn to_hex(self) -> String {
        match self {
            Self::Tx(tx) => HexEncoded::new(tx).to_string(),
            Self::Partial(tx) => HexEncoded::new(tx).to_string(),
        }
    }
}

pub struct Account<K> {
    chain_config: Arc<ChainConfig>,
    key_chain: K,
    output_cache: OutputCache,
    account_info: AccountInfo,
}

impl<K: AccountKeyChains> Account<K> {
    /// Create a new account by providing a key chain
    pub fn new(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut impl WalletStorageWriteLocked,
        key_chain: K,
        name: Option<String>,
    ) -> WalletResult<Self> {
        let account_id = key_chain.get_account_id();

        let account_info = AccountInfo::new(
            &chain_config,
            key_chain.account_index(),
            key_chain.account_public_key().clone(),
            key_chain.lookahead_size(),
            name,
        );

        db_tx.set_account(&account_id, &account_info)?;
        db_tx.set_account_unconfirmed_tx_counter(&account_id, 0)?;

        let output_cache = OutputCache::empty();

        let mut account = Account {
            chain_config,
            key_chain,
            output_cache,
            account_info,
        };

        account.scan_genesis(db_tx, &WalletEventsNoOp)?;

        Ok(account)
    }

    pub fn load_from_database(
        chain_config: Arc<ChainConfig>,
        db_tx: &impl WalletStorageReadLocked,
        id: &AccountId,
    ) -> WalletResult<Self> {
        let mut account_infos = db_tx.get_accounts_info()?;
        let account_info =
            account_infos.remove(id).ok_or(KeyChainError::NoAccountFound(id.clone()))?;

        let key_chain = K::load_from_database(chain_config.clone(), db_tx, id, &account_info)?;

        let txs = db_tx.get_transactions(&key_chain.get_account_id())?;
        let output_cache = OutputCache::new(txs)?;

        Ok(Account {
            chain_config,
            key_chain,
            output_cache,
            account_info,
        })
    }

    pub fn key_chain(&self) -> &K {
        &self.key_chain
    }

    pub fn find_used_tokens(
        &self,
        input_utxos: &[UtxoOutPoint],
        median_time: BlockTimestamp,
    ) -> WalletResult<BTreeSet<TokenId>> {
        let current_block_info = BlockInfo {
            height: self.account_info.best_block_height(),
            timestamp: median_time,
        };
        self.output_cache.find_used_tokens(current_block_info, input_utxos)
    }

    // Note: the default selection algo depends on whether input_utxos are empty.
    #[allow(clippy::too_many_arguments)]
    fn select_inputs_for_send_request(
        &mut self,
        request: SendRequest,
        input_utxos: SelectedInputs,
        selection_algo: Option<CoinSelectionAlgo>,
        change_addresses: BTreeMap<Currency, Address<Destination>>,
        db_tx: &mut impl WalletStorageWriteLocked,
        median_time: BlockTimestamp,
        fee_rates: CurrentFeeRate,
        order_info: Option<BTreeMap<OrderId, &RpcOrderInfo>>,
    ) -> WalletResult<SendRequest> {
        // TODO: allow to pay fees with different currency?
        let pay_fee_with_currency = Currency::Coin;

        let mut preselected_inputs = group_preselected_inputs(
            &request,
            fee_rates.current_fee_rate,
            &self.chain_config,
            self.account_info.best_block_height(),
            Some(self),
            order_info,
        )?;

        let mut output_currency_amounts = currency_grouper::group_outputs_with_issuance_fee(
            request.outputs().iter(),
            |&output| output,
            |grouped: &mut Amount, _, new_amount| -> WalletResult<()> {
                *grouped = grouped.add(new_amount).ok_or(WalletError::OutputAmountOverflow)?;
                Ok(())
            },
            Amount::ZERO,
            &self.chain_config,
            self.account_info.best_block_height(),
        )?;

        // update output currency amount with burn requirements of preselected inputs
        preselected_inputs
            .iter()
            .filter_map(|(currency, input)| {
                (input.burn > Amount::ZERO).then_some((currency, input.burn))
            })
            .try_for_each(|(currency, burn)| -> WalletResult<()> {
                let entry = output_currency_amounts.entry(*currency).or_insert(Amount::ZERO);
                *entry = (*entry + burn).ok_or(WalletError::OutputAmountOverflow)?;
                Ok(())
            })?;

        let network_fee: Amount = fee_rates
            .current_fee_rate
            .compute_fee(tx_size_with_outputs(request.outputs()))
            .map_err(|_| UtxoSelectorError::AmountArithmeticError)?
            .into();

        let (utxos, selection_algo) = if input_utxos.is_empty() {
            (
                self.get_utxos(
                    UtxoType::Transfer | UtxoType::LockThenTransfer | UtxoType::IssueNft,
                    median_time,
                    UtxoState::Confirmed | UtxoState::InMempool | UtxoState::Inactive,
                    WithLocked::Unlocked,
                ),
                selection_algo.unwrap_or(CoinSelectionAlgo::Randomize),
            )
        } else {
            let selection_algo = selection_algo.unwrap_or(CoinSelectionAlgo::UsePreselected);
            match input_utxos {
                SelectedInputs::Utxos(input_utxos) => {
                    let current_block_info = BlockInfo {
                        height: self.account_info.best_block_height(),
                        timestamp: median_time,
                    };
                    (
                        self.output_cache.find_utxos(current_block_info, input_utxos)?,
                        selection_algo,
                    )
                }
                SelectedInputs::Inputs(ref inputs) => (
                    inputs.iter().map(|(outpoint, utxo)| (outpoint.clone(), utxo)).collect(),
                    selection_algo,
                ),
            }
        };

        let current_fee_rate = fee_rates.current_fee_rate;
        let mut utxos_by_currency =
            self.utxo_output_groups_by_currency(fee_rates, &pay_fee_with_currency, utxos)?;

        let amount_to_be_paid_in_currency_with_fees =
            output_currency_amounts.remove(&pay_fee_with_currency).unwrap_or(Amount::ZERO);

        let mut total_fees_not_paid = network_fee;

        let mut selected_inputs: BTreeMap<_, _> = output_currency_amounts
            .iter()
            .map(|(currency, output_amount)| -> WalletResult<_> {
                let utxos = utxos_by_currency.remove(currency).unwrap_or(vec![]);
                let (preselected_amount, preselected_fee) = preselected_inputs
                    .remove(currency)
                    .map_or((Amount::ZERO, Amount::ZERO), |inputs| {
                        (inputs.amount, inputs.fee)
                    });

                let (coin_change_fee, token_change_fee) = coin_and_token_output_change_fees(
                    current_fee_rate,
                    change_addresses.get(currency),
                )?;

                let cost_of_change = match currency {
                    Currency::Coin => coin_change_fee,
                    Currency::Token(_) => token_change_fee,
                };
                let selection_result = select_coins(
                    utxos,
                    output_amount.sub(preselected_amount).unwrap_or(Amount::ZERO),
                    PayFee::DoNotPayFeeWithThisCurrency,
                    // TODO: change this to cost_of_change calculated in this currency
                    // when we allow paying fees with different currency
                    Amount::ZERO,
                    selection_algo,
                )?;

                total_fees_not_paid = (total_fees_not_paid + selection_result.get_total_fees())
                    .ok_or(WalletError::OutputAmountOverflow)?;
                total_fees_not_paid = (total_fees_not_paid + preselected_fee)
                    .ok_or(WalletError::OutputAmountOverflow)?;

                let preselected_change =
                    (preselected_amount - *output_amount).unwrap_or(Amount::ZERO);
                let selection_result = selection_result.add_change(preselected_change)?;
                let change_amount = selection_result.get_change();
                if change_amount > Amount::ZERO {
                    total_fees_not_paid = (total_fees_not_paid + cost_of_change)
                        .ok_or(WalletError::OutputAmountOverflow)?;
                }

                Ok((*currency, selection_result))
            })
            .try_collect()?;

        let utxos = utxos_by_currency.remove(&pay_fee_with_currency).unwrap_or(vec![]);
        let (preselected_amount, preselected_fee) = preselected_inputs
            .remove(&pay_fee_with_currency)
            .map_or((Amount::ZERO, Amount::ZERO), |inputs| {
                (inputs.amount, inputs.fee)
            });

        total_fees_not_paid =
            (total_fees_not_paid + preselected_fee).ok_or(WalletError::OutputAmountOverflow)?;
        total_fees_not_paid = preselected_inputs
            .values()
            .try_fold(total_fees_not_paid, |total, inputs| total + inputs.fee)
            .ok_or(WalletError::OutputAmountOverflow)?;

        let mut amount_to_be_paid_in_currency_with_fees = (amount_to_be_paid_in_currency_with_fees
            + total_fees_not_paid)
            .ok_or(WalletError::OutputAmountOverflow)?;

        let (coin_change_fee, token_change_fee) = coin_and_token_output_change_fees(
            current_fee_rate,
            change_addresses.get(&pay_fee_with_currency),
        )?;
        let cost_of_change = match pay_fee_with_currency {
            Currency::Coin => coin_change_fee,
            Currency::Token(_) => token_change_fee,
        };

        let selection_result = select_coins(
            utxos,
            (amount_to_be_paid_in_currency_with_fees - preselected_amount).unwrap_or(Amount::ZERO),
            PayFee::PayFeeWithThisCurrency,
            cost_of_change,
            selection_algo,
        )?;

        let selection_result = selection_result.add_change(
            (preselected_amount - amount_to_be_paid_in_currency_with_fees).unwrap_or(Amount::ZERO),
        )?;
        let change_amount = selection_result.get_change();
        if change_amount > Amount::ZERO {
            amount_to_be_paid_in_currency_with_fees = (amount_to_be_paid_in_currency_with_fees
                + cost_of_change)
                .ok_or(WalletError::OutputAmountOverflow)?;
        }

        output_currency_amounts.insert(
            pay_fee_with_currency,
            (amount_to_be_paid_in_currency_with_fees + selection_result.get_total_fees())
                .ok_or(WalletError::OutputAmountOverflow)?,
        );
        selected_inputs.insert(pay_fee_with_currency, selection_result);

        // Check outputs against inputs and create change
        self.check_outputs_and_add_change(
            &pay_fee_with_currency,
            output_currency_amounts,
            selected_inputs,
            change_addresses,
            db_tx,
            request,
        )
    }

    fn check_outputs_and_add_change(
        &mut self,
        pay_fee_with_currency: &Currency,
        output_currency_amounts: BTreeMap<Currency, Amount>,
        selected_inputs: BTreeMap<Currency, utxo_selector::SelectionResult>,
        mut change_addresses: BTreeMap<Currency, Address<Destination>>,
        db_tx: &mut impl WalletStorageWriteLocked,
        mut request: SendRequest,
    ) -> Result<SendRequest, WalletError> {
        for currency in output_currency_amounts.keys() {
            let currency_result = selected_inputs.get(currency);
            let change_amount = currency_result.map_or(Amount::ZERO, |result| result.get_change());
            let fees = currency_result.map_or(Amount::ZERO, |result| result.get_total_fees());

            if fees > Amount::ZERO {
                request.add_fee(*pay_fee_with_currency, fees)?;
            }

            if change_amount > Amount::ZERO {
                let change_address = if let Some(change_address) = change_addresses.remove(currency)
                {
                    change_address
                } else {
                    self.key_chain.next_unused_address(db_tx, KeyPurpose::Change)?.1
                };

                let change_output = match currency {
                    Currency::Coin => make_address_output(change_address, change_amount),
                    Currency::Token(token_id) => {
                        make_address_output_token(change_address, change_amount, *token_id)
                    }
                };
                request = request.with_outputs([change_output]);
            }
        }

        let selected_inputs = selected_inputs.into_iter().flat_map(|x| x.1.into_output_pairs());

        let pool_data_getter = |pool_id: &PoolId| self.output_cache.pool_data(*pool_id).ok();
        request.with_inputs(selected_inputs, &pool_data_getter)
    }

    fn utxo_output_groups_by_currency(
        &self,
        fee_rates: CurrentFeeRate,
        pay_fee_with_currency: &Currency,
        utxos: Vec<(UtxoOutPoint, &TxOutput)>,
    ) -> Result<BTreeMap<Currency, Vec<OutputGroup>>, WalletError> {
        let utxo_to_output_group =
            |(outpoint, txo): (UtxoOutPoint, TxOutput)| -> WalletResult<OutputGroup> {
                let tx_input: TxInput = outpoint.into();
                let input_size = serialization::Encode::encoded_size(&tx_input);

                let inp_sig_size = input_signature_size(&txo, Some(self))?;

                let fee = fee_rates
                    .current_fee_rate
                    .compute_fee(input_size + inp_sig_size)
                    .map_err(|_| UtxoSelectorError::AmountArithmeticError)?;
                let consolidate_fee = fee_rates
                    .consolidate_fee_rate
                    .compute_fee(input_size + inp_sig_size)
                    .map_err(|_| UtxoSelectorError::AmountArithmeticError)?;

                // TODO-#1120: calculate weight from the size of the input
                let weight = 0;
                let out_group =
                    OutputGroup::new((tx_input, txo), fee.into(), consolidate_fee.into(), weight)?;

                Ok(out_group)
            };

        currency_grouper::group_utxos_for_input(
            utxos.into_iter(),
            |(_, tx_output)| tx_output,
            |grouped: &mut Vec<(UtxoOutPoint, TxOutput)>, element, _| -> WalletResult<()> {
                grouped.push((element.0.clone(), element.1.clone()));
                Ok(())
            },
            vec![],
        )?
        .into_iter()
        .map(
            |(currency, utxos)| -> WalletResult<(Currency, Vec<OutputGroup>)> {
                let utxo_groups = utxos
                    .into_iter()
                    // TODO: group outputs by destination
                    .map(utxo_to_output_group)
                    .filter(|group| {
                        group.as_ref().map_or(true, |group| {
                            currency != *pay_fee_with_currency || group.value > group.fee
                        })
                    })
                    .try_collect()?;

                Ok((currency, utxo_groups))
            },
        )
        .try_collect()
    }

    pub fn sweep_addresses(
        &mut self,
        destination: Destination,
        request: SendRequest,
        current_fee_rate: FeeRate,
    ) -> WalletResult<SendRequest> {
        let mut grouped_inputs = group_preselected_inputs(
            &request,
            current_fee_rate,
            &self.chain_config,
            self.account_info.best_block_height(),
            Some(self),
            None,
        )?;

        let input_fees = grouped_inputs
            .values()
            .map(|input_amounts| input_amounts.fee)
            .sum::<Option<Amount>>()
            .ok_or(WalletError::OutputAmountOverflow)?;

        let coin_input = grouped_inputs.remove(&Currency::Coin).ok_or(WalletError::NoUtxos)?;

        let mut outputs = grouped_inputs
            .into_iter()
            .filter_map(|(currency, input_amounts)| {
                let value = match currency {
                    Currency::Coin => return None,
                    Currency::Token(token_id) => {
                        OutputValue::TokenV1(token_id, input_amounts.amount)
                    }
                };

                Some(TxOutput::Transfer(value, destination.clone()))
            })
            .collect::<Vec<_>>();

        let coin_output = TxOutput::Transfer(
            OutputValue::Coin(
                (coin_input.amount - input_fees)
                    .ok_or(WalletError::NotEnoughUtxo(coin_input.amount, input_fees))?,
            ),
            destination.clone(),
        );

        outputs.push(coin_output);
        let tx_fee: Amount = current_fee_rate
            .compute_fee(tx_size_with_outputs(outputs.as_slice()))
            .map_err(|_| UtxoSelectorError::AmountArithmeticError)?
            .into();
        outputs.pop();

        let total_fee = (tx_fee + input_fees).ok_or(WalletError::OutputAmountOverflow)?;

        let coin_output = TxOutput::Transfer(
            OutputValue::Coin(
                (coin_input.amount - total_fee)
                    .ok_or(WalletError::NotEnoughUtxo(coin_input.amount, input_fees))?,
            ),
            destination,
        );
        outputs.push(coin_output);

        Ok(request.with_outputs(outputs))
    }

    pub fn sweep_delegation(
        &mut self,
        address: Address<Destination>,
        delegation_id: DelegationId,
        delegation_share: Amount,
        current_fee_rate: FeeRate,
    ) -> WalletResult<SendRequest> {
        let current_block_height = self.best_block().1;
        let output = make_address_output_from_delegation(
            self.chain_config.as_ref(),
            address.clone(),
            delegation_share,
            current_block_height,
        );
        let delegation_data = self.find_delegation(&delegation_id)?;
        let nonce = delegation_data
            .last_nonce
            .map_or(Some(AccountNonce::new(0)), |nonce| nonce.increment())
            .ok_or(WalletError::DelegationNonceOverflow(delegation_id))?;

        let outputs = vec![output];

        let tx_input = TxInput::Account(AccountOutPoint::new(
            nonce,
            AccountSpending::DelegationBalance(delegation_id, delegation_share),
        ));
        let input_size = serialization::Encode::encoded_size(&tx_input);
        let total_fee: Amount = current_fee_rate
            .compute_fee(
                tx_size_with_outputs(outputs.as_slice())
                    + input_size
                    + input_signature_size_from_destination(
                        &delegation_data.destination,
                        Some(self),
                    )?,
            )
            .map_err(|_| WalletError::OutputAmountOverflow)?
            .into();

        let amount = (delegation_share - total_fee).ok_or(UtxoSelectorError::NotEnoughFunds(
            delegation_share,
            total_fee,
        ))?;

        let output = make_address_output_from_delegation(
            self.chain_config.as_ref(),
            address,
            amount,
            current_block_height,
        );

        let mut req = SendRequest::new()
            .with_inputs_and_destinations([(tx_input, delegation_data.destination.clone())])
            .with_outputs([output]);
        req.add_fee(Currency::Coin, total_fee)?;

        Ok(req)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_send_request(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        request: SendRequest,
        inputs: SelectedInputs,
        selection_algo: Option<CoinSelectionAlgo>,
        change_addresses: BTreeMap<Currency, Address<Destination>>,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
        additional_info: TxAdditionalInfo,
    ) -> WalletResult<(PartiallySignedTransaction, BTreeMap<Currency, Amount>)> {
        let mut request = self.select_inputs_for_send_request(
            request,
            inputs,
            selection_algo,
            change_addresses,
            db_tx,
            median_time,
            fee_rate,
            None,
        )?;

        let fees = request.get_fees();
        let ptx = request.into_partially_signed_tx(additional_info)?;

        Ok((ptx, fees))
    }

    pub fn process_send_request_and_sign(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        request: SendRequest,
        inputs: SelectedInputs,
        change_addresses: BTreeMap<Currency, Address<Destination>>,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SendRequest> {
        self.select_inputs_for_send_request(
            request,
            inputs,
            None,
            change_addresses,
            db_tx,
            median_time,
            fee_rate,
            None,
        )
        // TODO: Randomize inputs and outputs
    }

    fn decommission_stake_pool_impl(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        pool_id: PoolId,
        pool_balance: Amount,
        output_address: Option<Destination>,
        current_fee_rate: FeeRate,
    ) -> WalletResult<SendRequest> {
        let output_destination = if let Some(dest) = output_address {
            dest
        } else {
            self.get_new_address(db_tx, KeyPurpose::ReceiveFunds)?.1.into_object()
        };

        let pool_data = self.output_cache.pool_data(pool_id)?;
        let best_block_height = self.best_block().1;
        let tx_input = TxInput::Utxo(pool_data.utxo_outpoint.clone());

        let network_fee: Amount = {
            let output = make_decommission_stake_pool_output(
                self.chain_config.as_ref(),
                output_destination.clone(),
                pool_balance,
                best_block_height,
            )?;
            let outputs = vec![output];

            current_fee_rate
                .compute_fee(
                    tx_size_with_outputs(outputs.as_slice())
                        + input_signature_size_from_destination(
                            &pool_data.decommission_key,
                            Some(self),
                        )?
                        + serialization::Encode::encoded_size(&tx_input),
                )
                .map_err(|_| UtxoSelectorError::AmountArithmeticError)?
                .into()
        };

        let output = make_decommission_stake_pool_output(
            self.chain_config.as_ref(),
            output_destination,
            (pool_balance - network_fee)
                .ok_or(WalletError::NotEnoughUtxo(network_fee, pool_balance))?,
            best_block_height,
        )?;

        let input_utxo = self
            .output_cache
            .get_txo(&pool_data.utxo_outpoint)
            .ok_or(WalletError::NoUtxos)?;

        let mut req = SendRequest::new()
            .with_inputs([(tx_input, input_utxo.clone())], &|id| {
                (*id == pool_id).then_some(pool_data)
            })?
            .with_outputs([output]);
        req.add_fee(Currency::Coin, network_fee)?;

        Ok(req)
    }

    pub fn decommission_stake_pool(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        pool_id: PoolId,
        pool_balance: Amount,
        output_address: Option<Destination>,
        current_fee_rate: FeeRate,
    ) -> WalletResult<SendRequest> {
        self.decommission_stake_pool_impl(
            db_tx,
            pool_id,
            pool_balance,
            output_address,
            current_fee_rate,
        )
    }

    pub fn decommission_stake_pool_request(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        pool_id: PoolId,
        pool_balance: Amount,
        output_address: Option<Destination>,
        current_fee_rate: FeeRate,
    ) -> WalletResult<SendRequest> {
        self.decommission_stake_pool_impl(
            db_tx,
            pool_id,
            pool_balance,
            output_address,
            current_fee_rate,
        )
    }

    pub fn spend_from_delegation(
        &mut self,
        address: Address<Destination>,
        amount: Amount,
        delegation_id: DelegationId,
        delegation_share: Amount,
        current_fee_rate: FeeRate,
    ) -> WalletResult<SendRequest> {
        let current_block_height = self.best_block().1;
        let output = make_address_output_from_delegation(
            self.chain_config.as_ref(),
            address,
            amount,
            current_block_height,
        );
        let delegation_data = self.find_delegation(&delegation_id)?;
        let nonce = delegation_data
            .last_nonce
            .map_or(Some(AccountNonce::new(0)), |nonce| nonce.increment())
            .ok_or(WalletError::DelegationNonceOverflow(delegation_id))?;

        let outputs = vec![output];
        let network_fee: Amount = current_fee_rate
            .compute_fee(
                tx_size_with_outputs(outputs.as_slice())
                    + input_signature_size_from_destination(
                        &delegation_data.destination,
                        Some(self),
                    )?,
            )
            .map_err(|_| UtxoSelectorError::AmountArithmeticError)?
            .into();

        let amount_with_fee = (amount + network_fee).ok_or(WalletError::OutputAmountOverflow)?;
        let mut tx_input = TxInput::Account(AccountOutPoint::new(
            nonce,
            AccountSpending::DelegationBalance(delegation_id, amount_with_fee),
        ));
        // as the input size depends on the amount we specify the fee will also change a bit so
        // loop until it converges.
        let mut input_size = serialization::Encode::encoded_size(&tx_input);
        let mut total_fee;
        loop {
            total_fee = current_fee_rate
                .compute_fee(input_size)
                .map_err(|_| UtxoSelectorError::AmountArithmeticError)?
                .into();

            let new_amount_with_fee =
                (amount_with_fee + total_fee).ok_or(WalletError::OutputAmountOverflow)?;
            ensure!(
                new_amount_with_fee <= delegation_share,
                UtxoSelectorError::NotEnoughFunds(delegation_share, new_amount_with_fee)
            );

            tx_input = TxInput::Account(AccountOutPoint::new(
                nonce,
                AccountSpending::DelegationBalance(delegation_id, new_amount_with_fee),
            ));

            let new_input_size = serialization::Encode::encoded_size(&tx_input);
            if new_input_size == input_size {
                break;
            }
            input_size = new_input_size;
        }

        let mut req = SendRequest::new()
            .with_inputs_and_destinations([(tx_input, delegation_data.destination.clone())])
            .with_outputs(outputs);
        req.add_fee(Currency::Coin, total_fee)?;
        Ok(req)
    }

    pub fn get_pool_ids(&self, filter: WalletPoolsFilter) -> Vec<(PoolId, PoolData)> {
        self.output_cache
            .pool_ids()
            .into_iter()
            .filter(|(_, pool_data)| match filter {
                WalletPoolsFilter::All => true,
                // FIXME for standalone private keys
                WalletPoolsFilter::Decommission => {
                    self.key_chain.is_destination_mine(&pool_data.decommission_key)
                }
                WalletPoolsFilter::Stake => {
                    self.key_chain.is_destination_mine(&pool_data.stake_destination)
                }
            })
            .collect()
    }

    pub fn get_delegations(&self) -> impl Iterator<Item = (&DelegationId, &DelegationData)> {
        self.output_cache
            .delegation_ids()
            .filter(|(_, data)| self.is_destination_mine(&data.destination))
    }

    pub fn find_delegation(&self, delegation_id: &DelegationId) -> WalletResult<&DelegationData> {
        self.output_cache
            .delegation_data(delegation_id)
            .filter(|data| self.is_destination_mine(&data.destination))
            .ok_or(WalletError::DelegationNotFound(*delegation_id))
    }

    pub fn find_token(&self, token_id: &TokenId) -> WalletResult<&TokenIssuanceData> {
        self.output_cache
            .token_data(token_id)
            .filter(|data| self.is_destination_mine(&data.authority))
            .ok_or(WalletError::UnknownTokenId(*token_id))
    }

    pub fn find_order(&self, order_id: &OrderId) -> WalletResult<&OrderData> {
        self.output_cache
            .order_data(order_id)
            .filter(|data| self.is_destination_mine(&data.conclude_key))
            .ok_or(WalletError::UnknownOrderId(*order_id))
    }

    pub fn get_token_unconfirmed_info(
        &self,
        token_info: RPCFungibleTokenInfo,
    ) -> WalletResult<UnconfirmedTokenInfo> {
        self.output_cache
            .get_token_unconfirmed_info(token_info, |destination: &Destination| {
                self.is_destination_mine(destination)
            })
    }

    pub fn create_htlc_tx(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        output_value: OutputValue,
        htlc: HashedTimelockContract,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SendRequest> {
        let output = TxOutput::Htlc(output_value, Box::new(htlc));
        let request = SendRequest::new().with_outputs([output]);

        self.select_inputs_for_send_request(
            request,
            SelectedInputs::Utxos(vec![]),
            None,
            BTreeMap::new(),
            db_tx,
            median_time,
            fee_rate,
            None,
        )
    }

    pub fn create_order_tx(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        ask_value: OutputValue,
        give_value: OutputValue,
        conclude_address: Address<Destination>,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SendRequest> {
        let order_data =
            common::chain::OrderData::new(conclude_address.into_object(), ask_value, give_value);
        let output = TxOutput::CreateOrder(Box::new(order_data));
        let request = SendRequest::new().with_outputs([output]);

        self.select_inputs_for_send_request(
            request,
            SelectedInputs::Utxos(vec![]),
            None,
            BTreeMap::new(),
            db_tx,
            median_time,
            fee_rate,
            None,
        )
    }

    pub fn create_conclude_order_tx(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        order_id: OrderId,
        order_info: RpcOrderInfo,
        output_address: Option<Destination>,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SendRequest> {
        let output_destination = if let Some(dest) = output_address {
            dest
        } else {
            self.get_new_address(db_tx, KeyPurpose::ReceiveFunds)?.1.into_object()
        };

        let mut outputs = vec![];

        if order_info.give_balance > Amount::ZERO {
            let given_currency = Currency::from_rpc_output_value(&order_info.initially_given);
            let output_value = given_currency.into_output_value(order_info.give_balance);
            outputs.push(TxOutput::Transfer(output_value, output_destination.clone()));
        }

        let filled_amount = (order_info.initially_asked.amount() - order_info.ask_balance)
            .ok_or(WalletError::OutputAmountOverflow)?;
        if filled_amount > Amount::ZERO {
            let asked_currency = Currency::from_rpc_output_value(&order_info.initially_asked);
            let output_value = asked_currency.into_output_value(filled_amount);
            outputs.push(TxOutput::Transfer(output_value, output_destination));
        }

        let nonce = order_info
            .nonce
            .map_or(Some(AccountNonce::new(0)), |n| n.increment())
            .ok_or(WalletError::OrderNonceOverflow(order_id))?;
        let request = SendRequest::new().with_outputs(outputs).with_inputs_and_destinations([(
            TxInput::AccountCommand(nonce, AccountCommand::ConcludeOrder(order_id)),
            order_info.conclude_key.clone(),
        )]);

        self.select_inputs_for_send_request(
            request,
            SelectedInputs::Utxos(vec![]),
            None,
            BTreeMap::new(),
            db_tx,
            median_time,
            fee_rate,
            Some(BTreeMap::from_iter([(order_id, &order_info)])),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_fill_order_tx(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        order_id: OrderId,
        order_info: RpcOrderInfo,
        fill_amount_in_ask_currency: Amount,
        output_address: Option<Destination>,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SendRequest> {
        let output_destination = if let Some(dest) = output_address {
            dest
        } else {
            self.get_new_address(db_tx, KeyPurpose::ReceiveFunds)?.1.into_object()
        };

        let filled_amount = orders_accounting::calculate_filled_amount(
            order_info.ask_balance,
            order_info.give_balance,
            fill_amount_in_ask_currency,
        )
        .ok_or(WalletError::CalculateOrderFilledAmountFailed(order_id))?;
        let output_value = match order_info.initially_given {
            RpcOutputValue::Coin { .. } => OutputValue::Coin(filled_amount),
            RpcOutputValue::Token { id, .. } => OutputValue::TokenV1(id, filled_amount),
        };
        let outputs = vec![TxOutput::Transfer(output_value, output_destination.clone())];

        let nonce = order_info
            .nonce
            .map_or(Some(AccountNonce::new(0)), |n| n.increment())
            .ok_or(WalletError::OrderNonceOverflow(order_id))?;
        let request = SendRequest::new().with_outputs(outputs).with_inputs_and_destinations([(
            TxInput::AccountCommand(
                nonce,
                AccountCommand::FillOrder(
                    order_id,
                    fill_amount_in_ask_currency,
                    output_destination.clone(),
                ),
            ),
            output_destination,
        )]);

        self.select_inputs_for_send_request(
            request,
            SelectedInputs::Utxos(vec![]),
            None,
            BTreeMap::new(),
            db_tx,
            median_time,
            fee_rate,
            Some(BTreeMap::from_iter([(order_id, &order_info)])),
        )
    }

    pub fn create_issue_nft_tx(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        nft_issue_arguments: IssueNftArguments,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SendRequest> {
        let nft_issuance = NftIssuanceV0 {
            metadata: nft_issue_arguments.metadata,
        };
        tx_verifier::check_nft_issuance_data(&self.chain_config, &nft_issuance)?;

        // the first UTXO is needed in advance to issue a new nft, so just make a dummy one
        // and then replace it with when we can calculate the pool_id
        let dummy_token_id = TokenId::new(H256::zero());
        let dummy_issuance_output = TxOutput::IssueNft(
            dummy_token_id,
            Box::new(NftIssuance::V0(nft_issuance)),
            nft_issue_arguments.destination,
        );

        let request = SendRequest::new().with_outputs([dummy_issuance_output]);
        let mut request = self.select_inputs_for_send_request(
            request,
            SelectedInputs::Utxos(vec![]),
            None,
            BTreeMap::new(),
            db_tx,
            median_time,
            fee_rate,
            None,
        )?;

        let new_token_id = make_token_id(request.inputs()).ok_or(WalletError::NoUtxos)?;

        // update the dummy_token_id with the new_token_id
        let old_token_id = request
            .get_outputs_mut()
            .iter_mut()
            .find_map(|output| match output {
                TxOutput::CreateStakePool(_, _)
                | TxOutput::Burn(_)
                | TxOutput::Transfer(_, _)
                | TxOutput::DelegateStaking(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::IssueFungibleToken(_)
                | TxOutput::DataDeposit(_)
                | TxOutput::Htlc(_, _)
                | TxOutput::CreateOrder(_) => None,
                TxOutput::IssueNft(token_id, _, _) => {
                    (*token_id == dummy_token_id).then_some(token_id)
                }
            })
            .expect("find output with dummy_token_id");
        *old_token_id = new_token_id;

        Ok(request)
    }

    pub fn mint_tokens(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        token_info: &UnconfirmedTokenInfo,
        address: Address<Destination>,
        amount: Amount,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SendRequest> {
        let token_id = token_info.token_id();
        let outputs = make_mint_token_outputs(token_id, amount, address);

        token_info.check_can_mint(amount)?;

        let nonce = token_info.get_next_nonce()?;
        let tx_input = TxInput::AccountCommand(nonce, AccountCommand::MintTokens(token_id, amount));
        let authority = token_info.authority()?.clone();

        self.change_token_supply_transaction(
            authority,
            tx_input,
            outputs,
            db_tx,
            median_time,
            fee_rate,
        )
    }

    pub fn unmint_tokens(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        token_info: &UnconfirmedTokenInfo,
        amount: Amount,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SendRequest> {
        let token_id = token_info.token_id();
        let outputs = make_unmint_token_outputs(token_id, amount);

        token_info.check_can_unmint(amount)?;

        let nonce = token_info.get_next_nonce()?;
        let tx_input = TxInput::AccountCommand(nonce, AccountCommand::UnmintTokens(token_id));
        let authority = token_info.authority()?.clone();

        self.change_token_supply_transaction(
            authority,
            tx_input,
            outputs,
            db_tx,
            median_time,
            fee_rate,
        )
    }

    pub fn lock_token_supply(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        token_info: &UnconfirmedTokenInfo,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SendRequest> {
        let token_id = token_info.token_id();
        token_info.check_can_lock()?;

        let nonce = token_info.get_next_nonce()?;
        let tx_input = TxInput::AccountCommand(nonce, AccountCommand::LockTokenSupply(token_id));
        let authority = token_info.authority()?.clone();

        self.change_token_supply_transaction(
            authority,
            tx_input,
            vec![],
            db_tx,
            median_time,
            fee_rate,
        )
    }

    pub fn freeze_token(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        token_info: &UnconfirmedTokenInfo,
        is_token_unfreezable: IsTokenUnfreezable,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SendRequest> {
        token_info.check_can_freeze()?;

        let nonce = token_info.get_next_nonce()?;
        let tx_input = TxInput::AccountCommand(
            nonce,
            AccountCommand::FreezeToken(token_info.token_id(), is_token_unfreezable),
        );
        let authority = token_info.authority()?.clone();

        self.change_token_supply_transaction(
            authority,
            tx_input,
            vec![],
            db_tx,
            median_time,
            fee_rate,
        )
    }

    pub fn unfreeze_token(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        token_info: &UnconfirmedTokenInfo,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SendRequest> {
        token_info.check_can_unfreeze()?;

        let nonce = token_info.get_next_nonce()?;
        let tx_input =
            TxInput::AccountCommand(nonce, AccountCommand::UnfreezeToken(token_info.token_id()));
        let authority = token_info.authority()?.clone();

        self.change_token_supply_transaction(
            authority,
            tx_input,
            vec![],
            db_tx,
            median_time,
            fee_rate,
        )
    }

    pub fn change_token_authority(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        token_info: &UnconfirmedTokenInfo,
        address: Address<Destination>,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SendRequest> {
        let new_authority = address.into_object();

        let nonce = token_info.get_next_nonce()?;
        let tx_input = TxInput::AccountCommand(
            nonce,
            AccountCommand::ChangeTokenAuthority(token_info.token_id(), new_authority),
        );
        let authority = token_info.authority()?.clone();

        self.change_token_supply_transaction(
            authority,
            tx_input,
            vec![],
            db_tx,
            median_time,
            fee_rate,
        )
    }

    pub fn change_token_metadata_uri(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        token_info: &UnconfirmedTokenInfo,
        metadata_uri: Vec<u8>,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SendRequest> {
        let nonce = token_info.get_next_nonce()?;
        let tx_input = TxInput::AccountCommand(
            nonce,
            AccountCommand::ChangeTokenMetadataUri(token_info.token_id(), metadata_uri),
        );
        let authority = token_info.authority()?.clone();

        self.change_token_supply_transaction(
            authority,
            tx_input,
            vec![],
            db_tx,
            median_time,
            fee_rate,
        )
    }

    fn change_token_supply_transaction(
        &mut self,
        authority: Destination,
        tx_input: TxInput,
        outputs: Vec<TxOutput>,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> Result<SendRequest, WalletError> {
        let request = SendRequest::new()
            .with_outputs(outputs)
            .with_inputs_and_destinations([(tx_input, authority)]);

        self.select_inputs_for_send_request(
            request,
            SelectedInputs::Utxos(vec![]),
            None,
            BTreeMap::new(),
            db_tx,
            median_time,
            fee_rate,
            None,
        )
    }

    pub fn pool_exists(&self, pool_id: PoolId) -> bool {
        self.output_cache.pool_data(pool_id).is_ok()
    }

    pub fn find_account_destination(
        &self,
        acc_outpoint: &AccountOutPoint,
    ) -> WalletResult<Destination> {
        match acc_outpoint.account() {
            AccountSpending::DelegationBalance(delegation_id, _) => self
                .output_cache
                .delegation_data(delegation_id)
                .map(|data| data.destination.clone())
                .ok_or(WalletError::DelegationNotFound(*delegation_id)),
        }
    }

    pub fn find_account_command_destination(
        &self,
        cmd: &AccountCommand,
    ) -> WalletResult<Destination> {
        match cmd {
            AccountCommand::MintTokens(token_id, _)
            | AccountCommand::UnmintTokens(token_id)
            | AccountCommand::LockTokenSupply(token_id)
            | AccountCommand::ChangeTokenAuthority(token_id, _)
            | AccountCommand::ChangeTokenMetadataUri(token_id, _)
            | AccountCommand::FreezeToken(token_id, _)
            | AccountCommand::UnfreezeToken(token_id) => self
                .output_cache
                .token_data(token_id)
                .map(|data| data.authority.clone())
                .ok_or(WalletError::UnknownTokenId(*token_id)),
            AccountCommand::ConcludeOrder(order_id) => self
                .output_cache
                .order_data(order_id)
                .map(|data| data.conclude_key.clone())
                .ok_or(WalletError::UnknownOrderId(*order_id)),
            AccountCommand::FillOrder(_, _, dest) => Ok(dest.clone()),
        }
    }

    pub fn find_unspent_utxo_with_destination(
        &self,
        outpoint: &UtxoOutPoint,
        current_block_info: BlockInfo,
    ) -> WalletResult<(TxOutput, Destination)> {
        let txo = self.output_cache.find_unspent_unlocked_utxo(outpoint, current_block_info)?;

        Ok((
            txo.clone(),
            get_tx_output_destination(
                txo,
                &|pool_id| self.output_cache.pool_data(*pool_id).ok(),
                HtlcSpendingCondition::Skip,
            )
            .ok_or(WalletError::InputCannotBeSpent(txo.clone()))?,
        ))
    }

    pub fn account_index(&self) -> U31 {
        self.key_chain.account_index()
    }

    /// Get the id of this account
    pub fn get_account_id(&self) -> AccountId {
        self.key_chain.get_account_id()
    }

    /// Reload the keys from the DB
    /// Used to reset the in-memory state after a failed operation
    pub fn reload_keys(&mut self, db_tx: &impl WalletStorageReadLocked) -> WalletResult<()> {
        self.key_chain.reload_keys(db_tx)?;
        Ok(())
    }

    /// Add, rename or delete a label for a standalone address
    pub fn standalone_address_label_rename(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        address: Destination,
        label: Option<String>,
    ) -> WalletResult<()> {
        Ok(self.key_chain.standalone_address_label_rename(db_tx, address, label)?)
    }

    /// Add a standalone address not derived from this account's key chain to be watched
    pub fn add_standalone_address(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        address: PublicKeyHash,
        label: Option<String>,
    ) -> WalletResult<()> {
        Ok(self.key_chain.add_standalone_watch_only_address(db_tx, address, label)?)
    }

    /// Add a standalone private key not derived from this account's key chain to be watched
    pub fn add_standalone_private_key(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        private_key: PrivateKey,
        label: Option<String>,
    ) -> WalletResult<()> {
        Ok(self.key_chain.add_standalone_private_key(db_tx, private_key, label)?)
    }

    /// Add a standalone multisig address to be watched
    pub fn add_standalone_multisig(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        challenge: ClassicMultisigChallenge,
        label: Option<String>,
    ) -> WalletResult<PublicKeyHash> {
        Ok(self.key_chain.add_standalone_multisig(db_tx, challenge, label)?)
    }

    /// Get a new address that hasn't been used before
    pub fn get_new_address(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        purpose: KeyPurpose,
    ) -> WalletResult<(ChildNumber, Address<Destination>)> {
        Ok(self.key_chain.issue_address(db_tx, purpose)?)
    }

    /// Get the corresponding public key for a given public key hash
    pub fn find_corresponding_pub_key(
        &self,
        public_key_hash: &PublicKeyHash,
    ) -> WalletResult<PublicKey> {
        self.key_chain
            .get_public_key_from_public_key_hash(public_key_hash)
            .ok_or(WalletError::AddressNotFound)
    }

    pub fn get_all_issued_addresses(&self) -> BTreeMap<ChildNumber, Address<Destination>> {
        self.key_chain.get_all_issued_addresses()
    }

    pub fn get_all_standalone_addresses(&self) -> StandaloneAddresses {
        self.key_chain.get_all_standalone_addresses()
    }

    pub fn get_all_standalone_address_details(
        &self,
        address: Destination,
        median_time: BlockTimestamp,
    ) -> WalletResult<(
        Destination,
        BTreeMap<Currency, Amount>,
        StandaloneAddressDetails,
    )> {
        let (address, standalone_key) = self
            .key_chain
            .get_all_standalone_address_details(address.clone())
            .ok_or_else(|| {
                let addr = RpcAddress::new(&self.chain_config, address).expect("addressable");
                WalletError::StandaloneAddressNotFound(addr)
            })?;

        let current_block_info = BlockInfo {
            height: self.account_info.best_block_height(),
            timestamp: median_time,
        };
        let amounts_by_currency = currency_grouper::group_utxos_for_input(
            self.output_cache
                .utxos(
                    current_block_info,
                    UtxoState::Confirmed.into(),
                    WithLocked::Unlocked,
                    |txo| get_utxo_type(txo).is_some() && self.is_watched_by(txo, &address),
                )
                .into_iter(),
            |(_, tx_output)| tx_output,
            |total: &mut Amount, _, amount| -> WalletResult<()> {
                *total = (*total + amount).ok_or(WalletError::OutputAmountOverflow)?;
                Ok(())
            },
            Amount::ZERO,
        )?;

        Ok((address, amounts_by_currency, standalone_key))
    }

    pub fn get_addresses_usage(&self) -> &KeychainUsageState {
        self.key_chain.get_addresses_usage_state()
    }

    fn collect_output_destinations(&self, txo: &TxOutput) -> Vec<Destination> {
        match txo {
            TxOutput::Transfer(_, d)
            | TxOutput::LockThenTransfer(_, d, _)
            | TxOutput::CreateDelegationId(d, _)
            | TxOutput::IssueNft(_, _, d) => vec![d.clone()],
            | TxOutput::ProduceBlockFromStake(d, pool_id) => {
                let mut destinations = vec![d.clone()];
                if let Ok(pool_data) = self.output_cache.pool_data(*pool_id) {
                    destinations.push(pool_data.decommission_key.clone());
                }
                destinations
            }
            TxOutput::CreateStakePool(_, data) => {
                vec![data.decommission_key().clone(), data.staker().clone()]
            }
            TxOutput::Htlc(_, htlc) => vec![htlc.spend_key.clone(), htlc.refund_key.clone()],
            TxOutput::IssueFungibleToken(data) => match data.as_ref() {
                TokenIssuance::V1(data) => vec![data.authority.clone()],
            },
            TxOutput::DelegateStaking(_, delegation_id) => self
                .output_cache
                .delegation_data(delegation_id)
                .map_or(vec![], |data| vec![data.destination.clone()]),
            TxOutput::CreateOrder(data) => {
                vec![data.conclude_key().clone()]
            }
            TxOutput::Burn(_) | TxOutput::DataDeposit(_) => Vec::new(),
        }
    }

    /// Return true if this transaction output can be spent by this account
    fn is_mine(&self, txo: &TxOutput) -> bool {
        self.collect_output_destinations(txo)
            .iter()
            .any(|d| self.is_destination_mine(d))
    }

    /// Return true if this transaction output can be spent by this account or if it is being
    /// watched.
    fn is_mine_or_watched(&self, txo: &TxOutput) -> bool {
        self.collect_output_destinations(txo)
            .iter()
            .any(|d| self.is_destination_mine_or_watched(d))
    }

    /// Return true if this transaction output is a multisig that is being watched
    fn is_watched_multisig_output(&self, txo: &TxOutput) -> bool {
        self.collect_output_destinations(txo)
            .iter()
            .any(|destination| match destination {
                Destination::PublicKeyHash(_)
                | Destination::PublicKey(_)
                | Destination::AnyoneCanSpend
                | Destination::ScriptHash(_) => false,
                Destination::ClassicMultisig(_) => {
                    self.key_chain.get_multisig_challenge(destination).is_some()
                }
            })
    }

    /// Return true if this transaction output can be spent by this account
    fn is_watched_by(&self, txo: &TxOutput, watched_by: &Destination) -> bool {
        self.collect_output_destinations(txo).contains(watched_by)
    }

    /// Return true if this destination can be spent by this account
    fn is_destination_mine(&self, destination: &Destination) -> bool {
        match destination {
            Destination::PublicKeyHash(pkh) => self.key_chain.is_public_key_hash_mine(pkh),
            Destination::PublicKey(pk) => self.key_chain.is_public_key_mine(pk),
            Destination::AnyoneCanSpend => false,
            Destination::ScriptHash(_) | Destination::ClassicMultisig(_) => false,
        }
    }

    /// Return true if this destination can be spent by this account or if it is being watched.
    fn is_destination_mine_or_watched(&self, destination: &Destination) -> bool {
        match destination {
            Destination::PublicKeyHash(pkh) => {
                self.key_chain.is_public_key_hash_mine_or_watched(*pkh)
            }
            Destination::PublicKey(pk) => self.key_chain.is_public_key_mine(pk),
            Destination::AnyoneCanSpend => false,
            Destination::ScriptHash(_) => false,
            Destination::ClassicMultisig(_) => {
                self.key_chain.get_multisig_challenge(destination).is_some()
            }
        }
    }

    fn mark_outputs_as_seen(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        outputs: &[TxOutput],
    ) -> WalletResult<bool> {
        let mut found = false;
        // Process all outputs (without short-circuiting)
        for output in outputs {
            found |= self.mark_output_as_seen(db_tx, output)?;
        }
        Ok(found)
    }

    fn mark_output_as_seen(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        output: &TxOutput,
    ) -> WalletResult<bool> {
        self.mark_created_stake_pool_as_seen(output, db_tx)?;

        for destination in self.collect_output_destinations(output) {
            match destination {
                Destination::PublicKeyHash(pkh) => {
                    let found = self.key_chain.mark_public_key_hash_as_used(db_tx, &pkh)?;
                    if found || self.key_chain.is_public_key_hash_watched(pkh) {
                        return Ok(true);
                    }
                }
                Destination::PublicKey(pk) => {
                    let found = self.key_chain.mark_public_key_as_used(db_tx, &pk)?;
                    if found {
                        return Ok(true);
                    }
                }
                Destination::AnyoneCanSpend => return Ok(false),
                Destination::ClassicMultisig(_) => {
                    if self.key_chain.get_multisig_challenge(&destination).is_some() {
                        return Ok(true);
                    }
                }
                Destination::ScriptHash(_) => {}
            }
        }

        Ok(false)
    }

    /// check if the output is a CreateStakePool and check if the VRF key or decommission_key
    /// are tracked by this wallet and mark them as used
    fn mark_created_stake_pool_as_seen(
        &mut self,
        output: &TxOutput,
        db_tx: &mut impl WalletStorageWriteLocked,
    ) -> Result<(), WalletError> {
        if let TxOutput::CreateStakePool(_, data) = output {
            self.key_chain.mark_vrf_public_key_as_used(db_tx, data.vrf_public_key())?;
            match data.decommission_key() {
                Destination::PublicKeyHash(pkh) => {
                    self.key_chain.mark_public_key_hash_as_used(db_tx, pkh)?;
                }
                Destination::PublicKey(pk) => {
                    self.key_chain.mark_public_key_as_used(db_tx, pk)?;
                }
                Destination::AnyoneCanSpend
                | Destination::ClassicMultisig(_)
                | Destination::ScriptHash(_) => {}
            }
        }
        Ok(())
    }

    pub fn get_balance(
        &self,
        utxo_states: UtxoStates,
        median_time: BlockTimestamp,
        with_locked: WithLocked,
    ) -> WalletResult<BTreeMap<Currency, Amount>> {
        let amounts_by_currency = currency_grouper::group_utxos_for_input(
            self.get_utxos(
                UtxoType::Transfer | UtxoType::LockThenTransfer | UtxoType::IssueNft,
                median_time,
                utxo_states,
                with_locked,
            )
            .into_iter(),
            |(_, tx_output)| tx_output,
            |total: &mut Amount, _, amount| -> WalletResult<()> {
                *total = (*total + amount).ok_or(WalletError::OutputAmountOverflow)?;
                Ok(())
            },
            Amount::ZERO,
        )?;
        Ok(amounts_by_currency)
    }

    pub fn get_multisig_utxos(
        &self,
        utxo_types: UtxoTypes,
        median_time: BlockTimestamp,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> Vec<(UtxoOutPoint, &TxOutput)> {
        let current_block_info = BlockInfo {
            height: self.account_info.best_block_height(),
            timestamp: median_time,
        };
        self.output_cache.utxos(current_block_info, utxo_states, with_locked, |txo| {
            self.is_watched_multisig_output(txo)
                && get_utxo_type(txo).is_some_and(|v| utxo_types.contains(v))
        })
    }

    pub fn get_utxos(
        &self,
        utxo_types: UtxoTypes,
        median_time: BlockTimestamp,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> Vec<(UtxoOutPoint, &TxOutput)> {
        let current_block_info = BlockInfo {
            height: self.account_info.best_block_height(),
            timestamp: median_time,
        };
        self.output_cache.utxos(current_block_info, utxo_states, with_locked, |txo| {
            self.is_mine(txo) && get_utxo_type(txo).is_some_and(|v| utxo_types.contains(v))
        })
    }

    pub fn get_transaction_list(&self, skip: usize, count: usize) -> WalletResult<TransactionList> {
        get_transaction_list(&self.key_chain, &self.output_cache, skip, count)
    }

    pub fn get_transaction(&self, transaction_id: Id<Transaction>) -> WalletResult<&TxData> {
        self.output_cache.get_transaction(transaction_id)
    }

    pub fn reset_to_height<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        wallet_events: &impl WalletEvents,
        common_block_height: BlockHeight,
    ) -> WalletResult<()> {
        let mut revoked_txs = self
            .output_cache
            .txs_with_unconfirmed()
            .iter()
            .filter_map(|(id, tx)| match tx.state() {
                TxState::Confirmed(height, _, idx) => {
                    if height > common_block_height {
                        Some((
                            AccountWalletTxId::new(self.get_account_id(), id.clone()),
                            (height, idx),
                        ))
                    } else {
                        None
                    }
                }
                TxState::Inactive(_)
                | TxState::Conflicted(_)
                | TxState::InMempool(_)
                | TxState::Abandoned => None,
            })
            .collect::<Vec<_>>();

        // sort from latest tx down to remove them in order
        revoked_txs.sort_by_key(|&(_, height_idx)| Reverse(height_idx));

        for (tx_id, _) in revoked_txs {
            db_tx.del_transaction(&tx_id)?;
            let source = tx_id.into_item_id();
            self.output_cache.remove_tx(&source)?;
            wallet_events.del_transaction(self.account_index(), source);
        }

        Ok(())
    }

    /// Store a block or tx in the DB if any of the inputs or outputs belong to this wallet
    /// returns true if tx was added false otherwise
    fn add_wallet_tx_if_relevant(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        wallet_events: &impl WalletEvents,
        tx: WalletTx,
    ) -> WalletResult<bool> {
        let relevant_inputs = tx.inputs().iter().any(|input| match input {
            TxInput::Utxo(outpoint) => self
                .output_cache
                .get_txo(outpoint)
                .is_some_and(|txo| self.is_mine_or_watched(txo)),
            TxInput::Account(outpoint) => match outpoint.account() {
                AccountSpending::DelegationBalance(delegation_id, _) => {
                    self.find_delegation(delegation_id).is_ok()
                }
            },
            TxInput::AccountCommand(_, op) => match op {
                AccountCommand::MintTokens(token_id, _)
                | AccountCommand::UnmintTokens(token_id)
                | AccountCommand::LockTokenSupply(token_id)
                | AccountCommand::FreezeToken(token_id, _)
                | AccountCommand::UnfreezeToken(token_id)
                | AccountCommand::ChangeTokenMetadataUri(token_id, _) => {
                    self.find_token(token_id).is_ok()
                }
                AccountCommand::ChangeTokenAuthority(token_id, address) => {
                    self.find_token(token_id).is_ok()
                        || self.is_destination_mine_or_watched(address)
                }
                AccountCommand::ConcludeOrder(order_id) => self.find_order(order_id).is_ok(),
                AccountCommand::FillOrder(order_id, _, dest) => {
                    self.find_order(order_id).is_ok() || self.is_destination_mine_or_watched(dest)
                }
            },
        });
        let relevant_outputs = self.mark_outputs_as_seen(db_tx, tx.outputs())?;
        if relevant_inputs || relevant_outputs {
            let id = AccountWalletTxId::new(self.get_account_id(), tx.id());
            db_tx.set_transaction(&id, &tx)?;
            wallet_events.set_transaction(self.account_index(), &tx);
            self.output_cache.add_tx(id.into_item_id(), tx)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn scan_genesis(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        wallet_events: &impl WalletEvents,
    ) -> WalletResult<()> {
        let chain_config = Arc::clone(&self.chain_config);

        let block = BlockData::from_genesis(chain_config.genesis_block());
        self.add_wallet_tx_if_relevant(db_tx, wallet_events, WalletTx::Block(block))?;

        Ok(())
    }

    /// Scan the new blocks for relevant transactions and updates the state
    /// Returns true if a new transaction was added else false
    pub fn scan_new_blocks<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        wallet_events: &impl WalletEvents,
        common_block_height: BlockHeight,
        blocks: &[Block],
    ) -> WalletResult<bool> {
        assert!(!blocks.is_empty());
        assert!(
            common_block_height <= self.account_info.best_block_height(),
            "Invalid common block height: {}, current block height: {}",
            common_block_height,
            self.account_info.best_block_height(),
        );

        if self.account_info.best_block_height() > common_block_height {
            self.reset_to_height(db_tx, wallet_events, common_block_height)?;
        }

        let new_tx_was_added = blocks.iter().enumerate().try_fold(
            false,
            |mut new_tx_was_added, (index, block)| -> WalletResult<bool> {
                let block_height =
                    BlockHeight::new(common_block_height.into_int() + index as u64 + 1);
                let wallet_tx = WalletTx::Block(BlockData::from_block(block, block_height));

                new_tx_was_added |=
                    self.add_wallet_tx_if_relevant(db_tx, wallet_events, wallet_tx)?;

                block.transactions().iter().enumerate().try_fold(
                    new_tx_was_added,
                    |mut new_tx_was_added, (idx, signed_tx)| {
                        let tx_state =
                            TxState::Confirmed(block_height, block.timestamp(), idx as u64);
                        let wallet_tx = WalletTx::Tx(TxData::new(signed_tx.clone(), tx_state));
                        self.update_conflicting_txs(&wallet_tx, block, db_tx)?;

                        new_tx_was_added |= self
                            .add_wallet_tx_if_relevant_and_remove_from_user_txs(
                                db_tx,
                                wallet_events,
                                wallet_tx,
                                signed_tx.transaction().get_id(),
                            )?;
                        Ok(new_tx_was_added)
                    },
                )
            },
        )?;

        // Update best_block_height and best_block_id only after successful commit call!
        let best_block_height = (common_block_height.into_int() + blocks.len() as u64).into();
        let best_block_id = blocks.last().expect("blocks not empty").header().block_id().into();

        self.account_info.update_best_block(best_block_height, best_block_id);
        db_tx.set_account(&self.key_chain.get_account_id(), &self.account_info)?;

        Ok(new_tx_was_added)
    }

    /// Check for any conflicting txs and update the new state in the DB
    fn update_conflicting_txs<B: storage::Backend>(
        &mut self,
        wallet_tx: &WalletTx,
        block: &Block,
        db_tx: &mut StoreTxRw<B>,
    ) -> WalletResult<()> {
        let acc_id = self.get_account_id();
        let conflicting_tx = self.output_cache.check_conflicting(wallet_tx, block.get_id().into());
        for tx in conflicting_tx {
            let id = AccountWalletTxId::new(acc_id.clone(), tx.id());
            db_tx.set_transaction(&id, tx)?;
        }

        Ok(())
    }

    /// Add a new wallet tx if relevant for this account and remove it from the user transactions
    /// to not be rebroadcast again
    fn add_wallet_tx_if_relevant_and_remove_from_user_txs(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        wallet_events: &impl WalletEvents,
        wallet_tx: WalletTx,
        tx_id: Id<Transaction>,
    ) -> Result<bool, WalletError> {
        Ok(
            if self.add_wallet_tx_if_relevant(db_tx, wallet_events, wallet_tx)? {
                let id = AccountWalletCreatedTxId::new(self.get_account_id(), tx_id);
                db_tx.del_user_transaction(&id)?;
                true
            } else {
                false
            },
        )
    }

    pub fn update_best_block(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        best_block_height: BlockHeight,
        best_block_id: Id<GenBlock>,
    ) -> WalletResult<()> {
        self.account_info.update_best_block(best_block_height, best_block_id);
        db_tx.set_account(&self.key_chain.get_account_id(), &self.account_info)?;
        Ok(())
    }

    pub fn scan_new_inmempool_transactions(
        &mut self,
        transactions: &[SignedTransaction],
        db_tx: &mut impl WalletStorageWriteLocked,
        wallet_events: &impl WalletEvents,
    ) -> WalletResult<()> {
        self.scan_new_unconfirmed_transactions(
            transactions,
            TxState::InMempool,
            db_tx,
            wallet_events,
        )
    }

    pub fn scan_new_inactive_transactions(
        &mut self,
        transactions: &[SignedTransaction],
        db_tx: &mut impl WalletStorageWriteLocked,
        wallet_events: &impl WalletEvents,
    ) -> WalletResult<()> {
        self.scan_new_unconfirmed_transactions(
            transactions,
            TxState::Inactive,
            db_tx,
            wallet_events,
        )
    }

    fn scan_new_unconfirmed_transactions(
        &mut self,
        transactions: &[SignedTransaction],
        make_tx_state: fn(u64) -> TxState,
        db_tx: &mut impl WalletStorageWriteLocked,
        wallet_events: &impl WalletEvents,
    ) -> WalletResult<()> {
        let account_id = self.get_account_id();
        let mut not_added = vec![];
        let mut counter = db_tx
            .get_account_unconfirmed_tx_counter(&account_id)?
            .ok_or(WalletError::WalletNotInitialized)?;

        for signed_tx in transactions {
            counter += 1;
            let tx_state = make_tx_state(counter);
            let wallet_tx = WalletTx::Tx(TxData::new(signed_tx.clone(), tx_state));

            if !self.add_wallet_tx_if_relevant(db_tx, wallet_events, wallet_tx)? {
                not_added.push((signed_tx, tx_state));
            } else {
                let id =
                    AccountPrefixedId::new(account_id.clone(), signed_tx.transaction().get_id());
                db_tx.set_user_transaction(&id, signed_tx)?;
            }
        }

        // check them again after adding all we could
        // and keep looping as long as we add a new tx
        loop {
            let mut not_added_next = vec![];
            let previously_not_added = not_added.len();
            for (signed_tx, tx_state) in not_added {
                let wallet_tx = WalletTx::Tx(TxData::new(signed_tx.clone(), tx_state));

                if !self.add_wallet_tx_if_relevant(db_tx, wallet_events, wallet_tx)? {
                    not_added_next.push((signed_tx, tx_state));
                } else {
                    let id = AccountPrefixedId::new(
                        account_id.clone(),
                        signed_tx.transaction().get_id(),
                    );
                    db_tx.set_user_transaction(&id, signed_tx)?;
                }
            }

            // if no new tx was added break
            if not_added_next.len() == previously_not_added {
                break;
            }

            not_added = not_added_next;
        }

        // update the new counter in the DB
        db_tx.set_account_unconfirmed_tx_counter(&self.get_account_id(), counter)?;

        Ok(())
    }

    pub fn best_block(&self) -> (Id<GenBlock>, BlockHeight) {
        (
            self.account_info.best_block_id(),
            self.account_info.best_block_height(),
        )
    }

    pub fn has_transactions(&self) -> bool {
        self.output_cache.has_confirmed_transactions()
    }

    pub fn name(&self) -> &Option<String> {
        self.account_info.name()
    }

    pub fn pending_transactions(&self) -> Vec<WithId<&Transaction>> {
        self.output_cache.pending_transactions()
    }

    pub fn mainchain_transactions(
        &self,
        destination: Option<Destination>,
        limit: usize,
    ) -> Vec<TxInfo> {
        self.output_cache.mainchain_transactions(destination, limit)
    }

    pub fn abandon_transaction(
        &mut self,
        tx_id: Id<Transaction>,
        db_tx: &mut impl WalletStorageWriteLocked,
    ) -> WalletResult<()> {
        let abandoned_txs = self.output_cache.abandon_transaction(tx_id)?;
        let acc_id = self.get_account_id();

        for tx_id in abandoned_txs {
            let id = AccountWalletCreatedTxId::new(acc_id.clone(), tx_id);
            db_tx.del_user_transaction(&id)?;
        }

        Ok(())
    }

    pub fn set_name(
        &mut self,
        name: Option<String>,
        db_tx: &mut impl WalletStorageWriteLocked,
    ) -> WalletResult<()> {
        self.account_info.set_name(name);
        db_tx.set_account(&self.get_account_id(), &self.account_info)?;
        Ok(())
    }

    pub fn get_created_blocks(&self) -> Vec<(BlockHeight, Id<GenBlock>, PoolId)> {
        self.output_cache
            .get_created_blocks(|destination| self.is_destination_mine(destination))
    }

    pub fn top_up_addresses(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
    ) -> WalletResult<()> {
        self.key_chain.top_up_all(db_tx)?;
        Ok(())
    }
}

impl<K: AccountKeyChains> common::size_estimation::DestinationInfoProvider for Account<K> {
    fn get_multisig_info(
        &self,
        destination: &Destination,
    ) -> Option<common::size_estimation::MultisigInfo> {
        self.key_chain
            .get_multisig_challenge(destination)
            .map(common::size_estimation::MultisigInfo::from_challenge)
    }
}

#[derive(Debug)]
struct PreselectedInputAmounts {
    // Available amount from input
    pub amount: Amount,
    // Fee requirement introduced by an input
    pub fee: Amount,
    // Burn requirement introduced by an input
    pub burn: Amount,
}

impl<K: AccountKeyChains + VRFAccountKeyChains> Account<K> {
    fn get_vrf_public_key(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
    ) -> WalletResult<VRFPublicKey> {
        Ok(self.key_chain.issue_vrf_key(db_tx)?.1.into_public_key())
    }

    pub fn get_all_issued_vrf_public_keys(
        &self,
    ) -> BTreeMap<ChildNumber, (Address<VRFPublicKey>, bool)> {
        self.key_chain.get_all_issued_vrf_public_keys()
    }

    pub fn get_legacy_vrf_public_key(&self) -> Address<VRFPublicKey> {
        self.key_chain.get_legacy_vrf_public_key()
    }

    /// Get a new vrf key that hasn't been used before
    pub fn get_new_vrf_key(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
    ) -> WalletResult<(ChildNumber, Address<VRFPublicKey>)> {
        Ok(
            self.key_chain.issue_vrf_key(db_tx).map(|(child_number, vrf_key)| {
                (
                    child_number,
                    Address::new(&self.chain_config, vrf_key.public_key().clone())
                        .expect("addressable"),
                )
            })?,
        )
    }

    pub fn get_pos_gen_block_data(
        &self,
        db_tx: &impl WalletStorageReadUnlocked,
        pool_id: PoolId,
    ) -> WalletResult<PoSGenerateBlockInputData> {
        let pool_data = self.output_cache.pool_data(pool_id)?;
        let kernel_input: TxInput = pool_data.utxo_outpoint.clone().into();
        let stake_destination = &pool_data.stake_destination;
        let kernel_input_utxo =
            self.output_cache.get_txo(&pool_data.utxo_outpoint).expect("must exist");

        let stake_private_key = self
            .key_chain
            .get_private_key_for_destination(stake_destination, db_tx)?
            .ok_or(WalletError::KeyChainError(KeyChainError::NoPrivateKeyFound))?;

        let vrf_private_key = self
            .key_chain
            .get_vrf_private_key_for_public_key(&pool_data.vrf_public_key, db_tx)?
            .ok_or(WalletError::KeyChainError(
                KeyChainError::NoVRFPrivateKeyFound,
            ))?
            .private_key();

        let data = PoSGenerateBlockInputData::new(
            stake_private_key,
            vrf_private_key,
            pool_id,
            vec![kernel_input],
            vec![kernel_input_utxo.clone()],
        );

        Ok(data)
    }

    pub fn create_stake_pool_tx(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        stake_pool_arguments: StakePoolCreationArguments,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SendRequest> {
        // TODO: Use other accounts here
        let staker = match stake_pool_arguments.staker_key {
            Some(staker) => match staker {
                Destination::PublicKey(_) => staker,
                // Note: technically it's possible to create a pool with PublicKeyHash as the staker,
                // the pool will seem to work and will actually try producing blocks. However,
                // the produced blocks will be rejected by chainstate, see get_staking_kernel_destination
                // in `consensus`.
                Destination::AnyoneCanSpend
                | Destination::PublicKeyHash(_)
                | Destination::ScriptHash(_)
                | Destination::ClassicMultisig(_) => {
                    return Err(WalletError::StakerDestinationMustBePublicKey)
                }
            },
            None => Destination::PublicKey(
                self.key_chain.issue_key(db_tx, KeyPurpose::ReceiveFunds)?.into_public_key(),
            ),
        };
        let vrf_public_key = match stake_pool_arguments.vrf_public_key {
            Some(vrf_public_key) => vrf_public_key,
            None => self.get_vrf_public_key(db_tx)?,
        };

        // the first UTXO is needed in advance to calculate pool_id, so just make a dummy one
        // and then replace it with when we can calculate the pool_id
        let dummy_pool_id = PoolId::new(Uint256::from_u64(0).into());
        let dummy_stake_output = make_stake_output(
            dummy_pool_id,
            StakePoolCreationResolvedArguments {
                amount: stake_pool_arguments.amount,
                margin_ratio_per_thousand: stake_pool_arguments.margin_ratio_per_thousand,
                cost_per_block: stake_pool_arguments.cost_per_block,
                decommission_key: stake_pool_arguments.decommission_key,
                staker_key: staker,
                vrf_public_key,
            },
        );
        let request = SendRequest::new().with_outputs([dummy_stake_output]);
        let mut request = self.select_inputs_for_send_request(
            request,
            SelectedInputs::Utxos(vec![]),
            None,
            BTreeMap::new(),
            db_tx,
            median_time,
            fee_rate,
            None,
        )?;

        let input0_outpoint = crate::utils::get_first_utxo_outpoint(request.inputs())?;
        let new_pool_id = pos_accounting::make_pool_id(input0_outpoint);

        // update the dummy_pool_id with the new pool_id
        let old_pool_id = request
            .get_outputs_mut()
            .iter_mut()
            .find_map(|out| match out {
                TxOutput::CreateStakePool(pool_id, _) if *pool_id == dummy_pool_id => Some(pool_id),
                TxOutput::CreateStakePool(_, _)
                | TxOutput::Burn(_)
                | TxOutput::Transfer(_, _)
                | TxOutput::DelegateStaking(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::IssueFungibleToken(_)
                | TxOutput::IssueNft(_, _, _)
                | TxOutput::DataDeposit(_)
                | TxOutput::Htlc(_, _)
                | TxOutput::CreateOrder(_) => None,
            })
            .expect("find output with dummy_pool_id");
        *old_pool_id = new_pool_id;

        Ok(request)
    }
}

/// There are some preselected inputs like the Token account inputs with a nonce
/// that need to be included in the request
/// Here we group them up by currency and sum the total amount and fee they bring to the
/// transaction
fn group_preselected_inputs(
    request: &SendRequest,
    current_fee_rate: FeeRate,
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    dest_info_provider: Option<&dyn DestinationInfoProvider>,
    order_info: Option<BTreeMap<OrderId, &RpcOrderInfo>>,
) -> Result<BTreeMap<Currency, PreselectedInputAmounts>, WalletError> {
    let mut preselected_inputs = BTreeMap::new();
    for (input, destination, utxo) in
        izip!(request.inputs(), request.destinations(), request.utxos())
    {
        let input_size = serialization::Encode::encoded_size(&input);
        let inp_sig_size = input_signature_size_from_destination(destination, dest_info_provider)?;

        let fee = current_fee_rate
            .compute_fee(input_size + inp_sig_size)
            .map_err(|_| UtxoSelectorError::AmountArithmeticError)?;

        let mut update_preselected_inputs =
            |currency: Currency, amount: Amount, fee: Amount, burn: Amount| -> WalletResult<()> {
                match preselected_inputs.entry(currency) {
                    Entry::Vacant(entry) => {
                        entry.insert(PreselectedInputAmounts { amount, fee, burn });
                    }
                    Entry::Occupied(mut entry) => {
                        let existing = entry.get_mut();
                        existing.amount =
                            (existing.amount + amount).ok_or(WalletError::OutputAmountOverflow)?;
                        existing.fee =
                            (existing.fee + fee).ok_or(WalletError::OutputAmountOverflow)?;
                        existing.burn =
                            (existing.burn + burn).ok_or(WalletError::OutputAmountOverflow)?;
                    }
                }
                Ok(())
            };

        match input {
            TxInput::Utxo(_) => {
                let output = utxo.as_ref().expect("must be present");
                let (currency, value) = match output {
                    TxOutput::Transfer(v, _)
                    | TxOutput::LockThenTransfer(v, _, _)
                    | TxOutput::Htlc(v, _) => match v {
                        OutputValue::Coin(output_amount) => (Currency::Coin, *output_amount),
                        OutputValue::TokenV0(_) => {
                            return Err(WalletError::UnsupportedTransactionOutput(Box::new(
                                output.clone(),
                            )))
                        }
                        OutputValue::TokenV1(token_id, output_amount) => {
                            (Currency::Token(*token_id), *output_amount)
                        }
                    },
                    TxOutput::IssueNft(token_id, _, _) => {
                        (Currency::Token(*token_id), Amount::from_atoms(1))
                    }
                    TxOutput::CreateStakePool(_, _)
                    | TxOutput::ProduceBlockFromStake(_, _)
                    | TxOutput::Burn(_)
                    | TxOutput::CreateDelegationId(_, _)
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::IssueFungibleToken(_)
                    | TxOutput::DataDeposit(_)
                    | TxOutput::CreateOrder(_) => {
                        return Err(WalletError::UnsupportedTransactionOutput(Box::new(
                            output.clone(),
                        )))
                    }
                };
                update_preselected_inputs(currency, value, *fee, Amount::ZERO)?;
            }
            TxInput::Account(outpoint) => match outpoint.account() {
                AccountSpending::DelegationBalance(_, amount) => {
                    update_preselected_inputs(Currency::Coin, *amount, *fee, Amount::ZERO)?;
                }
            },
            TxInput::AccountCommand(_, op) => match op {
                AccountCommand::MintTokens(token_id, amount) => {
                    update_preselected_inputs(
                        Currency::Token(*token_id),
                        *amount,
                        (*fee + chain_config.token_supply_change_fee(block_height))
                            .ok_or(WalletError::OutputAmountOverflow)?,
                        Amount::ZERO,
                    )?;
                }
                AccountCommand::LockTokenSupply(token_id)
                | AccountCommand::UnmintTokens(token_id) => {
                    update_preselected_inputs(
                        Currency::Token(*token_id),
                        Amount::ZERO,
                        (*fee + chain_config.token_supply_change_fee(block_height))
                            .ok_or(WalletError::OutputAmountOverflow)?,
                        Amount::ZERO,
                    )?;
                }
                AccountCommand::FreezeToken(token_id, _)
                | AccountCommand::UnfreezeToken(token_id) => {
                    update_preselected_inputs(
                        Currency::Token(*token_id),
                        Amount::ZERO,
                        (*fee + chain_config.token_freeze_fee(block_height))
                            .ok_or(WalletError::OutputAmountOverflow)?,
                        Amount::ZERO,
                    )?;
                }
                AccountCommand::ChangeTokenAuthority(token_id, _) => {
                    update_preselected_inputs(
                        Currency::Token(*token_id),
                        Amount::ZERO,
                        (*fee + chain_config.token_change_authority_fee(block_height))
                            .ok_or(WalletError::OutputAmountOverflow)?,
                        Amount::ZERO,
                    )?;
                }
                AccountCommand::ChangeTokenMetadataUri(token_id, _) => {
                    update_preselected_inputs(
                        Currency::Token(*token_id),
                        Amount::ZERO,
                        (*fee + chain_config.token_change_metadata_uri_fee())
                            .ok_or(WalletError::OutputAmountOverflow)?,
                        Amount::ZERO,
                    )?;
                }
                AccountCommand::ConcludeOrder(order_id) => {
                    let order_info = order_info
                        .as_ref()
                        .and_then(|info| info.get(order_id))
                        .ok_or(WalletError::OrderInfoMissing(*order_id))?;

                    let given_currency =
                        Currency::from_rpc_output_value(&order_info.initially_given);
                    update_preselected_inputs(
                        given_currency,
                        order_info.give_balance,
                        Amount::ZERO,
                        Amount::ZERO,
                    )?;

                    let asked_currency =
                        Currency::from_rpc_output_value(&order_info.initially_asked);
                    let filled_amount = (order_info.initially_asked.amount()
                        - order_info.ask_balance)
                        .ok_or(WalletError::OutputAmountOverflow)?;
                    update_preselected_inputs(
                        asked_currency,
                        filled_amount,
                        Amount::ZERO,
                        Amount::ZERO,
                    )?;

                    // add fee
                    update_preselected_inputs(Currency::Coin, Amount::ZERO, *fee, Amount::ZERO)?;
                }
                AccountCommand::FillOrder(order_id, fill_amount_in_ask_currency, _) => {
                    let order_info = order_info
                        .as_ref()
                        .and_then(|info| info.get(order_id))
                        .ok_or(WalletError::OrderInfoMissing(*order_id))?;

                    let filled_amount = orders_accounting::calculate_filled_amount(
                        order_info.ask_balance,
                        order_info.give_balance,
                        *fill_amount_in_ask_currency,
                    )
                    .ok_or(WalletError::CalculateOrderFilledAmountFailed(*order_id))?;

                    let given_currency =
                        Currency::from_rpc_output_value(&order_info.initially_given);
                    update_preselected_inputs(given_currency, filled_amount, *fee, Amount::ZERO)?;

                    let asked_currency =
                        Currency::from_rpc_output_value(&order_info.initially_asked);
                    update_preselected_inputs(
                        asked_currency,
                        Amount::ZERO,
                        Amount::ZERO,
                        *fill_amount_in_ask_currency,
                    )?;
                }
            },
        }
    }
    Ok(preselected_inputs)
}

/// Calculate the amount of fee that needs to be paid to add a change output
/// Returns the Amounts for Coin output and Token output
fn coin_and_token_output_change_fees(
    feerate: mempool::FeeRate,
    destination: Option<&Address<Destination>>,
) -> WalletResult<(Amount, Amount)> {
    let destination = if let Some(addr) = destination {
        addr.as_object().clone()
    } else {
        let pub_key_hash = PublicKeyHash::from_low_u64_ne(0);
        Destination::PublicKeyHash(pub_key_hash)
    };

    let coin_output = TxOutput::Transfer(OutputValue::Coin(Amount::MAX), destination.clone());
    let token_output = TxOutput::Transfer(
        OutputValue::TokenV1(
            TokenId::zero(),
            // TODO: as the  amount is compact there is an edge case where those extra few bytes of
            // size can cause the output fee to be go over the available amount of coins thus not
            // including a change output, and losing money for the user
            // e.g. available money X and need to transfer Y and the difference Z = X - Y is just
            // enough the make an output with change but the amount having single byte encoding
            // but by using Amount::MAX the algorithm thinks that the change output will cost more
            // than Z and it will not create a change output
            Amount::MAX,
        ),
        destination,
    );

    Ok((
        feerate
            .compute_fee(serialization::Encode::encoded_size(&coin_output))
            .map_err(|_| UtxoSelectorError::AmountArithmeticError)?
            .into(),
        feerate
            .compute_fee(serialization::Encode::encoded_size(&token_output))
            .map_err(|_| UtxoSelectorError::AmountArithmeticError)?
            .into(),
    ))
}

#[cfg(test)]
mod tests;
