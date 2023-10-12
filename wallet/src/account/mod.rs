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

mod output_cache;
pub mod transaction_list;
mod utxo_selector;

use common::address::pubkeyhash::PublicKeyHash;
use common::chain::block::timestamp::BlockTimestamp;
use common::chain::AccountOp::{self, SpendDelegationBalance};
use common::primitives::id::WithId;
use common::primitives::{Idable, H256};
use common::Uint256;
use crypto::key::hdkd::child_number::ChildNumber;
use mempool::FeeRate;
use utils::ensure;
pub use utxo_selector::UtxoSelectorError;
use wallet_types::with_locked::WithLocked;

use crate::account::utxo_selector::{select_coins, OutputGroup};
use crate::key_chain::{make_path_to_vrf_key, AccountKeyChain, KeyChainError};
use crate::send_request::{
    get_tx_output_destination, make_address_output, make_address_output_from_delegation,
    make_address_output_token, make_decomission_stake_pool_output, make_lock_token_outputs,
    make_mint_token_outputs, make_redeem_token_outputs, make_stake_output, IssueNftArguments,
    StakePoolDataArguments,
};
use crate::wallet_events::{WalletEvents, WalletEventsNoOp};
use crate::{SendRequest, WalletError, WalletResult};
use common::address::Address;
use common::chain::output_value::OutputValue;
use common::chain::signature::inputsig::standard_signature::StandardInputSignature;
use common::chain::signature::inputsig::InputWitness;
use common::chain::signature::sighash::sighashtype::SigHashType;
use common::chain::tokens::{
    make_token_id, NftIssuance, NftIssuanceV0, TokenData, TokenId, TokenTransfer,
};
use common::chain::{
    AccountNonce, AccountOutPoint, Block, ChainConfig, DelegationId, Destination, GenBlock, PoolId,
    SignedTransaction, Transaction, TxInput, TxOutput, UtxoOutPoint,
};
use common::primitives::{Amount, BlockHeight, Id};
use consensus::PoSGenerateBlockInputData;
use crypto::key::hdkd::u31::U31;
use crypto::key::PublicKey;
use crypto::vrf::{VRFPrivateKey, VRFPublicKey};
use itertools::Itertools;
use std::cmp::Reverse;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::ops::{Add, Sub};
use std::sync::Arc;
use wallet_storage::{
    StoreTxRw, WalletStorageReadLocked, WalletStorageReadUnlocked, WalletStorageWriteLocked,
    WalletStorageWriteUnlocked,
};
use wallet_types::utxo_types::{get_utxo_type, UtxoState, UtxoStates, UtxoType, UtxoTypes};
use wallet_types::wallet_tx::{BlockData, TxData, TxState};
use wallet_types::{
    AccountId, AccountInfo, AccountWalletCreatedTxId, AccountWalletTxId, BlockInfo, KeyPurpose,
    KeychainUsageState, WalletTx,
};

pub use self::output_cache::DelegationData;
use self::output_cache::{OutputCache, TokenIssuanceData};
use self::transaction_list::{get_transaction_list, TransactionList};
use self::utxo_selector::{CoinSelectionAlgo, PayFee};

pub struct CurrentFeeRate {
    pub current_fee_rate: FeeRate,
    pub consolidate_fee_rate: FeeRate,
}

pub struct Account {
    chain_config: Arc<ChainConfig>,
    key_chain: AccountKeyChain,
    output_cache: OutputCache,
    account_info: AccountInfo,
}

impl Account {
    pub fn load_from_database(
        chain_config: Arc<ChainConfig>,
        db_tx: &impl WalletStorageReadLocked,
        id: &AccountId,
    ) -> WalletResult<Account> {
        let mut account_infos = db_tx.get_accounts_info()?;
        let account_info =
            account_infos.remove(id).ok_or(KeyChainError::NoAccountFound(id.clone()))?;

        let key_chain =
            AccountKeyChain::load_from_database(chain_config.clone(), db_tx, id, &account_info)?;

        let txs = db_tx.get_transactions(&key_chain.get_account_id())?;
        let output_cache = OutputCache::new(txs)?;

        Ok(Account {
            chain_config,
            key_chain,
            output_cache,
            account_info,
        })
    }

    /// Create a new account by providing a key chain
    pub fn new(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut impl WalletStorageWriteLocked,
        key_chain: AccountKeyChain,
        name: Option<String>,
    ) -> WalletResult<Account> {
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

    fn select_inputs_for_send_request(
        &mut self,
        request: SendRequest,
        input_utxos: Vec<UtxoOutPoint>,
        db_tx: &mut impl WalletStorageWriteLocked,
        median_time: BlockTimestamp,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
    ) -> WalletResult<SendRequest> {
        // TODO: allow to pay fees with different currency?
        let pay_fee_with_currency = Currency::Coin;

        let mut output_currency_amounts = group_outputs(
            request.outputs().iter(),
            |&output| output,
            |grouped: &mut Amount, _, new_amount| -> WalletResult<()> {
                *grouped = grouped.add(new_amount).ok_or(WalletError::OutputAmountOverflow)?;
                Ok(())
            },
            Amount::ZERO,
        )?;

        let network_fee: Amount = current_fee_rate
            .compute_fee(tx_size_with_outputs(request.outputs()))
            .map_err(|_| UtxoSelectorError::AmountArithmeticError)?
            .into();

        let (coin_change_fee, token_change_fee) =
            coin_and_token_output_change_fees(current_fee_rate)?;

        let current_block_info = BlockInfo {
            height: self.account_info.best_block_height(),
            timestamp: median_time,
        };

        let mut preselected_inputs = group_preselected_inputs(&request, current_fee_rate)?;

        let (utxos, selection_algo) = if input_utxos.is_empty() {
            (
                self.get_utxos(
                    UtxoType::Transfer
                        | UtxoType::LockThenTransfer
                        | UtxoType::IssueNft
                        | UtxoType::MintTokens,
                    median_time,
                    UtxoState::Confirmed | UtxoState::InMempool | UtxoState::Inactive,
                    WithLocked::Unlocked,
                ),
                CoinSelectionAlgo::Randomize,
            )
        } else {
            (
                self.output_cache.find_utxos(current_block_info, input_utxos)?,
                CoinSelectionAlgo::UsePreselected,
            )
        };

        let mut utxos_by_currency = self.utxo_output_groups_by_currency(
            current_fee_rate,
            consolidate_fee_rate,
            &pay_fee_with_currency,
            utxos,
        )?;

        let amount_to_be_paid_in_currency_with_fees =
            output_currency_amounts.remove(&pay_fee_with_currency).unwrap_or(Amount::ZERO);

        let mut total_fees_not_paid = network_fee;

        let mut selected_inputs: BTreeMap<_, _> = output_currency_amounts
            .iter()
            .map(|(currency, output_amount)| -> WalletResult<_> {
                let utxos = utxos_by_currency.remove(currency).unwrap_or(vec![]);
                let (preselected_amount, preselected_fee) =
                    preselected_inputs.remove(currency).unwrap_or((Amount::ZERO, Amount::ZERO));

                let cost_of_change = match currency {
                    Currency::Coin => coin_change_fee,
                    Currency::Token(_) => token_change_fee,
                };
                let selection_result = select_coins(
                    utxos,
                    output_amount.sub(preselected_amount).unwrap_or(Amount::ZERO),
                    PayFee::DoNotPayFeeWithThisCurrency,
                    cost_of_change,
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

                Ok((currency.clone(), selection_result))
            })
            .try_collect()?;

        let utxos = utxos_by_currency.remove(&pay_fee_with_currency).unwrap_or(vec![]);
        let (preselected_amount, preselected_fee) = preselected_inputs
            .remove(&pay_fee_with_currency)
            .unwrap_or((Amount::ZERO, Amount::ZERO));

        total_fees_not_paid =
            (total_fees_not_paid + preselected_fee).ok_or(WalletError::OutputAmountOverflow)?;
        let mut amount_to_be_paid_in_currency_with_fees = (amount_to_be_paid_in_currency_with_fees
            + total_fees_not_paid)
            .ok_or(WalletError::OutputAmountOverflow)?;

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
            pay_fee_with_currency.clone(),
            (amount_to_be_paid_in_currency_with_fees + selection_result.get_total_fees())
                .ok_or(WalletError::OutputAmountOverflow)?,
        );
        selected_inputs.insert(pay_fee_with_currency, selection_result);

        // Check outputs against inputs and create change
        self.check_outputs_and_add_change(output_currency_amounts, selected_inputs, db_tx, request)
    }

    fn check_outputs_and_add_change(
        &mut self,
        output_currency_amounts: BTreeMap<Currency, Amount>,
        selected_inputs: BTreeMap<Currency, utxo_selector::SelectionResult>,
        db_tx: &mut impl WalletStorageWriteLocked,
        mut request: SendRequest,
    ) -> Result<SendRequest, WalletError> {
        for currency in output_currency_amounts.keys() {
            let change_amount =
                selected_inputs.get(currency).map_or(Amount::ZERO, |result| result.get_change());

            if change_amount > Amount::ZERO {
                let (_, change_address) = self.get_new_address(db_tx, KeyPurpose::Change)?;
                let change_output = match currency {
                    Currency::Coin => make_address_output(
                        self.chain_config.as_ref(),
                        change_address,
                        change_amount,
                    )?,
                    Currency::Token(token_id) => make_address_output_token(
                        self.chain_config.as_ref(),
                        change_address,
                        change_amount,
                        *token_id,
                    )?,
                };
                request = request.with_outputs([change_output]);
            }
        }

        let selected_inputs = selected_inputs.into_iter().flat_map(|x| x.1.into_output_pairs());

        request.with_inputs(selected_inputs)
    }

    fn utxo_output_groups_by_currency(
        &self,
        current_fee_rate: FeeRate,
        consolidate_fee_rate: FeeRate,
        pay_fee_with_currency: &Currency,
        utxos: BTreeMap<UtxoOutPoint, (&TxOutput, Option<TokenId>)>,
    ) -> Result<BTreeMap<Currency, Vec<OutputGroup>>, WalletError> {
        let utxo_to_output_group =
            |(outpoint, txo): (UtxoOutPoint, TxOutput)| -> WalletResult<OutputGroup> {
                let tx_input: TxInput = outpoint.into();
                let input_size = serialization::Encode::encoded_size(&tx_input);

                let destination = get_tx_output_destination(&txo).ok_or_else(|| {
                    WalletError::UnsupportedTransactionOutput(Box::new(txo.clone()))
                })?;

                let inp_sig_size = input_signature_size(destination)?;

                let fee = current_fee_rate
                    .compute_fee(input_size + inp_sig_size)
                    .map_err(|_| UtxoSelectorError::AmountArithmeticError)?;
                let consolidate_fee = consolidate_fee_rate
                    .compute_fee(input_size + inp_sig_size)
                    .map_err(|_| UtxoSelectorError::AmountArithmeticError)?;

                // TODO-#1120: calculate weight from the size of the input
                let weight = 0;
                let out_group =
                    OutputGroup::new((tx_input, txo), fee.into(), consolidate_fee.into(), weight)?;

                Ok(out_group)
            };

        group_utxos_for_input(
            utxos.into_iter(),
            |(_, (tx_output, _))| tx_output,
            |grouped: &mut Vec<(UtxoOutPoint, TxOutput)>, element, _| -> WalletResult<()> {
                grouped.push((element.0.clone(), element.1 .0.clone()));
                Ok(())
            },
            |(_, (_, token_id))| token_id.ok_or(WalletError::MissingTokenId),
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

    pub fn process_send_request(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        request: SendRequest,
        inputs: Vec<UtxoOutPoint>,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SignedTransaction> {
        let request = self.select_inputs_for_send_request(
            request,
            inputs,
            db_tx,
            median_time,
            fee_rate.current_fee_rate,
            fee_rate.consolidate_fee_rate,
        )?;
        // TODO: Randomize inputs and outputs

        let tx = self.sign_transaction_from_req(request, db_tx)?;
        Ok(tx)
    }

    pub fn decommission_stake_pool(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        pool_id: PoolId,
        pool_balance: Amount,
        current_fee_rate: FeeRate,
    ) -> WalletResult<SignedTransaction> {
        let pool_data = self.output_cache.pool_data(pool_id)?;
        let best_block_height = self.best_block().1;
        let tx_input = TxInput::Utxo(pool_data.utxo_outpoint.clone());

        let network_fee: Amount = {
            let output = make_decomission_stake_pool_output(
                self.chain_config.as_ref(),
                pool_data.decommission_key.clone(),
                pool_balance,
                best_block_height,
            )?;
            let outputs = vec![output];

            current_fee_rate
                .compute_fee(
                    tx_size_with_outputs(outputs.as_slice())
                        + input_signature_size(&pool_data.decommission_key)?
                        + serialization::Encode::encoded_size(&tx_input),
                )
                .map_err(|_| UtxoSelectorError::AmountArithmeticError)?
                .into()
        };

        let output = make_decomission_stake_pool_output(
            self.chain_config.as_ref(),
            pool_data.decommission_key.clone(),
            (pool_balance - network_fee)
                .ok_or(WalletError::NotEnoughUtxo(network_fee, pool_balance))?,
            best_block_height,
        )?;

        let tx = Transaction::new(0, vec![tx_input], vec![output])?;

        let input_utxo = self.output_cache.get_txo(&pool_data.utxo_outpoint);
        let tx = self.sign_transaction(tx, &[&pool_data.decommission_key], &[input_utxo], db_tx)?;
        Ok(tx)
    }

    pub fn spend_from_delegation(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        address: Address<Destination>,
        amount: Amount,
        delegation_id: DelegationId,
        delegation_share: Amount,
        current_fee_rate: FeeRate,
    ) -> WalletResult<SignedTransaction> {
        let current_block_height = self.best_block().1;
        let output = make_address_output_from_delegation(
            self.chain_config.as_ref(),
            address,
            amount,
            current_block_height,
        )?;
        let delegation_data = self.find_delegation(&delegation_id)?;
        let nonce = delegation_data
            .last_nonce
            .map_or(Some(AccountNonce::new(0)), |nonce| nonce.increment())
            .ok_or(WalletError::DelegationNonceOverflow(delegation_id))?;

        let outputs = vec![output];
        let network_fee: Amount = current_fee_rate
            .compute_fee(
                tx_size_with_outputs(outputs.as_slice())
                    + input_signature_size(&delegation_data.destination)?,
            )
            .map_err(|_| UtxoSelectorError::AmountArithmeticError)?
            .into();

        let amount_with_fee = (amount + network_fee).ok_or(WalletError::OutputAmountOverflow)?;
        let mut tx_input = TxInput::Account(AccountOutPoint::new(
            nonce,
            SpendDelegationBalance(delegation_id, amount_with_fee),
        ));
        // as the input size depends on the amount we specify the fee will also change a bit so
        // loop until it converges.
        let mut input_size = serialization::Encode::encoded_size(&tx_input);
        loop {
            let new_amount_with_fee = (amount_with_fee
                + current_fee_rate
                    .compute_fee(input_size)
                    .map_err(|_| UtxoSelectorError::AmountArithmeticError)?
                    .into())
            .ok_or(WalletError::OutputAmountOverflow)?;
            ensure!(
                new_amount_with_fee <= delegation_share,
                UtxoSelectorError::NotEnoughFunds(delegation_share, new_amount_with_fee)
            );

            tx_input = TxInput::Account(AccountOutPoint::new(
                nonce,
                SpendDelegationBalance(delegation_id, new_amount_with_fee),
            ));

            let new_input_size = serialization::Encode::encoded_size(&tx_input);
            if new_input_size == input_size {
                break;
            }
            input_size = new_input_size;
        }
        let tx = Transaction::new(0, vec![tx_input], outputs)?;

        let tx = self.sign_transaction(tx, &[&delegation_data.destination], &[None], db_tx)?;
        Ok(tx)
    }

    fn get_vrf_key(
        &self,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> WalletResult<(VRFPrivateKey, VRFPublicKey)> {
        let vrf_key_path = make_path_to_vrf_key(&self.chain_config, self.account_index());
        let vrf_private_key =
            self.key_chain.get_private_vrf_key_for_path(&vrf_key_path, db_tx)?.private_key();
        let vrf_public_key = VRFPublicKey::from_private_key(&vrf_private_key);

        Ok((vrf_private_key, vrf_public_key))
    }

    pub fn get_vrf_public_key(
        &self,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> WalletResult<VRFPublicKey> {
        let vrf_keys = self.get_vrf_key(db_tx)?;
        Ok(vrf_keys.1)
    }

    pub fn get_pool_ids(&self) -> Vec<(PoolId, BlockInfo)> {
        self.output_cache.pool_ids()
    }

    pub fn get_delegations(&self) -> impl Iterator<Item = (&DelegationId, &DelegationData)> {
        self.output_cache
            .delegation_ids()
            .filter(|(_, data)| self.is_mine_or_watched_destination(&data.destination))
    }

    pub fn find_delegation(&self, delegation_id: &DelegationId) -> WalletResult<&DelegationData> {
        self.output_cache
            .delegation_data(delegation_id)
            .filter(|data| self.is_mine_or_watched_destination(&data.destination))
            .ok_or(WalletError::DelegationNotFound(*delegation_id))
    }

    pub fn find_token(&self, token_id: &TokenId) -> WalletResult<&TokenIssuanceData> {
        self.output_cache
            .token_data(token_id)
            .filter(|data| self.is_mine_or_watched_destination(&data.reissuance_controller))
            .ok_or(WalletError::UnknownTokenId(*token_id))
    }

    pub fn create_stake_pool_tx(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        stake_pool_arguments: StakePoolDataArguments,
        decomission_key: Option<PublicKey>,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SignedTransaction> {
        // TODO: Use other accounts here
        let staker = self.key_chain.issue_key(db_tx, KeyPurpose::ReceiveFunds)?;
        let decommission_key = match decomission_key {
            Some(key) => key,
            None => self.key_chain.issue_key(db_tx, KeyPurpose::ReceiveFunds)?.into_public_key(),
        };
        let (_vrf_private_key, vrf_public_key) = self.get_vrf_key(db_tx)?;

        // the first UTXO is needed in advance to calculate pool_id, so just make a dummy one
        // and then replace it with when we can calculate the pool_id
        let dummy_pool_id = PoolId::new(Uint256::from_u64(0).into());
        let dummy_stake_output = make_stake_output(
            dummy_pool_id,
            stake_pool_arguments,
            staker.into_public_key(),
            decommission_key,
            vrf_public_key,
        )?;
        let request = SendRequest::new().with_outputs([dummy_stake_output]);
        let mut request = self.select_inputs_for_send_request(
            request,
            vec![],
            db_tx,
            median_time,
            fee_rate.current_fee_rate,
            fee_rate.consolidate_fee_rate,
        )?;

        let new_pool_id = match request
            .inputs()
            .first()
            .expect("selector must have selected something or returned an error")
        {
            TxInput::Utxo(input0_outpoint) => Some(pos_accounting::make_pool_id(input0_outpoint)),
            TxInput::Account(_) => None,
        }
        .ok_or(WalletError::NoUtxos)?;

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
                | TxOutput::IssueNft(_, _, _) => None,
            })
            .expect("find output with dummy_pool_id");
        *old_pool_id = new_pool_id;

        let tx = self.sign_transaction_from_req(request, db_tx)?;
        Ok(tx)
    }

    pub fn create_issue_nft_tx(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        nft_issue_arguments: IssueNftArguments,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SignedTransaction> {
        // the first UTXO is needed in advance to issue a new nft, so just make a dummy one
        // and then replace it with when we can calculate the pool_id
        let dummy_token_id = TokenId::new(H256::zero());
        let dummy_issuance_output = TxOutput::IssueNft(
            dummy_token_id,
            Box::new(NftIssuance::V0(NftIssuanceV0 {
                metadata: nft_issue_arguments.metadata,
            })),
            nft_issue_arguments.destination,
        );

        let request = SendRequest::new().with_outputs([
            dummy_issuance_output,
            TxOutput::Burn(OutputValue::Coin(
                self.chain_config.token_min_issuance_fee(),
            )),
        ]);
        let mut request = self.select_inputs_for_send_request(
            request,
            vec![],
            db_tx,
            median_time,
            fee_rate.current_fee_rate,
            fee_rate.consolidate_fee_rate,
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
                | TxOutput::IssueFungibleToken(_) => None,
                TxOutput::IssueNft(token_id, _, _) => {
                    (*token_id == dummy_token_id).then_some(token_id)
                }
            })
            .expect("find output with dummy_token_id");
        *old_token_id = new_token_id;

        let tx = self.sign_transaction_from_req(request, db_tx)?;
        Ok(tx)
    }

    pub fn mint_tokens(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        token_id: TokenId,
        address: Address<Destination>,
        amount: Amount,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SignedTransaction> {
        let outputs =
            make_mint_token_outputs(token_id, amount, address, self.chain_config.as_ref())?;

        self.change_token_supply_transaction(
            token_id,
            amount,
            outputs,
            db_tx,
            median_time,
            fee_rate,
        )
    }

    fn change_token_supply_transaction(
        &mut self,
        token_id: TokenId,
        amount: Amount,
        outputs: Vec<TxOutput>,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> Result<SignedTransaction, WalletError> {
        let token_data = self.find_token(&token_id)?;
        let nonce = token_data
            .last_nonce
            .map_or(Some(AccountNonce::new(0)), |nonce| nonce.increment())
            .ok_or(WalletError::TokenIssuanceNonceOverflow(token_id))?;
        //FIXME: pass different input in
        let tx_input = TxInput::Account(AccountOutPoint::new(
            nonce,
            AccountOp::MintTokens(token_id, amount),
        ));

        let request = SendRequest::new()
            .with_outputs(outputs)
            .with_inputs_and_destinations([(tx_input, token_data.reissuance_controller.clone())]);

        let request = self.select_inputs_for_send_request(
            request,
            vec![],
            db_tx,
            median_time,
            fee_rate.current_fee_rate,
            fee_rate.consolidate_fee_rate,
        )?;

        let tx = self.sign_transaction_from_req(request, db_tx)?;
        Ok(tx)
    }

    pub fn redeem_tokens(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        token_id: TokenId,
        amount: Amount,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SignedTransaction> {
        let outputs = make_redeem_token_outputs(token_id, amount, self.chain_config.as_ref())?;

        self.change_token_supply_transaction(
            token_id,
            amount,
            outputs,
            db_tx,
            median_time,
            fee_rate,
        )
    }

    pub fn lock_tokens(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        token_id: TokenId,
        median_time: BlockTimestamp,
        fee_rate: CurrentFeeRate,
    ) -> WalletResult<SignedTransaction> {
        let outputs = make_lock_token_outputs(self.chain_config.as_ref())?;

        self.change_token_supply_transaction(
            token_id,
            Amount::ZERO,
            outputs,
            db_tx,
            median_time,
            fee_rate,
        )
    }

    pub fn get_pos_gen_block_data(
        &self,
        db_tx: &impl WalletStorageReadUnlocked,
        median_time: BlockTimestamp,
        pool_id: PoolId,
    ) -> WalletResult<PoSGenerateBlockInputData> {
        let utxos = self.get_utxos(
            UtxoType::CreateStakePool | UtxoType::ProduceBlockFromStake,
            median_time,
            UtxoState::Confirmed.into(),
            WithLocked::Unlocked,
        );
        let (kernel_input_outpoint, (kernel_input_utxo, _token_id)) = utxos
            .into_iter()
            .find(|(_kernel_input_outpoint, (kernel_input_utxo, _token_id))| {
                let utxo_pool_id = match kernel_input_utxo {
                    TxOutput::CreateStakePool(pool_id, _) => *pool_id,
                    TxOutput::ProduceBlockFromStake(_, pool_id) => *pool_id,
                    TxOutput::Transfer(_, _)
                    | TxOutput::LockThenTransfer(_, _, _)
                    | TxOutput::Burn(_)
                    | TxOutput::CreateDelegationId(_, _)
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::IssueFungibleToken(_)
                    | TxOutput::IssueNft(_, _, _) => panic!("Unexpected UTXO"),
                };
                pool_id == utxo_pool_id
            })
            .ok_or(WalletError::UnknownPoolId(pool_id))?;
        let kernel_input: TxInput = kernel_input_outpoint.into();

        let stake_destination = get_tx_output_destination(kernel_input_utxo)
            .expect("must succeed for CreateStakePool and ProduceBlockFromStake outputs");
        let stake_private_key = self
            .key_chain
            .get_private_key_for_destination(stake_destination, db_tx)?
            .ok_or(WalletError::KeyChainError(KeyChainError::NoPrivateKeyFound))?
            .private_key();

        let (vrf_private_key, _vrf_public_key) = self.get_vrf_key(db_tx)?;

        let data = PoSGenerateBlockInputData::new(
            stake_private_key,
            vrf_private_key,
            pool_id,
            vec![kernel_input],
            vec![kernel_input_utxo.clone()],
        );

        Ok(data)
    }

    fn sign_transaction_from_req(
        &self,
        request: SendRequest,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> WalletResult<SignedTransaction> {
        let (tx, input_utxos, destinations) = request.into_transaction_and_utxos()?;
        let destinations = destinations.iter().collect_vec();
        let input_utxos = input_utxos.iter().map(Option::as_ref).collect_vec();

        self.sign_transaction(tx, destinations.as_slice(), input_utxos.as_slice(), db_tx)
    }

    // TODO: Use a different type to support partially signed transactions
    fn sign_transaction(
        &self,
        tx: Transaction,
        destinations: &[&Destination],
        input_utxos: &[Option<&TxOutput>],
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> WalletResult<SignedTransaction> {
        let witnesses = destinations
            .iter()
            .copied()
            .enumerate()
            .map(|(i, destination)| {
                if *destination == Destination::AnyoneCanSpend {
                    Ok(InputWitness::NoSignature(None))
                } else {
                    let private_key = self
                        .key_chain
                        .get_private_key_for_destination(destination, db_tx)?
                        .ok_or(WalletError::KeyChainError(KeyChainError::NoPrivateKeyFound))?
                        .private_key();

                    let sighash_type =
                        SigHashType::try_from(SigHashType::ALL).expect("Should not fail");

                    StandardInputSignature::produce_uniparty_signature_for_input(
                        &private_key,
                        sighash_type,
                        destination.clone(),
                        &tx,
                        input_utxos,
                        i,
                    )
                    .map(InputWitness::Standard)
                    .map_err(WalletError::TransactionSig)
                }
            })
            .collect::<Result<Vec<InputWitness>, _>>()?;

        let tx = SignedTransaction::new(tx, witnesses)?;

        Ok(tx)
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

    /// Get a new address that hasn't been used before
    pub fn get_new_address(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        purpose: KeyPurpose,
    ) -> WalletResult<(ChildNumber, Address<Destination>)> {
        Ok(self.key_chain.issue_address(db_tx, purpose)?)
    }

    /// Get a new public key that hasn't been used before
    pub fn get_new_public_key<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        purpose: KeyPurpose,
    ) -> WalletResult<PublicKey> {
        Ok(self.key_chain.issue_key(db_tx, purpose)?.into_public_key())
    }

    pub fn get_all_issued_addresses(&self) -> BTreeMap<ChildNumber, Address<Destination>> {
        self.key_chain.get_all_issued_addresses()
    }

    pub fn get_addresses_usage(&self) -> &KeychainUsageState {
        self.key_chain.get_addresses_usage_state()
    }

    /// Return true if this transaction output is can be spent by this account or if it is being
    /// watched.
    fn is_mine_or_watched(&self, txo: &TxOutput) -> bool {
        get_tx_output_destination(txo).map_or(false, |d| self.is_mine_or_watched_destination(d))
    }

    /// Return true if this destination can be spent by this account or if it is being watched.
    fn is_mine_or_watched_destination(&self, destination: &Destination) -> bool {
        match destination {
            Destination::Address(pkh) => self.key_chain.is_public_key_hash_mine(pkh),
            Destination::PublicKey(pk) => self.key_chain.is_public_key_mine(pk),
            Destination::AnyoneCanSpend => false,
            Destination::ScriptHash(_) | Destination::ClassicMultisig(_) => false,
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
        if let Some(d) = get_tx_output_destination(output) {
            match d {
                Destination::Address(pkh) => {
                    let found = self.key_chain.mark_public_key_hash_as_used(db_tx, pkh)?;
                    if found {
                        return Ok(true);
                    }
                }
                Destination::PublicKey(pk) => {
                    let found = self.key_chain.mark_public_key_as_used(db_tx, pk)?;
                    if found {
                        return Ok(true);
                    }
                }
                Destination::AnyoneCanSpend => return Ok(false),
                Destination::ClassicMultisig(_) | Destination::ScriptHash(_) => {}
            }
        }
        Ok(false)
    }

    pub fn get_balance(
        &self,
        utxo_types: UtxoTypes,
        utxo_states: UtxoStates,
        median_time: BlockTimestamp,
        with_locked: WithLocked,
    ) -> WalletResult<BTreeMap<Currency, Amount>> {
        let amounts_by_currency = group_utxos_for_input(
            self.get_utxos(utxo_types, median_time, utxo_states, with_locked).into_iter(),
            |(_, (tx_output, _))| tx_output,
            |total: &mut Amount, _, amount| -> WalletResult<()> {
                *total = (*total + amount).ok_or(WalletError::OutputAmountOverflow)?;
                Ok(())
            },
            |(_, (_, token_id))| token_id.ok_or(WalletError::MissingTokenId),
            Amount::ZERO,
        )?;
        Ok(amounts_by_currency)
    }

    pub fn get_utxos(
        &self,
        utxo_types: UtxoTypes,
        median_time: BlockTimestamp,
        utxo_states: UtxoStates,
        with_locked: WithLocked,
    ) -> BTreeMap<UtxoOutPoint, (&TxOutput, Option<TokenId>)> {
        let current_block_info = BlockInfo {
            height: self.account_info.best_block_height(),
            timestamp: median_time,
        };
        let mut all_outputs =
            self.output_cache
                .utxos_with_token_ids(current_block_info, utxo_states, with_locked);
        all_outputs.retain(|_outpoint, (txo, _token_id)| {
            self.is_mine_or_watched(txo)
                && get_utxo_type(txo).is_some_and(|v| utxo_types.contains(v))
        });
        all_outputs
    }

    pub fn get_transaction_list(&self, skip: usize, count: usize) -> WalletResult<TransactionList> {
        get_transaction_list(&self.key_chain, &self.output_cache, skip, count)
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
            wallet_events.del_transaction(&tx_id);
            self.output_cache.remove_tx(&tx_id.into_item_id())?;
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
                .map_or(false, |txo| self.is_mine_or_watched(txo)),
            TxInput::Account(outpoint) => match outpoint.account() {
                AccountOp::SpendDelegationBalance(delegation_id, _) => {
                    self.find_delegation(delegation_id).is_ok()
                }
                AccountOp::MintTokens(token_id, _)
                | AccountOp::UnmintTokens(token_id)
                | AccountOp::LockTokenSupply(token_id) => self.find_token(token_id).is_ok(),
            },
        });
        let relevant_outputs = self.mark_outputs_as_seen(db_tx, tx.outputs())?;
        if relevant_inputs || relevant_outputs {
            let id = AccountWalletTxId::new(self.get_account_id(), tx.id());
            db_tx.set_transaction(&id, &tx)?;
            wallet_events.set_transaction(&id, &tx);
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
                        let wallet_tx = WalletTx::Tx(TxData::new(
                            signed_tx.transaction().clone().into(),
                            tx_state,
                        ));
                        new_tx_was_added |= self
                            .add_wallet_tx_if_relevant_and_remove_from_user_txs(
                                db_tx,
                                wallet_events,
                                wallet_tx,
                                signed_tx,
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

    /// Add a new wallet tx if relevant for this account and remove it from the user transactions
    /// to not be rebroadcast again
    fn add_wallet_tx_if_relevant_and_remove_from_user_txs(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        wallet_events: &impl WalletEvents,
        wallet_tx: WalletTx,
        signed_tx: &SignedTransaction,
    ) -> Result<bool, WalletError> {
        Ok(
            if self.add_wallet_tx_if_relevant(db_tx, wallet_events, wallet_tx)? {
                let id = AccountWalletCreatedTxId::new(
                    self.get_account_id(),
                    signed_tx.transaction().get_id(),
                );
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
        let mut not_added = vec![];
        let mut counter = db_tx
            .get_account_unconfirmed_tx_counter(&self.get_account_id())?
            .ok_or(WalletError::WalletNotInitialized)?;

        for signed_tx in transactions {
            counter += 1;
            let tx_state = make_tx_state(counter);
            let wallet_tx = WalletTx::Tx(TxData::new(
                signed_tx.transaction().clone().into(),
                tx_state,
            ));

            if !self.add_wallet_tx_if_relevant(db_tx, wallet_events, wallet_tx)? {
                not_added.push((signed_tx, tx_state));
            }
        }

        // check them again after adding all we could
        // and keep looping as long as we add a new tx
        loop {
            let mut not_added_next = vec![];
            for (signed_tx, tx_state) in not_added.iter() {
                let wallet_tx = WalletTx::Tx(TxData::new(
                    signed_tx.transaction().clone().into(),
                    *tx_state,
                ));

                if !self.add_wallet_tx_if_relevant(db_tx, wallet_events, wallet_tx)? {
                    not_added_next.push((*signed_tx, *tx_state));
                }
            }

            // if no new tx was added break
            if not_added.len() == not_added_next.len() {
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

    pub fn pending_transactions(&self) -> Vec<&WithId<Transaction>> {
        self.output_cache.pending_transactions()
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
}

fn group_preselected_inputs(
    request: &SendRequest,
    current_fee_rate: FeeRate,
) -> Result<BTreeMap<Currency, (Amount, Amount)>, WalletError> {
    let mut preselected_inputs = BTreeMap::new();
    for (input, destination) in request.inputs().iter().zip(request.destinations()) {
        let input_size = serialization::Encode::encoded_size(&input);
        let inp_sig_size = input_signature_size(destination)?;

        let fee = current_fee_rate
            .compute_fee(input_size + inp_sig_size)
            .map_err(|_| UtxoSelectorError::AmountArithmeticError)?;

        let mut update_preselected_inputs =
            |currency: Currency, amount: Amount, fee: Amount| -> WalletResult<()> {
                match preselected_inputs.entry(currency) {
                    Entry::Vacant(entry) => {
                        entry.insert((amount, fee));
                    }
                    Entry::Occupied(mut entry) => {
                        let (existing_amount, existing_fee) = entry.get_mut();
                        *existing_amount =
                            (*existing_amount + amount).ok_or(WalletError::OutputAmountOverflow)?;
                        *existing_fee =
                            (*existing_fee + fee).ok_or(WalletError::OutputAmountOverflow)?;
                    }
                }
                Ok(())
            };

        match input {
            TxInput::Utxo(_) => {}
            TxInput::Account(acc) => match acc.account() {
                AccountOp::MintTokens(token_id, amount) => {
                    update_preselected_inputs(Currency::Token(*token_id), *amount, *fee)?;
                }
                AccountOp::LockTokenSupply(_) | AccountOp::UnmintTokens(_) => {}
                AccountOp::SpendDelegationBalance(_, amount) => {
                    update_preselected_inputs(Currency::Coin, *amount, *fee)?;
                }
            },
        }
    }
    Ok(preselected_inputs)
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub enum Currency {
    Coin,
    Token(TokenId),
}

fn group_outputs<T, Grouped: Clone>(
    outputs: impl Iterator<Item = T>,
    get_tx_output: impl Fn(&T) -> &TxOutput,
    mut combiner: impl FnMut(&mut Grouped, &T, Amount) -> WalletResult<()>,
    init: Grouped,
) -> WalletResult<BTreeMap<Currency, Grouped>> {
    let mut coin_grouped = init.clone();
    let mut tokens_grouped: BTreeMap<Currency, Grouped> = BTreeMap::new();

    // Iterate over all outputs and group them up by currency
    for output in outputs {
        // Get the supported output value
        let output_value = match get_tx_output(&output) {
            TxOutput::Transfer(v, _) | TxOutput::LockThenTransfer(v, _, _) | TxOutput::Burn(v) => {
                v.clone()
            }
            TxOutput::CreateStakePool(_, stake) => OutputValue::Coin(stake.value()),
            TxOutput::DelegateStaking(amount, _) => OutputValue::Coin(*amount),
            TxOutput::CreateDelegationId(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _) => continue,
            TxOutput::ProduceBlockFromStake(_, _) => {
                return Err(WalletError::UnsupportedTransactionOutput(Box::new(
                    get_tx_output(&output).clone(),
                )))
            }
        };

        match output_value {
            OutputValue::Coin(output_amount) => {
                combiner(&mut coin_grouped, &output, output_amount)?;
            }
            OutputValue::TokenV0(token_data) => {
                let token_data = token_data.as_ref();
                match token_data {
                    TokenData::TokenTransfer(token_transfer) => {
                        let total_token_amount = tokens_grouped
                            .entry(Currency::Token(token_transfer.token_id))
                            .or_insert_with(|| init.clone());

                        combiner(total_token_amount, &output, token_transfer.amount)?;
                    }
                    TokenData::TokenIssuance(_) | TokenData::NftIssuance(_) => {}
                }
            }
            OutputValue::TokenV1(id, amount) => {
                let total_token_amount =
                    tokens_grouped.entry(Currency::Token(id)).or_insert_with(|| init.clone());

                combiner(total_token_amount, &output, amount)?;
            }
        }
    }

    tokens_grouped.insert(Currency::Coin, coin_grouped);
    Ok(tokens_grouped)
}

fn group_utxos_for_input<T, Grouped: Clone>(
    outputs: impl Iterator<Item = T>,
    get_tx_output: impl Fn(&T) -> &TxOutput,
    mut combiner: impl FnMut(&mut Grouped, &T, Amount) -> WalletResult<()>,
    get_token_id: impl Fn(&T) -> WalletResult<TokenId>,
    init: Grouped,
) -> WalletResult<BTreeMap<Currency, Grouped>> {
    let mut coin_grouped = init.clone();
    let mut tokens_grouped: BTreeMap<Currency, Grouped> = BTreeMap::new();

    // Iterate over all outputs and group them up by currency
    for output in outputs {
        // Get the supported output value
        let output_value = match get_tx_output(&output) {
            TxOutput::Transfer(v, _) | TxOutput::LockThenTransfer(v, _, _) => v.clone(),
            TxOutput::CreateStakePool(_, stake) => OutputValue::Coin(stake.value()),
            TxOutput::IssueNft(token_id, _, _) => {
                OutputValue::TokenV1(*token_id, Amount::from_atoms(1))
            }
            TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::IssueFungibleToken(_) => {
                return Err(WalletError::UnsupportedTransactionOutput(Box::new(
                    get_tx_output(&output).clone(),
                )))
            }
        };

        match output_value {
            OutputValue::Coin(output_amount) => {
                combiner(&mut coin_grouped, &output, output_amount)?;
            }
            OutputValue::TokenV0(token_data) => {
                let token_data = token_data.as_ref();
                match token_data {
                    TokenData::TokenTransfer(token_transfer) => {
                        let total_token_amount = tokens_grouped
                            .entry(Currency::Token(token_transfer.token_id))
                            .or_insert_with(|| init.clone());

                        combiner(total_token_amount, &output, token_transfer.amount)?;
                    }
                    TokenData::TokenIssuance(token_issuance) => {
                        let token_id = get_token_id(&output)?;
                        let total_token_amount = tokens_grouped
                            .entry(Currency::Token(token_id))
                            .or_insert_with(|| init.clone());

                        combiner(total_token_amount, &output, token_issuance.amount_to_issue)?;
                    }
                    TokenData::NftIssuance(_) => {
                        let token_id = get_token_id(&output)?;
                        let total_token_amount = tokens_grouped
                            .entry(Currency::Token(token_id))
                            .or_insert_with(|| init.clone());

                        combiner(total_token_amount, &output, Amount::from_atoms(1))?;
                    }
                }
            }
            OutputValue::TokenV1(id, amount) => {
                let total_token_amount =
                    tokens_grouped.entry(Currency::Token(id)).or_insert_with(|| init.clone());

                combiner(total_token_amount, &output, amount)?;
            }
        }
    }

    tokens_grouped.insert(Currency::Coin, coin_grouped);
    Ok(tokens_grouped)
}

/// Return the encoded size for a SignedTransaction with specified outputs and empty inputs and
/// signatures
pub fn tx_size_with_outputs(outputs: &[TxOutput]) -> usize {
    let tx = SignedTransaction::new(
        Transaction::new(1, vec![], outputs.into()).expect("should not fail"),
        vec![],
    )
    .expect("should not fail");
    serialization::Encode::encoded_size(&tx)
}

/// Return the encoded size of an input signature
fn input_signature_size(destination: &Destination) -> WalletResult<usize> {
    // Sizes calculated upfront
    match destination {
        Destination::Address(_) => Ok(103),
        Destination::PublicKey(_) => Ok(69),
        Destination::AnyoneCanSpend => Ok(2),
        Destination::ScriptHash(_) | Destination::ClassicMultisig(_) => Err(
            WalletError::UnsupportedInputDestination(destination.clone()),
        ),
    }
}

/// Calculate the amount of fee that needs to be paid to add a change output
/// Returns the Amounts for Coin output and Token output
fn coin_and_token_output_change_fees(feerate: mempool::FeeRate) -> WalletResult<(Amount, Amount)> {
    let pub_key_hash = PublicKeyHash::from_low_u64_ne(0);

    let destination = Destination::Address(pub_key_hash);

    let coin_output = TxOutput::Transfer(OutputValue::Coin(Amount::MAX), destination.clone());
    let token_output = TxOutput::Transfer(
        OutputValue::TokenV0(Box::new(TokenData::TokenTransfer(TokenTransfer {
            token_id: TokenId::zero(),
            // TODO: as the  amount is compact there is an edge case where those extra few bytes of
            // size can cause the output fee to be go over the available amount of coins thus not
            // including a change output, and losing money for the user
            // e.g. available money X and need to transfer Y and the difference Z = X - Y is just
            // enough the make an output with change but the amount having single byte encoding
            // but by using Amount::MAX the algorithm thinks that the change output will cost more
            // than Z and it will not create a change output
            amount: Amount::MAX,
        }))),
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
