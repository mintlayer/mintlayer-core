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
mod utxo_selector;

pub use utxo_selector::CoinSelectorError;

use crate::account::utxo_selector::{select_coins, OutputGroup};
use crate::key_chain::{
    make_path_to_vrf_key, vrf_from_private_key, AccountKeyChain, KeyChainError,
};
use crate::send_request::{make_address_output, make_address_output_token, make_stake_output};
use crate::{SendRequest, WalletError, WalletResult};
use common::address::Address;
use common::chain::signature::inputsig::standard_signature::StandardInputSignature;
use common::chain::signature::inputsig::InputWitness;
use common::chain::signature::sighash::sighashtype::SigHashType;
use common::chain::signature::TransactionSigError;
use common::chain::tokens::{OutputValue, TokenData, TokenId};
use common::chain::{
    Block, ChainConfig, Destination, GenBlock, SignedTransaction, TxInput, TxOutput, UtxoOutPoint,
};
use common::primitives::per_thousand::PerThousand;
use common::primitives::{Amount, BlockHeight, Id};
use consensus::PoSGenerateBlockInputData;
use crypto::key::hdkd::u31::U31;
use crypto::key::PublicKey;
use crypto::vrf::{VRFPrivateKey, VRFPublicKey};
use itertools::Itertools;
use std::collections::BTreeMap;
use std::ops::Add;
use std::sync::Arc;
use wallet_storage::{
    StoreTxRo, StoreTxRw, WalletStorageReadLocked, WalletStorageReadUnlocked,
    WalletStorageWriteLocked, WalletStorageWriteUnlocked,
};
use wallet_types::utxo_types::{get_utxo_type, UtxoType, UtxoTypes};
use wallet_types::wallet_tx::{BlockData, TxData, TxState};
use wallet_types::{AccountId, AccountInfo, AccountWalletTxId, KeyPurpose, WalletTx};

use self::output_cache::OutputCache;
use self::utxo_selector::PayFee;

pub struct Account {
    chain_config: Arc<ChainConfig>,
    key_chain: AccountKeyChain,
    output_cache: OutputCache,
    account_info: AccountInfo,
}

impl Account {
    pub fn load_from_database<B: storage::Backend>(
        chain_config: Arc<ChainConfig>,
        db_tx: &StoreTxRo<B>,
        id: &AccountId,
    ) -> WalletResult<Account> {
        let mut account_infos = db_tx.get_accounts_info()?;
        let account_info =
            account_infos.remove(id).ok_or(KeyChainError::NoAccountFound(id.clone()))?;

        let key_chain =
            AccountKeyChain::load_from_database(chain_config.clone(), db_tx, id, &account_info)?;

        let txs = db_tx.get_transactions(&key_chain.get_account_id())?;
        let output_cache = OutputCache::new(txs);

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
    ) -> WalletResult<Account> {
        let account_id = key_chain.get_account_id();

        let account_info = AccountInfo::new(
            &chain_config,
            key_chain.account_index(),
            key_chain.account_public_key().clone(),
            key_chain.lookahead_size(),
        );

        db_tx.set_account(&account_id, &account_info)?;

        let output_cache = OutputCache::empty();

        let mut account = Account {
            chain_config,
            key_chain,
            output_cache,
            account_info,
        };

        account.scan_genesis(db_tx)?;

        Ok(account)
    }

    pub fn process_send_request(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        mut request: SendRequest,
    ) -> WalletResult<SignedTransaction> {
        // TODO: allow to pay fees with different currency?
        let pay_fee_with_currency = Currency::Coin;

        let mut output_currency_amounts = group_outputs(
            request.outputs().iter(),
            |&output| output,
            |grouped: &mut Amount, _, new_amount| -> WalletResult<()> {
                *grouped = grouped.add(new_amount).ok_or(WalletError::OutputAmountOverflow)?;
                Ok(())
            },
        )?;

        // TODO: get current_fee_rate and long_term_fee_rate
        // let current_fee_rate = 1;
        // let long_term_fee_rate = 1;
        //
        // TODO: Calculate network fee from fee rate and expected transaction size
        let network_fee = Amount::from_atoms(10000);

        let utxos_by_currency = group_utxos_for_input(
            self.get_utxos(UtxoType::Transfer.into()).into_iter(),
            |(_, (tx_output, _))| tx_output,
            |grouped: &mut Vec<(UtxoOutPoint, TxOutput)>, element, _| -> WalletResult<()> {
                grouped.push((element.0.clone(), element.1 .0.clone()));
                Ok(())
            },
            |(_, (_, token_id))| token_id.ok_or(WalletError::MissingTokenId),
        )?;

        let amount_to_be_paied_in_currency_with_fees =
            output_currency_amounts.remove(&pay_fee_with_currency).unwrap_or_default();

        let mut total_fees_not_payed = network_fee;

        let utxo_to_output_group = |(outpoint, txo): &(UtxoOutPoint, TxOutput)| {
            // TODO: using current_fee_rate and long_term_fee_rate and the size in bytes
            // calculate the fee and long_term_fee_rate
            let fee = Amount::ZERO;
            let long_term_fee = Amount::ZERO;
            // TODO: calculate weight from the size of the input
            let weight = 0;
            OutputGroup::new((outpoint.clone(), txo.clone()), fee, long_term_fee, weight)
        };

        let mut selected_inputs: BTreeMap<_, _> = output_currency_amounts
            .iter()
            .map(|(currency, output_amount)| -> WalletResult<_> {
                let utxos = utxos_by_currency
                    .get(currency)
                    .unwrap_or(&vec![])
                    .iter()
                    // TODO: group outputs by destination
                    .map(utxo_to_output_group)
                    .try_collect()?;

                let selection_result =
                    select_coins(utxos, *output_amount, PayFee::DoNotPayFeeWithThisCurrency)?;

                total_fees_not_payed =
                    (total_fees_not_payed + selection_result.get_total_fees()).expect("");

                Ok((currency.clone(), selection_result))
            })
            .try_collect()?;

        let utxos = utxos_by_currency
            .get(&pay_fee_with_currency)
            .unwrap_or(&vec![])
            .iter()
            // TODO: group outputs by destination
            .map(utxo_to_output_group)
            .try_collect()?;

        let amount_to_be_paied_in_currency_with_fees =
            (amount_to_be_paied_in_currency_with_fees + total_fees_not_payed).expect("");
        let selection_result = select_coins(
            utxos,
            amount_to_be_paied_in_currency_with_fees,
            PayFee::PayFeeWithThisCurrency,
        )?;

        output_currency_amounts.insert(
            pay_fee_with_currency.clone(),
            (amount_to_be_paied_in_currency_with_fees + selection_result.get_total_fees())
                .ok_or(WalletError::OutputAmountOverflow)?,
        );
        selected_inputs.insert(pay_fee_with_currency, selection_result);

        // Check outputs against inputs and create change
        for (currency, output_amount) in output_currency_amounts {
            let input_amount = selected_inputs
                .get(&currency)
                .map_or(Amount::ZERO, |result| result.get_total_value());

            let change_amount = (input_amount - output_amount)
                .ok_or(WalletError::NotEnoughUtxo(input_amount, output_amount))?;
            if change_amount > Amount::ZERO {
                let change_address = self.get_new_address(db_tx, KeyPurpose::Change)?;
                let change_output = match currency {
                    Currency::Coin => make_address_output(change_address, change_amount)?,
                    Currency::Token(token_id) => {
                        make_address_output_token(change_address, change_amount, token_id)?
                    }
                };
                request = request.with_outputs([change_output]);
            }
        }
        let selected_inputs = selected_inputs.into_iter().flat_map(|x| x.1.into_output_pairs());

        request = request.with_inputs(selected_inputs);

        // TODO: Randomize inputs and outputs

        let tx = self.sign_transaction(request, db_tx)?;
        Ok(tx)
    }

    fn get_vrf_key(
        &self,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> WalletResult<(VRFPrivateKey, VRFPublicKey)> {
        let vrf_key_path = make_path_to_vrf_key(&self.chain_config, self.account_index());
        let private_key =
            self.key_chain.get_private_key_for_path(&vrf_key_path, db_tx)?.private_key();
        Ok(vrf_from_private_key(&private_key))
    }

    pub fn get_vrf_public_key(
        &self,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> WalletResult<VRFPublicKey> {
        let vrf_keys = self.get_vrf_key(db_tx)?;
        Ok(vrf_keys.1)
    }

    pub fn create_stake_pool_tx(
        &mut self,
        db_tx: &mut impl WalletStorageWriteUnlocked,
        amount: Amount,
        decomission_key: Option<PublicKey>,
    ) -> WalletResult<SignedTransaction> {
        // process_send_request can fill UTXOs, but the first UTXO is needed in advance to calculate pool_id

        // TODO: Add support for LockThenTransfer
        let utxos = self
            .get_utxos(UtxoType::Transfer.into())
            .into_iter()
            .map(|(outpoint, (txo, _token_id))| (outpoint, txo.clone()))
            .collect::<Vec<(UtxoOutPoint, TxOutput)>>();

        let input0 = utxos.get(0).ok_or(WalletError::NoUtxos)?;
        let pool_id = pos_accounting::make_pool_id(&input0.0);

        // TODO: Use other accounts here
        let staker = self.key_chain.issue_key(db_tx, KeyPurpose::ReceiveFunds)?;
        let decommission_key = match decomission_key {
            Some(key) => key,
            None => self.key_chain.issue_key(db_tx, KeyPurpose::ReceiveFunds)?.into_public_key(),
        };
        let (_vrf_private_key, vrf_public_key) = self.get_vrf_key(db_tx)?;

        let stake_output = make_stake_output(
            pool_id,
            amount,
            staker.into_public_key(),
            decommission_key,
            vrf_public_key,
            PerThousand::new(1000).expect("must not fail"),
            Amount::ZERO,
        )?;

        let request = SendRequest::new().with_outputs([stake_output]);

        self.process_send_request(db_tx, request)
    }

    pub fn get_pos_gen_block_data(
        &self,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> WalletResult<PoSGenerateBlockInputData> {
        let utxos = self.get_utxos(UtxoType::CreateStakePool | UtxoType::ProduceBlockFromStake);
        // TODO: Select by pool_id if there is more than one UTXO
        let (kernel_input_outpoint, (kernel_input_utxo, _token_id)) =
            utxos.into_iter().next().ok_or(WalletError::NoUtxos)?;
        let kernel_input: TxInput = kernel_input_outpoint.into();

        let stake_destination = Self::get_tx_output_destination(kernel_input_utxo)
            .expect("must succeed for CreateStakePool and ProduceBlockFromStake outputs");
        let stake_private_key = self
            .key_chain
            .get_private_key_for_destination(stake_destination, db_tx)?
            .ok_or(WalletError::KeyChainError(KeyChainError::NoPrivateKeyFound))?
            .private_key();

        let pool_id = match kernel_input_utxo {
            TxOutput::CreateStakePool(pool_id, _) => pool_id,
            TxOutput::ProduceBlockFromStake(_, pool_id) => pool_id,
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _) => panic!("Unexpected UTXO"),
        };

        let (vrf_private_key, _vrf_public_key) = self.get_vrf_key(db_tx)?;

        let data = PoSGenerateBlockInputData::new(
            stake_private_key,
            vrf_private_key,
            *pool_id,
            vec![kernel_input],
            vec![kernel_input_utxo.clone()],
        );

        Ok(data)
    }

    /// Calculate the output amount for coins and tokens
    fn calculate_output_amounts<'a>(
        outputs: impl Iterator<Item = (&'a TxOutput, Option<TokenId>)>,
    ) -> WalletResult<(Amount, BTreeMap<TokenId, Amount>)> {
        let mut coin_amount = Amount::ZERO;
        let mut tokens_amounts: BTreeMap<TokenId, Amount> = BTreeMap::new();

        // Iterate over all outputs and calculate the coin and tokens amounts
        for output in outputs {
            // Get the supported output value
            let output_value = match output.0 {
                TxOutput::Transfer(v, _)
                | TxOutput::LockThenTransfer(v, _, _)
                | TxOutput::Burn(v) => Some(v.clone()),
                TxOutput::CreateStakePool(_, stake) => Some(OutputValue::Coin(stake.value())),
                TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _) => None,
            };

            match output_value {
                Some(OutputValue::Coin(output_amount)) => {
                    coin_amount =
                        coin_amount.add(output_amount).ok_or(WalletError::OutputAmountOverflow)?
                }
                Some(OutputValue::Token(token_data)) => {
                    let token_data = token_data.as_ref();
                    match token_data {
                        TokenData::TokenTransfer(token_transfer) => {
                            let total_token_amount = tokens_amounts
                                .entry(token_transfer.token_id)
                                .or_insert(Amount::ZERO);
                            *total_token_amount = total_token_amount
                                .add(token_transfer.amount)
                                .ok_or(WalletError::OutputAmountOverflow)?;
                        }
                        TokenData::TokenIssuance(token_issuance) => {
                            let total_token_amount = tokens_amounts
                                .entry(output.1.ok_or(WalletError::MissingTokenId)?)
                                .or_insert(Amount::ZERO);
                            *total_token_amount = total_token_amount
                                .add(token_issuance.amount_to_issue)
                                .ok_or(WalletError::OutputAmountOverflow)?;
                        }
                        TokenData::NftIssuance(_) => {
                            let total_token_amount = tokens_amounts
                                .entry(output.1.ok_or(WalletError::MissingTokenId)?)
                                .or_insert(Amount::ZERO);
                            *total_token_amount = total_token_amount
                                .add(Amount::from_atoms(1))
                                .ok_or(WalletError::OutputAmountOverflow)?;
                        }
                    }
                }
                None => {}
            }
        }
        Ok((coin_amount, tokens_amounts))
    }

    // TODO: Use a different type to support partially signed transactions
    fn sign_transaction(
        &self,
        req: SendRequest,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> WalletResult<SignedTransaction> {
        let (tx, utxos) = req.into_transaction_and_utxos()?;
        let inputs = tx.inputs();
        let input_utxos = utxos.iter().map(Some).collect::<Vec<_>>();
        if utxos.len() != inputs.len() {
            return Err(
                TransactionSigError::InvalidUtxoCountVsInputs(utxos.len(), inputs.len()).into(),
            );
        }

        let witnesses = utxos
            .iter()
            .enumerate()
            .map(|(i, utxo)| {
                // Get the destination from this utxo
                let destination = Self::get_tx_output_destination(utxo).ok_or_else(|| {
                    WalletError::UnsupportedTransactionOutput(Box::new(utxo.clone()))
                })?;

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
                        &input_utxos,
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

    /// Get a new address that hasn't been used before
    pub fn get_new_address(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        purpose: KeyPurpose,
    ) -> WalletResult<Address> {
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

    fn get_tx_output_destination(txo: &TxOutput) -> Option<&Destination> {
        // TODO: Reuse code from TxVerifier
        match txo {
            TxOutput::Transfer(_, d) | TxOutput::LockThenTransfer(_, d, _) => Some(d),
            TxOutput::CreateStakePool(_, data) => Some(data.staker()),
            TxOutput::ProduceBlockFromStake(d, _) => Some(d),
            TxOutput::Burn(_)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _) => None,
        }
    }

    /// Return true if this transaction output is can be spent by this account or if it is being
    /// watched.
    fn is_mine_or_watched(&self, txo: &TxOutput) -> bool {
        // TODO: Should we really report `AnyoneCanSpend` as own?
        Self::get_tx_output_destination(txo).map_or(false, |d| match d {
            Destination::Address(pkh) => self.key_chain.is_public_key_hash_mine(pkh),
            Destination::PublicKey(pk) => self.key_chain.is_public_key_mine(pk),
            Destination::AnyoneCanSpend => true,
            Destination::ScriptHash(_) | Destination::ClassicMultisig(_) => false,
        })
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
        if let Some(d) = Self::get_tx_output_destination(output) {
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
                Destination::AnyoneCanSpend => return Ok(true),
                Destination::ClassicMultisig(_) | Destination::ScriptHash(_) => {}
            }
        }
        Ok(false)
    }

    pub fn get_balance(
        &self,
        utxo_types: UtxoTypes,
    ) -> WalletResult<(Amount, BTreeMap<TokenId, Amount>)> {
        let utxos = self.get_utxos(utxo_types);
        let balances = Self::calculate_output_amounts(utxos.into_values())?;
        Ok(balances)
    }

    pub fn get_utxos(
        &self,
        utxo_types: UtxoTypes,
    ) -> BTreeMap<UtxoOutPoint, (&TxOutput, Option<TokenId>)> {
        let mut all_outputs = self.output_cache.utxos_with_token_ids();
        all_outputs.retain(|_outpoint, (txo, _token_id)| {
            self.is_mine_or_watched(txo) && utxo_types.contains(get_utxo_type(txo))
        });
        all_outputs
    }

    fn reset_to_height<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        common_block_height: BlockHeight,
    ) -> WalletResult<()> {
        let revoked_txs = self
            .output_cache
            .txs()
            .iter()
            .filter_map(|(id, tx)| match tx.state() {
                TxState::Confirmed(height) => {
                    if height > common_block_height {
                        Some(id.clone())
                    } else {
                        None
                    }
                }
                TxState::Inactive | TxState::Conflicted(_) | TxState::InMempool => None,
            })
            .collect::<Vec<_>>();

        for tx_id in revoked_txs {
            db_tx.del_transaction(&tx_id)?;
            self.output_cache.remove_tx(&tx_id);
        }

        Ok(())
    }

    /// Store a block or tx in the DB if any of the inputs or outputs belong to this wallet
    fn add_wallet_tx_if_relevant(
        &mut self,
        db_tx: &mut impl WalletStorageWriteLocked,
        tx: WalletTx,
    ) -> WalletResult<()> {
        let relevant_inputs = tx.inputs().iter().any(|input| match input {
            TxInput::Utxo(outpoint) => self.output_cache.outpoints().contains(outpoint),
            TxInput::Account(_) => false,
        });
        let relevant_outputs = self.mark_outputs_as_seen(db_tx, tx.outputs())?;
        if relevant_inputs || relevant_outputs {
            let id = AccountWalletTxId::new(self.get_account_id(), tx.id());
            db_tx.set_transaction(&id, &tx)?;
            self.output_cache.add_tx(id, tx);
        }
        Ok(())
    }

    fn scan_genesis(&mut self, db_tx: &mut impl WalletStorageWriteLocked) -> WalletResult<()> {
        let chain_config = Arc::clone(&self.chain_config);

        let block = BlockData::from_genesis(chain_config.genesis_block());
        self.add_wallet_tx_if_relevant(db_tx, WalletTx::Block(block))?;

        Ok(())
    }

    pub fn scan_new_blocks<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        common_block_height: BlockHeight,
        blocks: &[Block],
    ) -> WalletResult<()> {
        assert!(!blocks.is_empty());
        assert!(
            common_block_height <= self.account_info.best_block_height(),
            "Invalid common block height: {}, current block height: {}",
            common_block_height,
            self.account_info.best_block_height(),
        );

        if self.account_info.best_block_height() > common_block_height {
            self.reset_to_height(db_tx, common_block_height)?;
        }

        for (index, block) in blocks.iter().enumerate() {
            let block_height = BlockHeight::new(common_block_height.into_int() + index as u64 + 1);
            let tx_state = TxState::Confirmed(block_height);

            let wallet_tx = WalletTx::Block(BlockData::from_block(block, block_height));
            self.add_wallet_tx_if_relevant(db_tx, wallet_tx)?;

            for signed_tx in block.transactions() {
                let wallet_tx = WalletTx::Tx(TxData::new(
                    signed_tx.transaction().clone().into(),
                    tx_state,
                ));
                self.add_wallet_tx_if_relevant(db_tx, wallet_tx)?;
            }
        }

        // Update best_block_height and best_block_id only after successful commit call!
        let best_block_height = (common_block_height.into_int() + blocks.len() as u64).into();
        let best_block_id = blocks.last().expect("blocks not empty").header().block_id().into();

        self.account_info.update_best_block(best_block_height, best_block_id);
        db_tx.set_account(&self.key_chain.get_account_id(), &self.account_info)?;

        Ok(())
    }

    pub fn best_block(&self) -> (Id<GenBlock>, BlockHeight) {
        (
            self.account_info.best_block_id(),
            self.account_info.best_block_height(),
        )
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
enum Currency {
    Coin,
    Token(TokenId),
}

fn group_outputs<T, Grouped: Default>(
    outputs: impl Iterator<Item = T>,
    get_tx_output: impl Fn(&T) -> &TxOutput,
    mut combiner: impl FnMut(&mut Grouped, &T, Amount) -> WalletResult<()>,
) -> WalletResult<BTreeMap<Currency, Grouped>> {
    let mut coin_grouped = Grouped::default();
    let mut tokens_grouped: BTreeMap<Currency, Grouped> = BTreeMap::new();

    // Iterate over all outputs and calculate the coin and tokens amounts
    for output in outputs {
        // Get the supported output value
        let output_value = match get_tx_output(&output) {
            TxOutput::Transfer(v, _) | TxOutput::LockThenTransfer(v, _, _) | TxOutput::Burn(v) => {
                v.clone()
            }
            TxOutput::CreateStakePool(_, stake) => OutputValue::Coin(stake.value()),
            TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _) => {
                return Err(WalletError::UnsupportedTransactionOutput(Box::new(
                    get_tx_output(&output).clone(),
                )))
            }
        };

        match output_value {
            OutputValue::Coin(output_amount) => {
                combiner(&mut coin_grouped, &output, output_amount)?;
            }
            OutputValue::Token(token_data) => {
                let token_data = token_data.as_ref();
                match token_data {
                    TokenData::TokenTransfer(token_transfer) => {
                        let total_token_amount = tokens_grouped
                            .entry(Currency::Token(token_transfer.token_id))
                            .or_default();

                        combiner(total_token_amount, &output, token_transfer.amount)?;
                    }
                    TokenData::TokenIssuance(_) | TokenData::NftIssuance(_) => {}
                }
            }
        }
    }

    tokens_grouped.insert(Currency::Coin, coin_grouped);
    Ok(tokens_grouped)
}

fn group_utxos_for_input<T, Grouped: Default>(
    outputs: impl Iterator<Item = T>,
    get_tx_output: impl Fn(&T) -> &TxOutput,
    mut combiner: impl FnMut(&mut Grouped, &T, Amount) -> WalletResult<()>,
    get_token_id: impl Fn(&T) -> WalletResult<TokenId>,
) -> WalletResult<BTreeMap<Currency, Grouped>> {
    let mut coin_grouped = Grouped::default();
    let mut tokens_grouped: BTreeMap<Currency, Grouped> = BTreeMap::new();

    // Iterate over all outputs and calculate the coin and tokens amounts
    for output in outputs {
        // Get the supported output value
        let output_value = match get_tx_output(&output) {
            TxOutput::Transfer(v, _) | TxOutput::LockThenTransfer(v, _, _) => v.clone(),
            TxOutput::CreateStakePool(_, stake) => OutputValue::Coin(stake.value()),
            TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _) => {
                return Err(WalletError::UnsupportedTransactionOutput(Box::new(
                    get_tx_output(&output).clone(),
                )))
            }
        };

        match output_value {
            OutputValue::Coin(output_amount) => {
                combiner(&mut coin_grouped, &output, output_amount)?;
            }
            OutputValue::Token(token_data) => {
                let token_data = token_data.as_ref();
                match token_data {
                    TokenData::TokenTransfer(token_transfer) => {
                        let total_token_amount = tokens_grouped
                            .entry(Currency::Token(token_transfer.token_id))
                            .or_default();

                        combiner(total_token_amount, &output, token_transfer.amount)?;
                    }
                    TokenData::TokenIssuance(token_issuance) => {
                        let token_id = get_token_id(&output)?;
                        let total_token_amount =
                            tokens_grouped.entry(Currency::Token(token_id)).or_default();

                        combiner(total_token_amount, &output, token_issuance.amount_to_issue)?;
                    }
                    TokenData::NftIssuance(_) => {
                        let token_id = get_token_id(&output)?;
                        let total_token_amount =
                            tokens_grouped.entry(Currency::Token(token_id)).or_default();

                        combiner(total_token_amount, &output, Amount::from_atoms(1))?;
                    }
                }
            }
        }
    }

    tokens_grouped.insert(Currency::Coin, coin_grouped);
    Ok(tokens_grouped)
}

#[cfg(test)]
mod tests;
