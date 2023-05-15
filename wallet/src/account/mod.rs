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

use crate::key_chain::AccountKeyChain;
use crate::{SendRequest, WalletError, WalletResult};
use common::address::Address;
use common::chain::signature::inputsig::standard_signature::StandardInputSignature;
use common::chain::signature::inputsig::InputWitness;
use common::chain::signature::TransactionSigError;
use common::chain::tokens::{OutputValue, TokenData, TokenId};
use common::chain::{
    Block, ChainConfig, Destination, OutPoint, OutPointSourceId, SignedTransaction, Transaction,
    TxOutput,
};
use common::primitives::id::WithId;
use common::primitives::{Amount, BlockHeight, Id, Idable};
use crypto::key::extended::ExtendedPrivateKey;
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::u31::U31;
use std::collections::BTreeMap;
use std::ops::Add;
use std::sync::Arc;
use storage::Backend;
use utxo::{Utxo, UtxoSource};
use wallet_storage::{StoreTxRo, StoreTxRw, WalletStorageRead, WalletStorageWrite};
use wallet_types::{AccountId, AccountOutPointId, AccountTxId, KeyPurpose, TxState, WalletTx};

pub struct Account {
    #[allow(dead_code)] // TODO remove
    chain_config: Arc<ChainConfig>,
    key_chain: AccountKeyChain,
    txs: BTreeMap<Id<Transaction>, WalletTx>,
}

impl Account {
    pub fn load_from_database<B: Backend>(
        chain_config: Arc<ChainConfig>,
        db_tx: &StoreTxRo<B>,
        id: &AccountId,
        root_key: &ExtendedPrivateKey,
    ) -> WalletResult<Account> {
        let key_chain =
            AccountKeyChain::load_from_database(chain_config.clone(), db_tx, id, root_key)?;

        let txs: BTreeMap<Id<Transaction>, WalletTx> = db_tx
            .get_transactions(id)?
            .into_iter()
            .map(|(k, v)| (k.into_item_id(), v))
            .collect();

        Ok(Account {
            chain_config,
            key_chain,
            txs,
        })
    }

    /// Create a new account by providing a key chain
    pub fn new<B: Backend>(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut StoreTxRw<B>,
        key_chain: AccountKeyChain,
    ) -> WalletResult<Account> {
        let account_id = key_chain.get_account_id();
        let account_info = key_chain.get_account_info();

        db_tx.set_account(&account_id, &account_info)?;

        let mut account = Account {
            chain_config,
            key_chain,
            txs: BTreeMap::new(),
        };

        account.scan_genesis_block(db_tx)?;

        Ok(account)
    }

    pub fn complete_and_add_send_request<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        mut request: SendRequest,
    ) -> WalletResult<SignedTransaction> {
        let utxos: BTreeMap<OutPoint, Utxo> = db_tx
            .get_utxo_set(&self.get_account_id())?
            .into_iter()
            .map(|(outpoint, utxo)| (outpoint.into_item_id(), utxo))
            .collect();

        if request.utxos().is_empty() {
            request.select_utxos(utxos)?;
        }

        self.complete_send_request(&mut request)?;
        let tx = request.get_signed_transaction()?;
        // let tx = WithId::new(request.into_transaction());
        // self.add_transaction(db_tx, tx.clone(), TxState::InMempool)?;
        Ok(tx)
    }

    fn complete_send_request(&mut self, request: &mut SendRequest) -> WalletResult<()> {
        if request.is_complete() {
            return Err(WalletError::SendRequestComplete);
        }

        // TODO: Collect UTXOs
        // TODO: Call coin selector

        let (input_coin_amount, input_tokens_amounts) =
            Self::calculate_output_amounts(request.utxos().iter().map(|utxo| utxo.output()))?;

        let (output_coin_amount, output_tokens_amounts) =
            Self::calculate_output_amounts(request.outputs().iter())?;

        // TODO: Fix tokens sending
        utils::ensure!(
            input_tokens_amounts.is_empty() && output_tokens_amounts.is_empty(),
            WalletError::NotImplemented("Token sending")
        );

        // TODO: Add change output(s) and make sure the network fee is reasonable

        utils::ensure!(
            input_coin_amount > output_coin_amount,
            WalletError::NotEnoughUtxo(input_coin_amount, output_coin_amount)
        );

        if request.sign_transaction() {
            self.sign_transaction(request)?;
        }

        request.complete();

        Ok(())
    }

    /// Calculate the output amount for coins and tokens
    fn calculate_output_amounts<'a>(
        outputs: impl Iterator<Item = &'a TxOutput>,
    ) -> WalletResult<(Amount, BTreeMap<TokenId, Amount>)> {
        let mut coin_amount = Amount::ZERO;
        let mut tokens_amounts: BTreeMap<TokenId, Amount> = BTreeMap::new();

        // Iterate over all outputs and calculate the coin and tokens amounts
        for output in outputs {
            // Get the supported output value
            let output_value = match output {
                TxOutput::Transfer(v, _)
                | TxOutput::LockThenTransfer(v, _, _)
                | TxOutput::Burn(v) => v,
                TxOutput::CreateStakePool(_)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::DecommissionPool(_, _, _, _) => {
                    return Err(WalletError::UnsupportedTransactionOutput(Box::new(
                        output.clone(),
                    )))
                }
            };

            match output_value {
                OutputValue::Coin(output_amount) => {
                    coin_amount =
                        coin_amount.add(*output_amount).ok_or(WalletError::OutputAmountOverflow)?
                }
                OutputValue::Token(token_data) => {
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
                        TokenData::TokenIssuance(_) | TokenData::NftIssuance(_) => {
                            return Err(WalletError::UnsupportedTransactionOutput(Box::new(
                                output.clone(),
                            )))
                        }
                    }
                }
            }
        }
        Ok((coin_amount, tokens_amounts))
    }

    fn sign_transaction(&self, req: &mut SendRequest) -> WalletResult<()> {
        let tx = req.get_transaction()?;
        let inputs = tx.inputs();
        let utxos = req.utxos();
        if utxos.len() != inputs.len() {
            return Err(
                TransactionSigError::InvalidUtxoCountVsInputs(utxos.len(), inputs.len()).into(),
            );
        }

        let sighash_types = req.get_sighash_types();
        if sighash_types.len() != inputs.len() {
            return Err(TransactionSigError::InvalidSigHashCountVsInputs(
                sighash_types.len(),
                inputs.len(),
            )
            .into());
        }

        let witnesses = tx
            .inputs()
            .iter()
            .enumerate()
            .map(|(i, _)| {
                // Get the destination from this utxo. This should not fail as we checked that
                // inputs and utxos have the same length
                let destination =
                    Self::get_tx_output_destination(utxos[i].output()).ok_or_else(|| {
                        WalletError::UnsupportedTransactionOutput(Box::new(
                            utxos[i].output().clone(),
                        ))
                    })?;

                if *destination == Destination::AnyoneCanSpend {
                    Ok(InputWitness::NoSignature(None))
                } else {
                    let private_key =
                        self.key_chain.get_private_key_for_destination(destination)?.private_key();

                    let sighash_type = sighash_types[i];

                    let input_utxos = utxos.iter().map(|utxo| utxo.output()).collect::<Vec<_>>();

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

        req.set_witnesses(witnesses)?;

        Ok(())
    }

    pub fn account_index(&self) -> U31 {
        self.key_chain.account_index()
    }

    /// Get the id of this account
    pub fn get_account_id(&self) -> AccountId {
        self.key_chain.get_account_id()
    }

    /// Get a new address that hasn't been used before
    pub fn get_new_address<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        purpose: KeyPurpose,
    ) -> WalletResult<Address> {
        Ok(self.key_chain.issue_address(db_tx, purpose)?)
    }

    #[allow(dead_code)] // TODO remove
    fn add_transaction<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        tx: WithId<Transaction>,
        state: TxState,
    ) -> WalletResult<()> {
        let tx_id = tx.get_id();

        if self.txs.contains_key(&tx_id) {
            return Err(WalletError::DuplicateTransaction(tx_id));
        }

        let account_tx_id = AccountTxId::new(self.get_account_id(), tx_id);
        let wallet_tx = WalletTx::new(tx, state);

        self.add_to_utxos(db_tx, &wallet_tx)?;

        db_tx.set_transaction(&account_tx_id, &wallet_tx)?;
        self.txs.insert(tx_id, wallet_tx);

        Ok(())
    }

    #[allow(dead_code)] // TODO remove
    fn delete_transaction<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        tx_id: Id<Transaction>,
    ) -> WalletResult<()> {
        if !self.txs.contains_key(&tx_id) {
            return Err(WalletError::NoTransactionFound(tx_id));
        }

        let account_tx_id = AccountTxId::new(self.get_account_id(), tx_id);
        db_tx.del_transaction(&account_tx_id)?;

        if let Some(wallet_tx) = self.txs.remove(&tx_id) {
            self.remove_from_utxos(db_tx, &wallet_tx)?;
        }

        Ok(())
    }

    fn add_utxo_if_own<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        output: &TxOutput,
        outpoint: OutPoint,
        utxo_source: utxo::UtxoSource,
    ) -> WalletResult<()> {
        if self.is_available_for_spending(output) && self.is_mine_or_watched(output) {
            let is_block_reward = outpoint.tx_id().get_tx_id().is_none();
            let utxo = Utxo::new(output.clone(), is_block_reward, utxo_source);
            let account_utxo_id = AccountOutPointId::new(self.get_account_id(), outpoint);
            db_tx.set_utxo(&account_utxo_id, utxo)?;
        }
        Ok(())
    }

    fn del_utxo_if_own<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        outpoint: &OutPoint,
    ) -> WalletResult<()> {
        let account_utxo_id = AccountOutPointId::new(self.get_account_id(), outpoint.clone());
        db_tx.del_utxo(&account_utxo_id)?;
        Ok(())
    }

    /// Add the transaction outputs to the UTXO set of the account
    fn add_to_utxos<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        wallet_tx: &WalletTx,
    ) -> WalletResult<()> {
        // For now only confirmed can be added to the UTXO set
        match wallet_tx.state() {
            TxState::Confirmed(_) => {}
            TxState::InMempool | TxState::Conflicted(_) | TxState::Inactive => return Ok(()),
        }

        let tx = wallet_tx.tx();

        for (i, output) in tx.outputs().iter().enumerate() {
            // Check if this output belongs to this wallet or it is watched
            if self.is_available_for_spending(output) && self.is_mine_or_watched(output) {
                let outpoint = OutPoint::new(tx.get_id().into(), i as u32);
                let utxo = Utxo::new(output.clone(), false, utxo::UtxoSource::Mempool);
                let account_utxo_id = AccountOutPointId::new(self.get_account_id(), outpoint);
                db_tx.set_utxo(&account_utxo_id, utxo)?;
            }
        }
        Ok(())
    }

    /// Remove transaction outputs from the UTXO set of the account
    fn remove_from_utxos<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        wallet_tx: &WalletTx,
    ) -> WalletResult<()> {
        let tx = wallet_tx.tx();
        for (i, _) in tx.outputs().iter().enumerate() {
            let outpoint = OutPoint::new(tx.get_id().into(), i as u32);
            db_tx.del_utxo(&AccountOutPointId::new(self.get_account_id(), outpoint))?;
        }
        Ok(())
    }

    #[allow(dead_code)] // TODO remove
    fn is_available_for_spending(&self, _txo: &TxOutput) -> bool {
        // TODO implement
        true
    }

    fn get_tx_output_destination(txo: &TxOutput) -> Option<&Destination> {
        match txo {
            TxOutput::Transfer(_, d)
            | TxOutput::LockThenTransfer(_, d, _)
            | TxOutput::DecommissionPool(_, d, _, _) => Some(d),
            TxOutput::Burn(_)
            | TxOutput::CreateStakePool(_)
            | TxOutput::ProduceBlockFromStake(_, _) => None,
        }
    }

    /// Return true if this transaction output is can be spent by this account or if it is being
    /// watched.
    fn is_mine_or_watched(&self, txo: &TxOutput) -> bool {
        // TODO: Should we also report `AnyoneCanSpend` as own?
        Self::get_tx_output_destination(txo).map_or(false, |d| match d {
            Destination::Address(pkh) => self.key_chain.is_public_key_hash_mine(pkh),
            Destination::PublicKey(pk) => self.key_chain.is_public_key_mine(pk),
            Destination::AnyoneCanSpend => true,
            Destination::ScriptHash(_) | Destination::ClassicMultisig(_) => false,
        })
    }

    #[allow(dead_code)] // TODO remove
    fn get_last_issued(&self, purpose: KeyPurpose) -> Option<ChildNumber> {
        self.key_chain.get_leaf_key_chain(purpose).last_issued()
    }

    #[allow(dead_code)] // TODO remove
    fn get_last_derived_index(&self, purpose: KeyPurpose) -> Option<ChildNumber> {
        self.key_chain.get_leaf_key_chain(purpose).get_last_derived_index()
    }

    pub fn get_balance<B: Backend>(
        &self,
        db_tx: &StoreTxRo<B>,
    ) -> WalletResult<(Amount, BTreeMap<TokenId, Amount>)> {
        let utxos = db_tx.get_utxo_set(&self.get_account_id())?;
        let balances = Self::calculate_output_amounts(utxos.values().map(|utxo| utxo.output()))?;
        Ok(balances)
    }

    pub fn reset_to_height<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        block_height: BlockHeight,
    ) -> WalletResult<()> {
        let revoked_utxos: Vec<AccountOutPointId> = db_tx
            .get_utxo_set(&self.get_account_id())?
            .into_iter()
            .filter_map(|(utxo_id, utxo)| match utxo.source() {
                UtxoSource::Blockchain(utxo_height) if *utxo_height >= block_height => {
                    Some(utxo_id)
                }
                UtxoSource::Mempool | UtxoSource::Blockchain(_) => None,
            })
            .collect();

        for utxo_id in revoked_utxos {
            db_tx.del_utxo(&utxo_id)?;
        }

        Ok(())
    }

    fn scan_genesis_block<B: Backend>(&mut self, db_tx: &mut StoreTxRw<B>) -> WalletResult<()> {
        let chain_config = Arc::clone(&self.chain_config);
        for (output_index, output) in chain_config.genesis_block().utxos().iter().enumerate() {
            let utxo_source = UtxoSource::Blockchain(BlockHeight::zero());
            let outpoint = OutPoint::new(
                OutPointSourceId::BlockReward(self.chain_config.genesis_block_id()),
                output_index as u32,
            );
            self.add_utxo_if_own(db_tx, output, outpoint, utxo_source)?
        }
        Ok(())
    }

    pub fn scan_new_blocks<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        mut block_height: BlockHeight,
        blocks: &[Block],
    ) -> WalletResult<()> {
        for block in blocks {
            let utxo_source = UtxoSource::Blockchain(block_height);
            let block_id = block.header().block_id().into();

            for (output_index, output) in block.block_reward().outputs().iter().enumerate() {
                let outpoint =
                    OutPoint::new(OutPointSourceId::BlockReward(block_id), output_index as u32);
                self.add_utxo_if_own(db_tx, output, outpoint, utxo_source.clone())?
            }

            for signed_tx in block.transactions() {
                let tx_id = signed_tx.transaction().get_id();
                for input in signed_tx.inputs().iter() {
                    self.del_utxo_if_own(db_tx, input.outpoint())?
                }
                for (output_index, output) in signed_tx.outputs().iter().enumerate() {
                    let outpoint =
                        OutPoint::new(OutPointSourceId::Transaction(tx_id), output_index as u32);
                    self.add_utxo_if_own(db_tx, output, outpoint, utxo_source.clone())?
                }
            }

            block_height = block_height.next_height();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;
