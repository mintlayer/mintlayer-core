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
    Block, ChainConfig, Destination, OutPoint, OutPointSourceId, SignedTransaction, TxOutput,
};
use common::primitives::{Amount, BlockHeight, Idable};
use crypto::key::extended::ExtendedPrivateKey;
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::u31::U31;
use std::collections::BTreeMap;
use std::ops::Add;
use std::sync::Arc;
use storage::Backend;
use utxo::{Utxo, UtxoSource};
use wallet_storage::{StoreTxRo, StoreTxRw, WalletStorageRead, WalletStorageWrite};
use wallet_types::{AccountId, AccountOutPointId, KeyPurpose};

pub struct Account {
    chain_config: Arc<ChainConfig>,
    key_chain: AccountKeyChain,
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

        Ok(Account {
            chain_config,
            key_chain,
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
            request.fill_inputs(utxos)?;
        }

        let tx = self.complete_send_request(&mut request)?;

        Ok(tx)
    }

    fn complete_send_request(&self, request: &SendRequest) -> WalletResult<SignedTransaction> {
        // TODO: Collect UTXOs
        // TODO: Call coin selector

        let (input_coin_amount, input_tokens_amounts) =
            Self::calculate_output_amounts(request.utxos().iter())?;

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

        let tx = self.sign_transaction(request)?;

        Ok(tx)
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

    fn sign_transaction(&self, req: &SendRequest) -> WalletResult<SignedTransaction> {
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
                let destination = Self::get_tx_output_destination(&utxos[i]).ok_or_else(|| {
                    WalletError::UnsupportedTransactionOutput(Box::new(utxos[i].clone()))
                })?;

                if *destination == Destination::AnyoneCanSpend {
                    Ok(InputWitness::NoSignature(None))
                } else {
                    let private_key =
                        self.key_chain.get_private_key_for_destination(destination)?.private_key();

                    let sighash_type = sighash_types[i];

                    let input_utxos = utxos.iter().collect::<Vec<_>>();

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

        let tx = req.get_signed_transaction(witnesses)?;

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
    pub fn get_new_address<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        purpose: KeyPurpose,
    ) -> WalletResult<Address> {
        Ok(self.key_chain.issue_address(db_tx, purpose)?)
    }

    fn add_utxo_if_own<B: Backend>(
        &self,
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
        &self,
        db_tx: &mut StoreTxRw<B>,
        outpoint: &OutPoint,
    ) -> WalletResult<()> {
        let account_utxo_id = AccountOutPointId::new(self.get_account_id(), outpoint.clone());
        db_tx.del_utxo(&account_utxo_id)?;
        Ok(())
    }

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
