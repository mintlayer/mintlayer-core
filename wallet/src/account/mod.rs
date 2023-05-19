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
use crate::send_request::make_address_output;
use crate::{SendRequest, WalletError, WalletResult};
use common::address::Address;
use common::chain::signature::inputsig::standard_signature::StandardInputSignature;
use common::chain::signature::inputsig::InputWitness;
use common::chain::signature::sighash::sighashtype::SigHashType;
use common::chain::signature::TransactionSigError;
use common::chain::tokens::{OutputValue, TokenData, TokenId};
use common::chain::{
    Block, ChainConfig, Destination, OutPoint, OutPointSourceId, SignedTransaction, TxOutput,
};
use common::primitives::{Amount, BlockHeight, Idable};
use crypto::key::extended::ExtendedPrivateKey;
use crypto::key::hdkd::u31::U31;
use std::collections::BTreeMap;
use std::ops::Add;
use std::sync::Arc;
use utxo::{Utxo, UtxoSource};
use wallet_storage::{StoreTxRo, StoreTxRw, WalletStorageRead, WalletStorageWrite};
use wallet_types::{AccountId, AccountOutPointId, KeyPurpose};

pub struct Account {
    chain_config: Arc<ChainConfig>,
    key_chain: AccountKeyChain,
}

impl Account {
    pub fn load_from_database<B: storage::Backend>(
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
    pub fn new<B: storage::Backend>(
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

    pub fn process_send_request<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        mut request: SendRequest,
    ) -> WalletResult<SignedTransaction> {
        if request.utxos().is_empty() {
            let utxos: BTreeMap<OutPoint, Utxo> = db_tx
                .get_utxo_set(&self.get_account_id())?
                .into_iter()
                .map(|(outpoint, utxo)| (outpoint.into_item_id(), utxo))
                .collect();

            // TODO: Call coin selector

            request = request.with_inputs(utxos);
        }

        let (input_coin_amount, input_tokens_amounts) =
            Self::calculate_output_amounts(request.utxos().iter())?;

        let (output_coin_amount, output_tokens_amounts) =
            Self::calculate_output_amounts(request.outputs().iter())?;

        // TODO: Implement tokens sending
        utils::ensure!(
            input_tokens_amounts.is_empty() && output_tokens_amounts.is_empty(),
            WalletError::NotImplemented("Token sending")
        );

        // TODO: Calculate network fee from fee rate and expected transaction size
        let network_fee = Amount::from_atoms(10000);

        let output_with_fee =
            (output_coin_amount + network_fee).ok_or(WalletError::OutputAmountOverflow)?;

        let change_amount = (input_coin_amount - output_with_fee).ok_or(
            WalletError::NotEnoughUtxo(input_coin_amount, output_with_fee),
        )?;
        if change_amount > Amount::ZERO {
            let change_address = self.get_new_address(db_tx, KeyPurpose::Change)?;
            let change_output = make_address_output(change_address, change_amount)?;
            request = request.with_outputs([change_output]);
        }

        // TODO: Randomize inputs and outputs

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
            // TODO: Include DecommissionPool output
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

    // TODO: Use a different type to support partially signed transactions
    fn sign_transaction(&self, req: SendRequest) -> WalletResult<SignedTransaction> {
        let (tx, utxos) = req.into_transaction_and_utxos()?;
        let inputs = tx.inputs();
        let input_utxos = utxos.iter().collect::<Vec<_>>();
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
                    let private_key =
                        self.key_chain.get_private_key_for_destination(destination)?.private_key();

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
    pub fn get_new_address<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        purpose: KeyPurpose,
    ) -> WalletResult<Address> {
        Ok(self.key_chain.issue_address(db_tx, purpose)?)
    }

    fn add_utxo_if_own<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        output: &TxOutput,
        outpoint: OutPoint,
        utxo_source: utxo::UtxoSource,
    ) -> WalletResult<()> {
        if self.is_mine_or_watched(output) {
            let utxo = Utxo::new(output.clone(), utxo_source);
            let account_utxo_id = AccountOutPointId::new(self.get_account_id(), outpoint);
            db_tx.set_utxo(&account_utxo_id, utxo)?;
            self.mark_output_as_used(db_tx, output)?;
        }
        Ok(())
    }

    fn del_utxo_if_own<B: storage::Backend>(
        &self,
        db_tx: &mut StoreTxRw<B>,
        outpoint: &OutPoint,
    ) -> WalletResult<()> {
        let account_utxo_id = AccountOutPointId::new(self.get_account_id(), outpoint.clone());
        // TODO: Mark UTXO as consumed (or leave it as is, but consult the list of known transactions)
        db_tx.del_utxo(&account_utxo_id)?;
        Ok(())
    }

    fn get_tx_output_destination(txo: &TxOutput) -> Option<&Destination> {
        // TODO: Reuse code from TxVerifier
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
        // TODO: Should we really report `AnyoneCanSpend` as own?
        Self::get_tx_output_destination(txo).map_or(false, |d| match d {
            Destination::Address(pkh) => self.key_chain.is_public_key_hash_mine(pkh),
            Destination::PublicKey(pk) => self.key_chain.is_public_key_mine(pk),
            Destination::AnyoneCanSpend => true,
            Destination::ScriptHash(_) | Destination::ClassicMultisig(_) => false,
        })
    }

    fn mark_output_as_used<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        txo: &TxOutput,
    ) -> WalletResult<()> {
        if let Some(d) = Self::get_tx_output_destination(txo) {
            match d {
                Destination::Address(pkh) => {
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

    pub fn get_balance<B: storage::Backend>(
        &self,
        db_tx: &StoreTxRo<B>,
    ) -> WalletResult<(Amount, BTreeMap<TokenId, Amount>)> {
        let utxos = db_tx.get_utxo_set(&self.get_account_id())?;
        let balances = Self::calculate_output_amounts(utxos.values().map(|utxo| utxo.output()))?;
        Ok(balances)
    }

    pub fn reset_to_height<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        common_block_height: BlockHeight,
    ) -> WalletResult<()> {
        let revoked_utxos: Vec<AccountOutPointId> = db_tx
            .get_utxo_set(&self.get_account_id())?
            .into_iter()
            .filter_map(|(utxo_id, utxo)| match utxo.source() {
                UtxoSource::Blockchain(utxo_height) if *utxo_height > common_block_height => {
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

    fn scan_genesis_block<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
    ) -> WalletResult<()> {
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

    pub fn scan_new_blocks<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        common_block_height: BlockHeight,
        blocks: &[Block],
    ) -> WalletResult<()> {
        for (index, block) in blocks.iter().enumerate() {
            let block_height = BlockHeight::new(common_block_height.into_int() + index as u64 + 1);
            let utxo_source = UtxoSource::Blockchain(block_height);
            let block_id = block.get_id();

            for (output_index, output) in block.block_reward().outputs().iter().enumerate() {
                let outpoint = OutPoint::new(
                    OutPointSourceId::BlockReward(block_id.into()),
                    output_index as u32,
                );
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
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;
