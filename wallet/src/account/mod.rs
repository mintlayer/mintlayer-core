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

mod txo_cache;

use crate::key_chain::{AccountKeyChain, KeyChainError};
use crate::send_request::{make_address_output, make_stake_output};
use crate::{SendRequest, WalletError, WalletResult};
use common::address::Address;
use common::chain::signature::inputsig::standard_signature::StandardInputSignature;
use common::chain::signature::inputsig::InputWitness;
use common::chain::signature::sighash::sighashtype::SigHashType;
use common::chain::signature::TransactionSigError;
use common::chain::tokens::{OutputValue, TokenData, TokenId};
use common::chain::{
    Block, ChainConfig, Destination, OutPoint, SignedTransaction, Transaction, TxInput, TxOutput,
};
use common::primitives::per_thousand::PerThousand;
use common::primitives::{Amount, BlockHeight, Idable};
use consensus::PoSGenerateBlockInputData;
use crypto::key::extended::ExtendedPrivateKey;
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::u31::U31;
use crypto::vrf::{VRFKeyKind, VRFPrivateKey, VRFPublicKey};
use std::collections::BTreeMap;
use std::ops::Add;
use std::sync::Arc;
use wallet_storage::{StoreTxRo, StoreTxRw, WalletStorageRead, WalletStorageWrite};
use wallet_types::account_id::AccountBlockHeight;
use wallet_types::wallet_block::WalletBlock;
use wallet_types::wallet_tx::TxState;
use wallet_types::{AccountId, AccountTxId, KeyPurpose, WalletTx};

use self::txo_cache::TxoCache;

pub struct Account {
    chain_config: Arc<ChainConfig>,
    key_chain: AccountKeyChain,
    txo_cache: TxoCache,
}

#[derive(PartialEq, Eq)]
pub enum UtxoType {
    Transfer,
    LockThenTransfer,
    CreateStakePool,
    Other,
}

pub fn get_utxo_type(output: &TxOutput) -> UtxoType {
    match output {
        TxOutput::Transfer(_, _) => UtxoType::Transfer,
        TxOutput::LockThenTransfer(_, _, _) => UtxoType::LockThenTransfer,
        TxOutput::Burn(_) => UtxoType::Other,
        TxOutput::CreateStakePool(_, _) => UtxoType::CreateStakePool,
        TxOutput::ProduceBlockFromStake(_, _) => UtxoType::Other,
        TxOutput::CreateDelegationId(_, _) => UtxoType::Other,
        TxOutput::DelegateStaking(_, _) => UtxoType::Other,
    }
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

        let blocks = db_tx.get_blocks(&key_chain.get_account_id())?;
        let txs = db_tx.get_transactions(&key_chain.get_account_id())?;
        let txo_cache = TxoCache::new(blocks, txs);

        Ok(Account {
            chain_config,
            key_chain,
            txo_cache,
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

        let txo_cache = TxoCache::empty();

        let mut account = Account {
            chain_config,
            key_chain,
            txo_cache,
        };

        account.scan_genesis(db_tx)?;

        Ok(account)
    }

    pub fn process_send_request<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        mut request: SendRequest,
    ) -> WalletResult<SignedTransaction> {
        if request.utxos().is_empty() {
            let utxos = self
                .get_utxos(UtxoType::Transfer)
                .into_iter()
                .map(|(outpoint, txo)| (outpoint, txo.clone()));

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

    fn get_vrf_key(&self) -> WalletResult<(VRFPrivateKey, VRFPublicKey)> {
        let public_key = self
            .key_chain
            .get_leaf_key_chain(KeyPurpose::ReceiveFunds)
            .get_derived_xpub(ChildNumber::ZERO)
            .ok_or(WalletError::WalletNotInitialized)?;
        let private_key = self
            .key_chain
            .get_private_key_for_destination(&Destination::PublicKey(
                public_key.clone().into_public_key(),
            ))?
            .ok_or(WalletError::KeyChainError(KeyChainError::NoPrivateKeyFound))?
            .private_key();
        let keys =
            VRFPrivateKey::new_from_bytes(private_key.as_bytes(), VRFKeyKind::Schnorrkel).unwrap();
        Ok(keys)
    }

    pub fn create_stake_pool_tx<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        amount: Amount,
    ) -> WalletResult<SignedTransaction> {
        let utxos = self
            .get_utxos(UtxoType::Transfer)
            .into_iter()
            .map(|(outpoint, txo)| (outpoint, txo.clone()))
            .collect::<Vec<(OutPoint, TxOutput)>>();

        let input0 = utxos.get(0).ok_or(WalletError::NoUtxos)?;
        let pool_id = pos_accounting::make_pool_id(&input0.0);

        // TODO: Use other accounts here
        let staker = self.key_chain.issue_key(db_tx, KeyPurpose::ReceiveFunds)?;
        let decommission_key = self.key_chain.issue_key(db_tx, KeyPurpose::ReceiveFunds)?;
        let (_vrf_private_key, vrf_public_key) = self.get_vrf_key()?;

        let stake_output = make_stake_output(
            pool_id,
            amount,
            staker.into_public_key(),
            decommission_key.into_public_key(),
            vrf_public_key,
            PerThousand::new(1000).unwrap(),
            Amount::ZERO,
        )?;

        let request = SendRequest::new().with_inputs(utxos).with_outputs([stake_output]);

        self.process_send_request(db_tx, request)
    }

    pub fn get_pos_gen_block_data<B: storage::Backend>(
        &self,
        _db_tx: &StoreTxRo<B>,
    ) -> WalletResult<PoSGenerateBlockInputData> {
        let utxos = self.get_utxos(UtxoType::CreateStakePool);
        // TODO: Select by pool_id if there are more than one CreateStakePool UTXO
        let (kernel_input_outpoint, kernel_input_utxo) =
            utxos.into_iter().next().ok_or(WalletError::NoUtxos)?;
        let kernel_input: TxInput = kernel_input_outpoint.into();
        let stake_private_key = self
            .key_chain
            .get_private_key_for_destination(
                Self::get_tx_output_destination(kernel_input_utxo).unwrap(),
            )?
            .ok_or(WalletError::KeyChainError(KeyChainError::NoPrivateKeyFound))?
            .private_key();

        let pool_id = match kernel_input_utxo {
            TxOutput::CreateStakePool(pool_id, _) => pool_id,
            TxOutput::ProduceBlockFromStake(_, pool_id) => pool_id,
            TxOutput::Burn(_)
            | TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _) => panic!("Unexpected UTXO"),
        };

        let (vrf_private_key, _vrf_public_key) = self.get_vrf_key()?;

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
                | TxOutput::Burn(v) => v.clone(),
                TxOutput::CreateStakePool(_, stake) => OutputValue::Coin(stake.value()),
                TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _) => {
                    return Err(WalletError::UnsupportedTransactionOutput(Box::new(
                        output.clone(),
                    )))
                }
            };

            match output_value {
                OutputValue::Coin(output_amount) => {
                    coin_amount =
                        coin_amount.add(output_amount).ok_or(WalletError::OutputAmountOverflow)?
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
                    let private_key = self
                        .key_chain
                        .get_private_key_for_destination(destination)?
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
    pub fn get_new_address<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        purpose: KeyPurpose,
    ) -> WalletResult<Address> {
        Ok(self.key_chain.issue_address(db_tx, purpose)?)
    }

    fn get_tx_output_destination(txo: &TxOutput) -> Option<&Destination> {
        // TODO: Reuse code from TxVerifier
        // TODO(PR): Fix CreateStakePool and ProduceBlockFromStake
        match txo {
            TxOutput::Transfer(_, d) | TxOutput::LockThenTransfer(_, d, _) => Some(d),
            TxOutput::CreateStakePool(_, data) => Some(data.staker()),
            TxOutput::Burn(_)
            | TxOutput::ProduceBlockFromStake(_, _)
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

    fn mark_outputs_as_used<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        outputs: &[TxOutput],
    ) -> WalletResult<bool> {
        let mut found = false;
        // Process all outputs (without short-circuiting)
        for output in outputs {
            found |= self.mark_output_as_used(db_tx, output)?;
        }
        Ok(found)
    }

    fn mark_output_as_used<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
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

    pub fn get_balance(&self) -> WalletResult<(Amount, BTreeMap<TokenId, Amount>)> {
        let utxos = self.get_utxos(UtxoType::Transfer);
        let balances = Self::calculate_output_amounts(utxos.into_values())?;
        Ok(balances)
    }

    pub fn get_utxos(&self, utxo_type: UtxoType) -> BTreeMap<OutPoint, &TxOutput> {
        let mut all_outputs = self.txo_cache.utxos();
        all_outputs.retain(|_outpoint, txo| {
            self.is_mine_or_watched(txo) && get_utxo_type(txo) == utxo_type
        });
        all_outputs
    }

    pub fn reset_to_height<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        common_block_height: BlockHeight,
    ) -> WalletResult<()> {
        let revoked_blocks = self
            .txo_cache
            .blocks()
            .iter()
            .filter_map(|(id, block)| {
                if block.height() > common_block_height {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let revoked_txs = self
            .txo_cache
            .txs()
            .iter()
            .filter_map(|(id, tx)| match tx.state() {
                TxState::Confirmed(height) => {
                    if *height > common_block_height {
                        Some(id.clone())
                    } else {
                        None
                    }
                }
            })
            .collect::<Vec<_>>();

        for block_id in revoked_blocks {
            db_tx.del_block(&block_id)?;
            self.txo_cache.remove_block(&block_id);
        }

        for tx_id in revoked_txs {
            db_tx.del_transaction(&tx_id)?;
            self.txo_cache.remove_tx(&tx_id);
        }

        Ok(())
    }

    fn add_block_if_relevant<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        block: WalletBlock,
    ) -> WalletResult<()> {
        let relevant_inputs = block
            .kernel_inputs()
            .iter()
            .any(|input| self.txo_cache.outpoints().contains(input.outpoint()));
        let relevant_outputs = self.mark_outputs_as_used(db_tx, block.reward())?;
        if relevant_inputs || relevant_outputs {
            let block_height = AccountBlockHeight::new(self.get_account_id(), block.height());
            db_tx.set_block(&block_height, &block)?;
            self.txo_cache.add_block(block_height, block);
        }
        Ok(())
    }

    fn add_tx_if_relevant<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        tx: &Transaction,
        state: &TxState,
    ) -> WalletResult<()> {
        let relevant_inputs = tx
            .inputs()
            .iter()
            .any(|input| self.txo_cache.outpoints().contains(input.outpoint()));
        let relevant_output = self.mark_outputs_as_used(db_tx, tx.outputs())?;
        if relevant_inputs || relevant_output {
            let wallet_tx = WalletTx::new(tx.clone().into(), state.clone());
            let tx_id = AccountTxId::new(self.get_account_id(), wallet_tx.tx().get_id());
            db_tx.set_transaction(&tx_id, &wallet_tx)?;
            self.txo_cache.add_tx(tx_id, wallet_tx);
        }
        Ok(())
    }

    fn scan_genesis<B: storage::Backend>(&mut self, db_tx: &mut StoreTxRw<B>) -> WalletResult<()> {
        let chain_config = Arc::clone(&self.chain_config);

        let block = WalletBlock::from_genesis(chain_config.genesis_block());
        self.add_block_if_relevant(db_tx, block)?;

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
            let tx_state = TxState::Confirmed(block_height);

            let wallet_block = WalletBlock::from_block(block, block_height);
            self.add_block_if_relevant(db_tx, wallet_block)?;

            for signed_tx in block.transactions() {
                self.add_tx_if_relevant(db_tx, signed_tx.transaction(), &tx_state)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;
