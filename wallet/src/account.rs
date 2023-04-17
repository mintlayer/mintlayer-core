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
use common::chain::{ChainConfig, Destination, OutPoint, Transaction, TxOutput};
use common::primitives::id::WithId;
use common::primitives::{Amount, Id, Idable};
use crypto::key::hdkd::child_number::ChildNumber;
use std::collections::BTreeMap;
use std::ops::Add;
use std::sync::Arc;
use storage::Backend;
use utxo::Utxo;
use wallet_storage::{StoreTxRo, StoreTxRw, WalletStorageRead, WalletStorageWrite};
use wallet_types::{AccountId, AccountOutPointId, AccountTxId, KeyPurpose, TxState, WalletTx};

pub struct Account {
    #[allow(dead_code)] // TODO remove
    chain_config: Arc<ChainConfig>,
    key_chain: AccountKeyChain,
    txs: BTreeMap<Id<Transaction>, WalletTx>,
    utxo: BTreeMap<OutPoint, Utxo>,
}

impl Account {
    pub fn load_from_database<B: Backend>(
        chain_config: Arc<ChainConfig>,
        db_tx: &StoreTxRo<B>,
        id: AccountId,
    ) -> WalletResult<Account> {
        let key_chain = AccountKeyChain::load_from_database(chain_config.clone(), db_tx, &id)?;

        let utxo: BTreeMap<OutPoint, Utxo> = db_tx
            .get_utxo_set(&id)?
            .into_iter()
            .map(|(k, v)| (k.into_item_id(), v))
            .collect();

        let txs: BTreeMap<Id<Transaction>, WalletTx> = db_tx
            .get_transactions(&id)?
            .into_iter()
            .map(|(k, v)| (k.into_item_id(), v))
            .collect();

        Ok(Account {
            chain_config,
            key_chain,
            txs,
            utxo,
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

        Ok(Account {
            chain_config,
            key_chain,
            txs: BTreeMap::new(),
            utxo: BTreeMap::new(),
        })
    }

    pub fn complete_and_add_send_request<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        mut request: SendRequest,
    ) -> WalletResult<WithId<Transaction>> {
        self.complete_send_request(&mut request)?;
        let tx = WithId::new(request.into_transaction());
        self.add_transaction(db_tx, tx.clone(), TxState::InMempool)?;
        Ok(tx)
    }

    fn complete_send_request(&mut self, req: &mut SendRequest) -> WalletResult<()> {
        if req.is_complete() {
            return Err(WalletError::SendRequestComplete);
        }

        // TODO Calculate the amount we need to send
        // TODO call coin selector

        if req.sign_transaction() {
            self.sign_transaction(req)?;
        }

        req.complete();

        Ok(())
    }

    /// Calculate the output amount for coins and tokens
    #[allow(dead_code)] // TODO remove
    fn calculate_output_amounts(
        req: &SendRequest,
    ) -> WalletResult<(Amount, BTreeMap<TokenId, Amount>)> {
        let mut coin_amount = Amount::ZERO;
        let mut tokens_amounts: BTreeMap<TokenId, Amount> = BTreeMap::new();

        // Iterate over all outputs and calculate the coin and tokens amounts
        for output in req.get_transaction().outputs() {
            // Get the supported output value
            let output_value = match output {
                TxOutput::Transfer(v, _)
                | TxOutput::LockThenTransfer(v, _, _)
                | TxOutput::Burn(v) => v,
                _ => {
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
                            let new_amount = match tokens_amounts.get(&token_transfer.token_id) {
                                Some(amount) => amount
                                    .add(token_transfer.amount)
                                    .ok_or(WalletError::OutputAmountOverflow)?,
                                None => token_transfer.amount,
                            };

                            tokens_amounts.insert(token_transfer.token_id, new_amount);
                        }
                        _ => {
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
        let tx = req.get_transaction();
        let inputs = tx.inputs();
        let utxos = req.get_connected_tx_outputs();
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

        let sigs: WalletResult<Vec<StandardInputSignature>> = tx
            .inputs()
            .iter()
            .enumerate()
            .map(|(i, _)| {
                // Get the destination from this utxo. This should not fail as we checked that
                // inputs and utxos have the same length
                let destination = Self::get_tx_output_destination(&utxos[i]).ok_or_else(|| {
                    WalletError::UnsupportedTransactionOutput(Box::new(utxos[i].clone()))
                })?;

                let private_key =
                    self.key_chain.get_private_key_for_destination(destination)?.private_key();

                let sighash_type = sighash_types[i];

                StandardInputSignature::produce_uniparty_signature_for_input(
                    &private_key,
                    sighash_type,
                    destination.clone(),
                    tx,
                    &utxos.iter().collect::<Vec<_>>(),
                    i,
                )
                .map_err(WalletError::TransactionSig)
            })
            .collect();

        let witnesses = sigs?.into_iter().map(InputWitness::Standard).collect();

        req.set_witnesses(witnesses)?;

        Ok(())
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

    /// Add the transaction outputs to the UTXO set of the account
    fn add_to_utxos<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        wallet_tx: &WalletTx,
    ) -> WalletResult<()> {
        // Only Confirmed can be added to the UTXO set
        if match wallet_tx.get_state() {
            TxState::Confirmed(_) => false,
            TxState::InMempool | TxState::Conflicted(_) | TxState::Inactive => true,
        } {
            return Ok(());
        }

        let tx = wallet_tx.get_tx();

        for (i, output) in tx.outputs().iter().enumerate() {
            // Check if this output belongs to this wallet or it is watched
            if self.is_available_for_spending(output) && self.is_mine_or_watched(output) {
                let outpoint = OutPoint::new(tx.get_id().into(), i as u32);
                let utxo = Utxo::new(output.clone(), false, utxo::UtxoSource::Mempool);
                self.utxo.insert(outpoint.clone(), utxo.clone());
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
        let tx = wallet_tx.get_tx();
        for (i, _) in tx.outputs().iter().enumerate() {
            let outpoint = OutPoint::new(tx.get_id().into(), i as u32);
            self.utxo.remove(&outpoint);
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
            TxOutput::Transfer(_, d) | TxOutput::LockThenTransfer(_, d, _) => Some(d),
            _ => None,
        }
    }

    /// Return true if this transaction output is can be spent by this account or if it is being
    /// watched.
    fn is_mine_or_watched(&self, txo: &TxOutput) -> bool {
        // TODO: Should we also report `AnyoneCanSpend` as own?
        match txo {
            TxOutput::Transfer(_, d)
            | TxOutput::LockThenTransfer(_, d, _)
            | TxOutput::DecommissionPool(_, d, _, _) => match d {
                Destination::Address(pkh) => self.key_chain.is_public_key_hash_mine(pkh),
                Destination::PublicKey(pk) => self.key_chain.is_public_key_mine(pk),
                Destination::AnyoneCanSpend
                | Destination::ScriptHash(_)
                | Destination::ClassicMultisig(_) => false,
            },
            TxOutput::Burn(_)
            | TxOutput::CreateStakePool(_)
            | TxOutput::ProduceBlockFromStake(_, _) => false,
        }
    }

    #[allow(dead_code)] // TODO remove
    fn get_last_issued(&self, purpose: KeyPurpose) -> Option<ChildNumber> {
        self.key_chain.get_leaf_key_chain(purpose).get_last_issued()
    }

    #[allow(dead_code)] // TODO remove
    fn get_last_derived_index(&self, purpose: KeyPurpose) -> Option<ChildNumber> {
        self.key_chain.get_leaf_key_chain(purpose).get_last_derived_index()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_chain::MasterKeyChain;
    use common::address::pubkeyhash::PublicKeyHash;
    use common::chain::config::create_regtest;
    use common::chain::signature::verify_signature;
    use common::chain::timelock::OutputTimeLock;
    use common::chain::tokens::OutputValue;
    use common::chain::{GenBlock, Transaction, TxInput};
    use common::primitives::amount::UnsignedIntType;
    use common::primitives::id::WithId;
    use common::primitives::{Amount, Idable, H256};
    use crypto::key::hdkd::child_number::ChildNumber;
    use crypto::key::hdkd::u31::U31;
    use crypto::key::{KeyKind, PrivateKey};
    use crypto::random::{Rng, RngCore};
    use rstest::rstest;
    use std::ops::{Div, Mul, Sub};
    use test_utils::random::{make_seedable_rng, Seed};
    use wallet_storage::{DefaultBackend, Store, TransactionRo, TransactionRw, Transactional};
    use wallet_types::KeyPurpose::{Change, ReceiveFunds};
    use wallet_types::TxState;

    const ZERO_H: ChildNumber = ChildNumber::from_hardened(U31::from_u32_with_msb(0).0);
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn account_transactions() {
        let config = Arc::new(create_regtest());
        let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
        let mut db_tx = db.transaction_rw(None).unwrap();

        let master_key_chain =
            MasterKeyChain::new_from_mnemonic(config.clone(), &mut db_tx, MNEMONIC, None).unwrap();

        let mut key_chain = master_key_chain.create_account_key_chain(&mut db_tx, ZERO_H).unwrap();

        let address1 = key_chain.issue_address(&mut db_tx, ReceiveFunds).unwrap();
        let address2 = key_chain.issue_address(&mut db_tx, ReceiveFunds).unwrap();
        let pk3 = key_chain.issue_key(&mut db_tx, ReceiveFunds).unwrap();
        let pk4 = key_chain.issue_key(&mut db_tx, ReceiveFunds).unwrap();

        let mut account = Account::new(config.clone(), &mut db_tx, key_chain).unwrap();
        db_tx.commit().unwrap();

        let id = account.get_account_id();

        let txo1 = TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1)),
            Destination::Address(PublicKeyHash::try_from(address1.data(&config).unwrap()).unwrap()),
        );
        let txo2 = TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(2)),
            Destination::Address(PublicKeyHash::try_from(address2.data(&config).unwrap()).unwrap()),
        );
        let txo3 = TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(3)),
            Destination::PublicKey(pk3.into_public_key()),
        );
        let txo4 = TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(4)),
            Destination::PublicKey(pk4.into_public_key()),
        );

        let tx1 =
            WithId::new(Transaction::new(1, vec![], vec![txo1, txo2, txo3, txo4], 0).unwrap());
        let tx2 = WithId::new(Transaction::new(2, vec![], vec![], 0).unwrap());
        let tx3 = WithId::new(Transaction::new(3, vec![], vec![], 0).unwrap());
        let tx4 = WithId::new(Transaction::new(4, vec![], vec![], 0).unwrap());

        let block_id: Id<GenBlock> = H256::from_low_u64_le(123).into();

        let mut db_tx = db.transaction_rw(None).unwrap();
        account
            .add_transaction(&mut db_tx, tx1.clone(), TxState::Confirmed(block_id))
            .unwrap();
        account
            .add_transaction(&mut db_tx, tx2.clone(), TxState::Conflicted(block_id))
            .unwrap();
        account.add_transaction(&mut db_tx, tx3.clone(), TxState::InMempool).unwrap();
        account.add_transaction(&mut db_tx, tx4.clone(), TxState::Inactive).unwrap();
        db_tx.commit().unwrap();

        assert_eq!(id, account.get_account_id());
        assert_eq!(4, account.txs.len());
        assert_eq!(&tx1, account.txs.get(&tx1.get_id()).unwrap().get_tx());
        assert_eq!(&tx2, account.txs.get(&tx2.get_id()).unwrap().get_tx());
        assert_eq!(&tx3, account.txs.get(&tx3.get_id()).unwrap().get_tx());
        assert_eq!(&tx4, account.txs.get(&tx4.get_id()).unwrap().get_tx());

        assert_eq!(4, account.utxo.len());

        drop(account);

        let db_tx = db.transaction_ro().unwrap();
        let mut account = Account::load_from_database(config.clone(), &db_tx, id.clone()).unwrap();
        db_tx.close();

        assert_eq!(id, account.get_account_id());
        assert_eq!(4, account.txs.len());
        assert_eq!(&tx1, account.txs.get(&tx1.get_id()).unwrap().get_tx());
        assert_eq!(&tx2, account.txs.get(&tx2.get_id()).unwrap().get_tx());
        assert_eq!(&tx3, account.txs.get(&tx3.get_id()).unwrap().get_tx());
        assert_eq!(&tx4, account.txs.get(&tx4.get_id()).unwrap().get_tx());
        assert_eq!(4, account.utxo.len());

        let mut db_tx = db.transaction_rw(None).unwrap();
        account.delete_transaction(&mut db_tx, tx1.get_id()).unwrap();
        account.delete_transaction(&mut db_tx, tx3.get_id()).unwrap();
        db_tx.commit().unwrap();

        assert_eq!(id, account.get_account_id());
        assert_eq!(2, account.txs.len());
        assert_eq!(&tx2, account.txs.get(&tx2.get_id()).unwrap().get_tx());
        assert_eq!(&tx4, account.txs.get(&tx4.get_id()).unwrap().get_tx());
        assert_eq!(0, account.utxo.len());

        drop(account);

        let db_tx = db.transaction_ro().unwrap();
        let account = Account::load_from_database(config, &db_tx, id.clone()).unwrap();
        db_tx.close();

        assert_eq!(id, account.get_account_id());
        assert_eq!(2, account.txs.len());
        assert_eq!(&tx2, account.txs.get(&tx2.get_id()).unwrap().get_tx());
        assert_eq!(&tx4, account.txs.get(&tx4.get_id()).unwrap().get_tx());
        assert_eq!(0, account.utxo.len());
    }

    #[test]
    fn account_addresses() {
        let config = Arc::new(create_regtest());
        let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
        let mut db_tx = db.transaction_rw(None).unwrap();

        let master_key_chain =
            MasterKeyChain::new_from_mnemonic(config.clone(), &mut db_tx, MNEMONIC, None).unwrap();

        let key_chain = master_key_chain.create_account_key_chain(&mut db_tx, ZERO_H).unwrap();

        let mut account = Account::new(config, &mut db_tx, key_chain).unwrap();
        db_tx.commit().unwrap();

        let test_vec = vec![
            (ReceiveFunds, "rmt14qdg6kvlkpfwcw6zjc3dlxpj0g6ddknf54evpv"),
            (Change, "rmt1867l3cva9qprxny6yanula7k6scuj9xy9rv7m2"),
            (ReceiveFunds, "rmt1vnqqfgfccs2sg7c0feptrw03qm8ejq5vqqvpql"),
        ];

        let mut db_tx = db.transaction_rw(None).unwrap();
        for (purpose, address_str) in test_vec {
            let address = account.get_new_address(&mut db_tx, purpose).unwrap();
            assert_eq!(address.get(), address_str);
        }
    }

    #[test]
    fn account_addresses_lookahead() {
        let config = Arc::new(create_regtest());
        let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
        let mut db_tx = db.transaction_rw(None).unwrap();

        let master_key_chain =
            MasterKeyChain::new_from_mnemonic(config.clone(), &mut db_tx, MNEMONIC, None).unwrap();

        let key_chain = master_key_chain.create_account_key_chain(&mut db_tx, ZERO_H).unwrap();
        let mut account = Account::new(config, &mut db_tx, key_chain).unwrap();

        assert_eq!(account.get_last_issued(ReceiveFunds), None);
        let expected_last_derived =
            ChildNumber::from_index_with_hardened_bit(account.key_chain.get_lookahead_size() - 1);
        assert_eq!(
            account.get_last_derived_index(ReceiveFunds),
            Some(expected_last_derived)
        );

        // Issue a new address
        account.key_chain.issue_address(&mut db_tx, ReceiveFunds).unwrap();
        assert_eq!(
            account.get_last_issued(ReceiveFunds),
            Some(ChildNumber::from_index_with_hardened_bit(0))
        );
        assert_eq!(
            account.get_last_derived_index(ReceiveFunds),
            Some(expected_last_derived)
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn sign_transaction(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let config = Arc::new(create_regtest());
        let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
        let mut db_tx = db.transaction_rw(None).unwrap();

        let master_key_chain =
            MasterKeyChain::new_from_mnemonic(config.clone(), &mut db_tx, MNEMONIC, None).unwrap();

        let key_chain = master_key_chain.create_account_key_chain(&mut db_tx, ZERO_H).unwrap();
        let mut account = Account::new(config.clone(), &mut db_tx, key_chain).unwrap();

        let amounts: Vec<Amount> = (0..(2 + rng.next_u32() % 5))
            .map(|_| Amount::from_atoms(rng.next_u32() as UnsignedIntType))
            .collect();

        let total_amount = amounts.iter().fold(Amount::ZERO, |acc, a| acc.add(*a).unwrap());

        let utxos: Vec<TxOutput> = amounts
            .iter()
            .map(|a| {
                let purpose = if rng.gen_bool(0.5) {
                    ReceiveFunds
                } else {
                    Change
                };

                TxOutput::Transfer(
                    OutputValue::Coin(*a),
                    Destination::Address(
                        PublicKeyHash::try_from(
                            &account.get_new_address(&mut db_tx, purpose).unwrap(),
                        )
                        .unwrap(),
                    ),
                )
            })
            .collect();

        let inputs: Vec<TxInput> = utxos
            .iter()
            .map(|_txo| {
                let source_id = if rng.gen_bool(0.5) {
                    Id::<Transaction>::new(H256::random_using(&mut rng)).into()
                } else {
                    Id::<GenBlock>::new(H256::random_using(&mut rng)).into()
                };
                TxInput::new(source_id, rng.next_u32())
            })
            .collect();

        let dest_amount = total_amount.div(10).unwrap().mul(5).unwrap();
        let lock_amount = total_amount.div(10).unwrap().mul(1).unwrap();
        let burn_amount = total_amount.div(10).unwrap().mul(1).unwrap();
        let change_amount = total_amount.div(10).unwrap().mul(2).unwrap();
        let outputs_amounts_sum = [dest_amount, lock_amount, burn_amount, change_amount]
            .iter()
            .fold(Amount::ZERO, |acc, a| acc.add(*a).unwrap());
        let _fee_amount = total_amount.sub(outputs_amounts_sum).unwrap();

        let (_dest_prv, dest_pub) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let outputs = vec![
            TxOutput::Transfer(
                OutputValue::Coin(dest_amount),
                Destination::PublicKey(dest_pub),
            ),
            TxOutput::LockThenTransfer(
                OutputValue::Coin(lock_amount),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForSeconds(rng.next_u64()),
            ),
            TxOutput::Burn(OutputValue::Coin(burn_amount)),
            TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(100)),
                Destination::Address(
                    PublicKeyHash::try_from(&account.get_new_address(&mut db_tx, Change).unwrap())
                        .unwrap(),
                ),
            ),
        ];

        let tx = Transaction::new(0, inputs, outputs, 0).unwrap();

        let mut req = SendRequest::from_transaction(tx);
        req.set_connected_tx_outputs(utxos.clone());

        account.complete_send_request(&mut req).unwrap();

        let sig_tx = req.signed_transaction().unwrap();

        let utxos_ref = utxos.iter().collect::<Vec<_>>();

        for i in 0..sig_tx.inputs().len() {
            let destination = Account::get_tx_output_destination(utxos_ref[i]).unwrap();
            verify_signature(&config, destination, &sig_tx, &utxos_ref, i).unwrap();
        }
    }
}
