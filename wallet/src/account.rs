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
use crate::{WalletError, WalletResult};
use common::address::Address;
use common::chain::{ChainConfig, Destination, OutPoint, Transaction, TxOutput};
use common::primitives::id::WithId;
use common::primitives::{Id, Idable};
use crypto::key::hdkd::child_number::ChildNumber;
use std::collections::BTreeMap;
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

    /// Return true if this transaction output is can be spent by this account or if it is being
    /// watched.
    #[allow(dead_code)] // TODO remove
    fn is_mine_or_watched(&self, txo: &TxOutput) -> bool {
        let destination = match txo {
            TxOutput::Transfer(_, d) => Some(d),
            TxOutput::LockThenTransfer(_, d, _) => Some(d),
            TxOutput::Burn(_) => None,
            TxOutput::StakePool(_) => None,
            TxOutput::ProduceBlockFromStake(_, _) => None,
            TxOutput::DecommissionPool(_, _, _, _) => None,
        };

        match destination {
            Some(Destination::Address(pkh)) => self.key_chain.is_public_key_hash_mine(pkh),
            Some(Destination::PublicKey(pk)) => self.key_chain.is_public_key_mine(pk),
            _ => false,
        }
    }

    #[allow(dead_code)] // TODO remove
    pub fn get_last_issued(&self, purpose: KeyPurpose) -> Option<ChildNumber> {
        self.key_chain.get_leaf_key_chain(purpose).get_last_issued()
    }

    #[allow(dead_code)] // TODO remove
    pub fn get_last_derived_index(&self, purpose: KeyPurpose) -> Option<ChildNumber> {
        self.key_chain.get_leaf_key_chain(purpose).get_last_derived_index()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_chain::MasterKeyChain;
    use common::address::pubkeyhash::PublicKeyHash;
    use common::chain::config::create_regtest;
    use common::chain::tokens::OutputValue;
    use common::chain::{GenBlock, Transaction};
    use common::primitives::id::WithId;
    use common::primitives::{Amount, Idable, H256};
    use crypto::key::hdkd::child_number::ChildNumber;
    use crypto::key::hdkd::u31::U31;
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
}
