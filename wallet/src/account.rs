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

use crate::key_chain::{AccountKeyChain, KeyPurpose};
use crate::{WalletError, WalletResult};
use common::address::Address;
use common::chain::{ChainConfig, OutPoint, Transaction, TxOutput};
use common::primitives::{Id, Idable};
use std::collections::BTreeMap;
use std::sync::Arc;
use storage::Backend;
use utxo::Utxo;
use wallet_storage::{StoreTxRo, StoreTxRw, WalletStorageRead, WalletStorageWrite};
use wallet_types::{AccountId, AccountOutPointId, AccountTxId, TxState, WalletTx};

pub struct Account {
    #[allow(dead_code)] // TODO remove
    chain_config: Arc<ChainConfig>,
    key_chain: AccountKeyChain,
    txs: BTreeMap<Id<Transaction>, WalletTx>,
    utxo: BTreeMap<OutPoint, Utxo>,
}

impl Account {
    pub fn load_from_database<B: storage::Backend>(
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
    pub fn new<B: storage::Backend>(
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
    pub fn get_acount_id(&self) -> AccountId {
        self.key_chain.get_account_id()
    }

    /// Get a new address that hasn't been used before
    pub fn get_new_address<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        purpose: KeyPurpose,
    ) -> WalletResult<Address> {
        Ok(self.key_chain.issue_new_address(db_tx, purpose)?)
    }

    #[allow(dead_code)] // TODO remove
    fn add_transaction<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        tx: Transaction,
        state: TxState,
    ) -> WalletResult<()> {
        let tx_id = tx.get_id();

        if self.txs.contains_key(&tx_id) {
            return Err(WalletError::DuplicateTransaction(tx_id));
        }

        let account_tx_id = AccountTxId::new(self.get_acount_id(), tx_id);
        let wallet_tx = WalletTx::new(tx, state);

        db_tx.set_transaction(&account_tx_id, &wallet_tx)?;

        self.txs.insert(tx_id, wallet_tx);

        // TODO add UTXO?

        Ok(())
    }

    #[allow(dead_code)] // TODO remove
    fn delete_transaction<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        tx_id: Id<Transaction>,
    ) -> WalletResult<()> {
        if !self.txs.contains_key(&tx_id) {
            return Err(WalletError::NoTransactionFound(tx_id));
        }

        let account_tx_id = AccountTxId::new(self.get_acount_id(), tx_id);
        db_tx.del_transaction(&account_tx_id)?;

        self.txs.remove(&tx_id);

        // TODO remove UTXO?

        Ok(())
    }

    // TODO fix incompatibility between borrowing mut self and the database transaction
    #[allow(dead_code)] // TODO remove
    fn add_to_utxos<B: storage::Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        tx: &Transaction,
    ) -> WalletResult<()> {
        for (i, output) in tx.outputs().iter().enumerate() {
            // Check if this output belongs to this wallet or it is watched
            if self.is_available_for_spending(output) && self.is_mine_or_watched(output) {
                let outpoint = OutPoint::new(tx.get_id().into(), i as u32);
                let utxo = Utxo::new(output.clone(), false, utxo::UtxoSource::Mempool);
                self.utxo.insert(outpoint.clone(), utxo.clone());
                let account_utxo_id = AccountOutPointId::new(self.get_acount_id(), outpoint);
                db_tx.set_utxo(&account_utxo_id, utxo)?;
            }
        }
        Ok(())
    }

    #[allow(dead_code)] // TODO remove
    fn is_available_for_spending(&self, _txo: &TxOutput) -> bool {
        // TODO implement
        true
    }

    #[allow(dead_code)] // TODO remove
    fn is_mine_or_watched(&self, _txo: &TxOutput) -> bool {
        // TODO implement
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_chain::MasterKeyChain;
    use common::chain::config::create_regtest;
    use common::chain::{GenBlock, Transaction};
    use common::primitives::{Idable, H256};
    use crypto::key::hdkd::child_number::ChildNumber;
    use crypto::key::hdkd::u31::U31;
    use wallet_storage::{DefaultBackend, Store, TransactionRo, TransactionRw, Transactional};
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

        let key_chain = master_key_chain.create_account_key_chain(&mut db_tx, ZERO_H).unwrap();

        let mut account = Account::new(config.clone(), &mut db_tx, key_chain).unwrap();
        db_tx.commit().unwrap();

        let id = account.get_acount_id();

        let tx1 = Transaction::new(1, vec![], vec![], 0).unwrap();
        let tx2 = Transaction::new(2, vec![], vec![], 0).unwrap();
        let tx3 = Transaction::new(3, vec![], vec![], 0).unwrap();
        let tx4 = Transaction::new(4, vec![], vec![], 0).unwrap();

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

        assert_eq!(id, account.get_acount_id());
        assert_eq!(4, account.txs.len());
        assert_eq!(&tx1, account.txs.get(&tx1.get_id()).unwrap().get_tx());
        assert_eq!(&tx2, account.txs.get(&tx2.get_id()).unwrap().get_tx());
        assert_eq!(&tx3, account.txs.get(&tx3.get_id()).unwrap().get_tx());
        assert_eq!(&tx4, account.txs.get(&tx4.get_id()).unwrap().get_tx());

        drop(account);

        let db_tx = db.transaction_ro().unwrap();
        let mut account = Account::load_from_database(config.clone(), &db_tx, id.clone()).unwrap();
        db_tx.close();

        assert_eq!(id, account.get_acount_id());
        assert_eq!(4, account.txs.len());
        assert_eq!(&tx1, account.txs.get(&tx1.get_id()).unwrap().get_tx());
        assert_eq!(&tx2, account.txs.get(&tx2.get_id()).unwrap().get_tx());
        assert_eq!(&tx3, account.txs.get(&tx3.get_id()).unwrap().get_tx());
        assert_eq!(&tx4, account.txs.get(&tx4.get_id()).unwrap().get_tx());

        let mut db_tx = db.transaction_rw(None).unwrap();
        account.delete_transaction(&mut db_tx, tx1.get_id()).unwrap();
        account.delete_transaction(&mut db_tx, tx3.get_id()).unwrap();
        db_tx.commit().unwrap();

        assert_eq!(id, account.get_acount_id());
        assert_eq!(2, account.txs.len());
        assert_eq!(&tx2, account.txs.get(&tx2.get_id()).unwrap().get_tx());
        assert_eq!(&tx4, account.txs.get(&tx4.get_id()).unwrap().get_tx());

        drop(account);

        let db_tx = db.transaction_ro().unwrap();
        let account = Account::load_from_database(config, &db_tx, id.clone()).unwrap();
        db_tx.close();

        assert_eq!(id, account.get_acount_id());
        assert_eq!(2, account.txs.len());
        assert_eq!(&tx2, account.txs.get(&tx2.get_id()).unwrap().get_tx());
        assert_eq!(&tx4, account.txs.get(&tx4.get_id()).unwrap().get_tx());
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
            (
                KeyPurpose::ReceiveFunds,
                "rmt14qdg6kvlkpfwcw6zjc3dlxpj0g6ddknf54evpv",
            ),
            (
                KeyPurpose::Change,
                "rmt1867l3cva9qprxny6yanula7k6scuj9xy9rv7m2",
            ),
            (
                KeyPurpose::ReceiveFunds,
                "rmt1vnqqfgfccs2sg7c0feptrw03qm8ejq5vqqvpql",
            ),
        ];

        let mut db_tx = db.transaction_rw(None).unwrap();
        for (purpose, address_str) in test_vec {
            let address = account.get_new_address(&mut db_tx, purpose).unwrap();
            assert_eq!(address.get(), address_str);
        }
    }
}
