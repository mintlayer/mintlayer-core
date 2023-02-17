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

use std::collections::BTreeMap;
use std::path::Path;

use common::chain::{OutPoint, Transaction, TxOutput};
use common::primitives::{Id, Idable};
use utxo::Utxo;
use wallet_storage::{
    DefaultBackend, Store, StoreTxRw, TransactionRw, Transactional, WalletStorageWrite,
};
use wallet_types::{TxState, WalletTx};

/// Wallet errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum WalletError {
    #[error("Wallet database error: {0}")]
    DatabaseError(wallet_storage::Error),
    #[error("Transaction already present: {0}")]
    DuplicateTransaction(Id<Transaction>),
    #[error("No transaction found: {0}")]
    NoTransactionFound(Id<Transaction>),
}
#[allow(dead_code)] // TODO remove
pub struct Wallet<B: storage::Backend> {
    db: Store<B>,
    txs: BTreeMap<Id<Transaction>, WalletTx>,
    utxo: BTreeMap<OutPoint, Utxo>,
}

pub fn open_wallet_file<P: AsRef<Path>>(path: P) -> Result<Wallet<DefaultBackend>, WalletError> {
    let db = Store::new(DefaultBackend::new(path)).map_err(WalletError::DatabaseError)?;

    Wallet::load_wallet(db)
}

pub fn open_wallet_in_memory() -> Result<Wallet<DefaultBackend>, WalletError> {
    let db = Store::new(DefaultBackend::new_in_memory()).map_err(WalletError::DatabaseError)?;

    Wallet::load_wallet(db)
}

impl<B: storage::Backend> Wallet<B> {
    fn load_wallet(db: Store<B>) -> Result<Self, WalletError> {
        let txs = db.read_transactions().map_err(WalletError::DatabaseError)?;
        let utxo = db.read_utxo_set().map_err(WalletError::DatabaseError)?;

        Ok(Wallet { db, txs, utxo })
    }

    pub fn get_database(&self) -> &Store<B> {
        &self.db
    }

    #[allow(dead_code)] // TODO remove
    fn add_transaction(&mut self, tx: Transaction, state: TxState) -> Result<(), WalletError> {
        let tx_id = tx.get_id();

        if self.txs.contains_key(&tx_id) {
            return Err(WalletError::DuplicateTransaction(tx_id));
        }

        let mut db_tx = self.db.transaction_rw(None).map_err(WalletError::DatabaseError)?;

        let mut wallet_tx = WalletTx::new(tx, state);
        wallet_tx.set_order(Some(self.txs.len() as u64));

        db_tx.set_transaction(&tx_id, &wallet_tx).map_err(WalletError::DatabaseError)?;
        db_tx.commit().map_err(WalletError::DatabaseError)?;

        self.txs.insert(tx_id, wallet_tx);

        // TODO add UTXO?

        Ok(())
    }

    #[allow(dead_code)] // TODO remove
    fn delete_transaction(&mut self, tx_id: Id<Transaction>) -> Result<(), WalletError> {
        if !self.txs.contains_key(&tx_id) {
            return Err(WalletError::NoTransactionFound(tx_id));
        }

        let mut db_tx = self.db.transaction_rw(None).map_err(WalletError::DatabaseError)?;
        db_tx.del_transaction(&tx_id).map_err(WalletError::DatabaseError)?;
        db_tx.commit().map_err(WalletError::DatabaseError)?;

        self.txs.remove(&tx_id);

        // TODO remove UTXO?

        Ok(())
    }

    // TODO fix incompatibility between borrowing mut self and the database transaction
    #[allow(dead_code)] // TODO remove
    fn add_to_utxos(
        &mut self,
        tx: &Transaction,
        db_tx: &mut StoreTxRw<B>,
    ) -> Result<(), WalletError> {
        for (i, output) in tx.outputs().iter().enumerate() {
            // Check if this output belongs to this wallet or it is watched
            if self.is_available_for_spending(output) && self.is_mine_or_watched(output) {
                let outpoint = OutPoint::new(tx.get_id().into(), i as u32);
                let utxo = Utxo::new(output.clone(), false, utxo::UtxoSource::Mempool);
                self.utxo.insert(outpoint.clone(), utxo.clone());
                db_tx.set_utxo(&outpoint, utxo).map_err(WalletError::DatabaseError)?;
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
    use common::chain::{GenBlock, Transaction};
    use common::primitives::H256;

    #[test]
    fn in_memory_wallet() {
        let wallet = open_wallet_in_memory();
        assert!(wallet.is_ok())
    }

    #[test]
    fn wallet_transactions() {
        let wallet_path =
            tempfile::TempDir::new().unwrap().path().join("wallet_transactions.sqlite");

        let mut wallet = open_wallet_file(wallet_path.as_path()).expect("the wallet to load");

        let tx1 = Transaction::new(1, vec![], vec![], 0).unwrap();
        let tx2 = Transaction::new(2, vec![], vec![], 0).unwrap();
        let tx3 = Transaction::new(3, vec![], vec![], 0).unwrap();
        let tx4 = Transaction::new(4, vec![], vec![], 0).unwrap();
        let tx5 = Transaction::new(5, vec![], vec![], 0).unwrap();

        let block_id: Id<GenBlock> = H256::from_low_u64_le(123).into();

        wallet.add_transaction(tx1.clone(), TxState::Confirmed(block_id)).unwrap();
        wallet.add_transaction(tx2.clone(), TxState::Conflicted(block_id)).unwrap();
        wallet.add_transaction(tx3.clone(), TxState::InMempool).unwrap();
        wallet.add_transaction(tx4.clone(), TxState::Inactive).unwrap();
        wallet.add_transaction(tx5.clone(), TxState::Unrecognized).unwrap();
        drop(wallet);

        let mut wallet = open_wallet_file(wallet_path.as_path()).expect("the wallet to load");

        assert_eq!(5, wallet.txs.len());
        assert_eq!(&tx1, wallet.txs.get(&tx1.get_id()).unwrap().get_tx());
        assert_eq!(&tx2, wallet.txs.get(&tx2.get_id()).unwrap().get_tx());
        assert_eq!(&tx3, wallet.txs.get(&tx3.get_id()).unwrap().get_tx());
        assert_eq!(&tx4, wallet.txs.get(&tx4.get_id()).unwrap().get_tx());
        assert_eq!(&tx5, wallet.txs.get(&tx5.get_id()).unwrap().get_tx());

        wallet.delete_transaction(tx1.get_id()).unwrap();
        wallet.delete_transaction(tx3.get_id()).unwrap();
        wallet.delete_transaction(tx5.get_id()).unwrap();
        drop(wallet);

        let wallet = open_wallet_file(wallet_path.as_path()).expect("the wallet to load");

        assert_eq!(2, wallet.txs.len());
        assert_eq!(&tx2, wallet.txs.get(&tx2.get_id()).unwrap().get_tx());
        assert_eq!(&tx4, wallet.txs.get(&tx4.get_id()).unwrap().get_tx());
    }
}
