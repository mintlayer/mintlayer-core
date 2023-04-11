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

//! # BIP39 key chain
//! The KeyChain struct holds and constantly derives keys for the wallet addresses
//! It uses the following derivation scheme:
//!
//! m/44'/19788'/<account_number>'/<key_purpose>'/<key_index>'
//!
//! Where 44' is the standard BIP44 prefix
//!       19788' or 0x4D4C' (1' for the testnets) is Mintlayer's BIP44 registered coin type
//!       `account_number` is the index of an account,
//!       `key_purpose` is if the generated address is for receiving or change purposes and this
//!                     value is 0 or 1 respectively,
//!       `key_index` starts from 0 and it is incremented for each new address

use crate::key_chain::KeyPurpose::{Change, ReceiveFunds};
use common::address::{Address, AddressError};
use common::chain::config::BIP44_PATH;
use common::chain::ChainConfig;
use crypto::key::extended::{ExtendedKeyKind, ExtendedPrivateKey, ExtendedPublicKey};
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::derivable::{Derivable, DerivationError};
use crypto::key::hdkd::derivation_path::DerivationPath;
use crypto::key::hdkd::u31::U31;
use serialization::{Decode, Encode};
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::sync::Arc;
use storage::Backend;
use wallet_storage::{StoreTxRo, StoreTxRw, WalletStorageRead, WalletStorageWrite};
use wallet_types::account_info::KeychainUsageState;
use wallet_types::{
    AccountAddressId, AccountId, AccountInfo, DeterministicAccountInfo, RootKeyContent, RootKeyId,
};
use zeroize::Zeroize;

/// The number of nodes in a BIP44 path
const BIP44_PATH_LENGTH: usize = 5;
/// The index of key_purpose
const BIP44_KEY_PURPOSE_INDEX: usize = 3;
/// The index of the usable key in the BIP44 hierarchy
const BIP44_KEY_INDEX: usize = 4;
/// Default cryptography type
const DEFAULT_KEY_KIND: ExtendedKeyKind = ExtendedKeyKind::Secp256k1Schnorr;
/// Default size of the number of unused addresses that need to be checked after the
/// last used address.
const LOOKAHEAD_SIZE: u16 = 100;

/// KeyChain errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum KeyChainError {
    #[error("Wallet database error: {0}")]
    DatabaseError(#[from] wallet_storage::Error),
    #[error("Bip39 error: {0}")]
    Bip39(bip39::Error),
    #[error("Key derivation error: {0}")]
    Derivation(#[from] DerivationError),
    #[error("Address error: {0}")]
    Address(#[from] AddressError),
    #[error("Key chain is locked")]
    KeyChainIsLocked,
    #[error("No account found")] // TODO implement display for AccountId
    NoAccountFound(AccountId),
    #[error("Invalid BIP44 derivation path format: {0}")]
    InvalidBip44DerivationPath(DerivationPath),
    #[error("Could not load key chain")]
    CouldNotLoadKeyChain,
    #[error("The provided keys do not belong to the same hierarchy")]
    KeysNotInSameHierarchy,
    #[error("Invalid key purpose index {0}")]
    InvalidKeyPurpose(ChildNumber),
    #[error("Only one root key is supported")]
    OnlyOneRootKeyIsSupported,
    #[error("Cannot issue more keys, lookahead exceeded")]
    LookAheadExceeded,
    #[error("The provided key is not a root in a hierarchy")]
    KeyNotRoot,
}

/// Result type used for the key chain
type KeyChainResult<T> = Result<T, KeyChainError>;

/// The usage purpose of a key i.e. if it is for receiving funds or for change
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
#[allow(clippy::unnecessary_cast)]
pub enum KeyPurpose {
    /// This is for addresses created for receiving funds that are given to the user
    ReceiveFunds = 0,
    /// This is for the internal usage of the wallet when creating change output for a transaction
    Change = 1,
}

impl KeyPurpose {
    const ALL: [KeyPurpose; 2] = [ReceiveFunds, Change];
    /// The index for each purpose
    const DETERMINISTIC_INDEX: [ChildNumber; 2] = [
        ChildNumber::from_normal(U31::from_u32_with_msb(0).0),
        ChildNumber::from_normal(U31::from_u32_with_msb(1).0),
    ];
}

impl TryFrom<ChildNumber> for KeyPurpose {
    type Error = KeyChainError;

    fn try_from(num: ChildNumber) -> Result<Self, Self::Error> {
        match num.get_index() {
            0 => Ok(ReceiveFunds),
            1 => Ok(Change),
            _ => Err(KeyChainError::InvalidKeyPurpose(num)),
        }
    }
}

#[allow(dead_code)] // TODO remove
pub struct MasterKeyChain {
    // pub struct MasterKeyChain<B: Backend> {
    /// The specific chain this KeyChain is based on, this will affect the address format
    chain_config: Arc<ChainConfig>,
    /// The master key of this key chain from where all the keys are derived from
    // TODO implement encryption
    root_key: ExtendedPrivateKey,
}

impl MasterKeyChain {
    #[allow(dead_code)] // TODO remove
    pub fn mnemonic_to_root_key(
        mnemonic_str: &str,
        passphrase: Option<&str>,
    ) -> KeyChainResult<ExtendedPrivateKey> {
        let mut mnemonic = bip39::Mnemonic::parse(mnemonic_str).map_err(KeyChainError::Bip39)?;
        let mut seed = mnemonic.to_seed(passphrase.unwrap_or(""));
        let root_key = ExtendedPrivateKey::new_master(&seed, DEFAULT_KEY_KIND)?;
        mnemonic.zeroize();
        seed.zeroize();
        Ok(root_key)
    }

    #[allow(dead_code)] // TODO remove
    pub fn new_from_mnemonic<B: Backend>(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut StoreTxRw<B>,
        mnemonic_str: &str,
        passphrase: Option<&str>,
    ) -> KeyChainResult<Self> {
        let root_key = Self::mnemonic_to_root_key(mnemonic_str, passphrase)?;
        Self::new_from_root_key(chain_config, db_tx, root_key)
    }

    #[allow(dead_code)] // TODO remove
    pub fn new_from_root_key<B: Backend>(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut StoreTxRw<B>,
        root_key: ExtendedPrivateKey,
    ) -> KeyChainResult<Self> {
        if !root_key.get_derivation_path().is_root() {
            return Err(KeyChainError::KeyNotRoot);
        }

        let key_id = RootKeyId::from(root_key.to_public_key());
        let key_content = RootKeyContent::from(root_key);

        db_tx.set_root_key(&key_id, &key_content)?;

        let root_key = key_content.into_key();

        Ok(MasterKeyChain {
            chain_config,
            root_key,
        })
    }

    /// Load the Master key chain from database and all the account key chains it derives
    #[allow(dead_code)] // TODO remove
    pub fn load_from_database<B: Backend>(
        chain_config: Arc<ChainConfig>,
        db_tx: &StoreTxRo<B>,
    ) -> KeyChainResult<Self> {
        let mut root_keys = db_tx.get_all_root_keys()?;

        // The current format supports a single root key
        if root_keys.len() != 1 {
            return Err(KeyChainError::OnlyOneRootKeyIsSupported);
        }

        let (_, key_content) =
            root_keys.pop_first().expect("Should not fail because it contains 1 key/value");

        let root_key = key_content.into_key();

        Ok(MasterKeyChain {
            chain_config,
            root_key,
        })
    }

    #[allow(dead_code)] // TODO remove
    pub fn create_account_key_chain<B: Backend>(
        &self,
        db_tx: &mut StoreTxRw<B>,
        account_index: ChildNumber,
    ) -> KeyChainResult<AccountKeyChain> {
        AccountKeyChain::new_from_root_key(
            self.chain_config.clone(),
            db_tx,
            &self.root_key,
            account_index,
        )
    }

    #[allow(dead_code)] // TODO remove
    pub fn load_keychain_from_database<B: Backend>(
        &self,
        db_tx: &StoreTxRo<B>,
        id: &AccountId,
    ) -> KeyChainResult<AccountKeyChain> {
        AccountKeyChain::load_from_database(self.chain_config.clone(), db_tx, id)
    }

    #[allow(dead_code)] // TODO remove
    pub fn get_root_key(&self) -> ExtendedPublicKey {
        self.root_key.to_public_key()
    }
}

#[allow(dead_code)] // TODO remove
/// This key chain contains a pool of pre-generated keys and addresses for the usage in a wallet
pub struct AccountKeyChain {
    /// The specific chain this KeyChain is based on, this will affect the address format
    chain_config: Arc<ChainConfig>,

    /// The account key from which all the addresses are derived
    account_pubkey: ExtendedPublicKey,

    /// The master/root key that this account key was derived from
    root_hierarchy_key: Option<ExtendedPublicKey>,

    /// The derived addresses for the receiving funds. Those are derived as needed.
    receiving_addresses: BTreeMap<ChildNumber, Address>,

    /// Key hierarchy used for receiving funds
    receiving_state: KeychainUsageState,

    /// The derived addresses for the change. Those are derived as needed.
    change_addresses: BTreeMap<ChildNumber, Address>,

    /// Key hierarchy used for change
    change_state: KeychainUsageState,

    /// The number of unused addresses that need to be checked after the last used address
    lookahead_size: u16,
}

impl AccountKeyChain {
    fn new_from_root_key<B: Backend>(
        chain_config: Arc<ChainConfig>,
        db_tx: &mut StoreTxRw<B>,
        root_key: &ExtendedPrivateKey,
        index: ChildNumber,
    ) -> KeyChainResult<AccountKeyChain> {
        let account_path = make_account_path(&chain_config, index);

        let account_privkey = root_key.clone().derive_absolute_path(&account_path)?;

        let mut new_account = AccountKeyChain {
            chain_config,
            account_pubkey: account_privkey.to_public_key(),
            root_hierarchy_key: Some(root_key.to_public_key()),
            receiving_addresses: BTreeMap::new(),
            receiving_state: KeychainUsageState::default(),
            change_addresses: BTreeMap::new(),
            change_state: KeychainUsageState::default(),
            lookahead_size: LOOKAHEAD_SIZE,
        };

        Self::persist_account_info(&mut new_account, db_tx)?;

        Ok(new_account)
    }

    /// Load all
    pub fn load_from_database<B: Backend>(
        chain_config: Arc<ChainConfig>,
        db_tx: &StoreTxRo<B>,
        id: &AccountId,
    ) -> KeyChainResult<Self> {
        let account_info =
            db_tx.get_account(id)?.ok_or(KeyChainError::NoAccountFound(id.clone()))?;

        let AccountInfo::Deterministic(account_info) = account_info;

        let (receiving_addresses, change_addresses) = Self::load_addresses(db_tx, id)?;

        Ok(AccountKeyChain {
            chain_config,
            account_pubkey: account_info.get_account_key().clone(),
            root_hierarchy_key: account_info.get_root_hierarchy_key().clone(),
            receiving_addresses,
            receiving_state: account_info.get_receiving_state().clone(),
            change_addresses,
            change_state: account_info.get_change_state().clone(),
            lookahead_size: account_info.get_lookahead_size(),
        })
    }

    fn load_addresses<B: Backend>(
        db_tx: &StoreTxRo<B>,
        id: &AccountId,
    ) -> KeyChainResult<(
        BTreeMap<ChildNumber, Address>,
        BTreeMap<ChildNumber, Address>,
    )> {
        let mut receiving_addresses = BTreeMap::new();
        let mut change_addresses = BTreeMap::new();

        for (address_id, address) in db_tx.get_addresses(id)? {
            // Check that derivation path has the expected number of nodes
            let derivation_path = address_id.into_item_id();
            if derivation_path.len() != BIP44_PATH_LENGTH {
                return Err(KeyChainError::InvalidBip44DerivationPath(derivation_path));
            }
            let path = derivation_path.as_vec();
            let purpose = KeyPurpose::try_from(path[BIP44_KEY_PURPOSE_INDEX])?;
            let old_value = match purpose {
                ReceiveFunds => receiving_addresses.insert(path[BIP44_KEY_INDEX], address),
                Change => change_addresses.insert(path[BIP44_KEY_INDEX], address),
            };
            if old_value.is_some() {
                return Err(KeyChainError::CouldNotLoadKeyChain);
            }
        }
        Ok((receiving_addresses, change_addresses))
    }

    pub fn get_account_id(&self) -> AccountId {
        AccountId::new_from_xpub(&self.account_pubkey)
    }

    pub fn get_account_key(&self) -> ExtendedPublicKey {
        self.account_pubkey.clone()
    }

    /// Issue a new address that hasn't been used before
    pub fn issue_new_address<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        purpose: KeyPurpose,
    ) -> KeyChainResult<Address> {
        let key = self.issue_new_key(db_tx, purpose)?;
        let derivation_path = key.get_derivation_path().clone();

        let address = Address::from_public_key(&self.chain_config, &key.into_public_key())?;
        let id = AccountAddressId::new(self.get_account_id(), derivation_path);
        db_tx.set_address(&id, &address)?;

        Ok(address)
    }

    /// Issue a new derived key that hasn't been used before
    pub fn issue_new_key<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        purpose: KeyPurpose,
    ) -> KeyChainResult<ExtendedPublicKey> {
        let usage_state = self.get_usage_state(purpose);
        let new_issued = {
            match usage_state.get_last_issued() {
                None => ChildNumber::ZERO,
                Some(last_issued) => last_issued.increment()?,
            }
        };

        self.check_issued_lookahead(purpose, new_issued)?;

        // The path of the new key
        let key_path = {
            let mut path = self.account_pubkey.get_derivation_path().clone().into_vec();
            path.push(KeyPurpose::DETERMINISTIC_INDEX[purpose as usize]);
            path.push(new_issued);
            path.try_into()?
        };

        // TODO get key from a precalculated pool
        let new_key = self.account_pubkey.clone().derive_absolute_path(&key_path)?;
        // Update the last issued index
        self.get_usage_state_mut(purpose).set_last_issued(Some(new_issued));
        Self::persist_account_info(self, db_tx)?;

        Ok(new_key)
    }

    fn check_issued_lookahead(
        &self,
        purpose: KeyPurpose,
        new_last_issued: ChildNumber,
    ) -> KeyChainResult<()> {
        let usage_state = self.get_usage_state(purpose);

        let new_issued_index = new_last_issued.get_index();
        let lookahead = self.lookahead_size as u32;

        // Check if the issued addresses are less or equal to lookahead size
        let lookahead_exceeded = match usage_state.get_last_used() {
            None => new_issued_index >= lookahead,
            Some(last_used_index) => new_issued_index > last_used_index.get_index() + lookahead,
        };

        if lookahead_exceeded {
            Err(KeyChainError::LookAheadExceeded)
        } else {
            Ok(())
        }
    }

    /// Get the private key that corresponds to the provided public key
    #[allow(dead_code)] // TODO remove
    pub(crate) fn get_private_key(
        &self,
        parent_key: &ExtendedPrivateKey,
        requested_key: &ExtendedPublicKey,
    ) -> KeyChainResult<ExtendedPrivateKey> {
        let derived_key =
            parent_key.clone().derive_absolute_path(requested_key.get_derivation_path())?;
        if &derived_key.to_public_key() == requested_key {
            Ok(derived_key)
        } else {
            Err(KeyChainError::KeysNotInSameHierarchy)
        }
    }

    fn get_usage_state(&self, purpose: KeyPurpose) -> &KeychainUsageState {
        match purpose {
            ReceiveFunds => &self.receiving_state,
            Change => &self.change_state,
        }
    }

    /// Get the mutable usage state, this is used internally with database persistence done
    /// externally.
    fn get_usage_state_mut(&mut self, purpose: KeyPurpose) -> &mut KeychainUsageState {
        match purpose {
            ReceiveFunds => &mut self.receiving_state,
            Change => &mut self.change_state,
        }
    }

    /// Derive addresses until there are lookahead unused ones
    fn top_up_all(&mut self) -> KeyChainResult<()> {
        for purpose in KeyPurpose::ALL {
            self.top_up(purpose)?
        }
        Ok(())
    }

    /// Derive addresses for the `purpose` key chain
    fn top_up(&mut self, purpose: KeyPurpose) -> KeyChainResult<()> {
        // TODO add db_tx
        let dest = match purpose {
            ReceiveFunds => &mut self.receiving_addresses,
            Change => &mut self.change_addresses,
        };
        println!("TODO topup {dest:?}");
        Ok(())
    }

    pub(crate) fn get_account_info(&self) -> AccountInfo {
        AccountInfo::Deterministic(DeterministicAccountInfo::new(
            self.root_hierarchy_key.clone(),
            self.account_pubkey.clone(),
            self.lookahead_size,
            self.get_usage_state(ReceiveFunds).clone(),
            self.get_usage_state(Change).clone(),
        ))
    }

    pub fn get_lookahead_size(&self) -> u16 {
        self.lookahead_size
    }

    pub fn set_lookahead_size<B: Backend>(
        &mut self,
        db_tx: &mut StoreTxRw<B>,
        lookahead_size: u16,
    ) -> KeyChainResult<()> {
        self.lookahead_size = lookahead_size;
        Self::persist_account_info(self, db_tx)
    }

    fn persist_account_info<B: Backend>(
        account: &mut Self,
        db_tx: &mut StoreTxRw<B>,
    ) -> KeyChainResult<()> {
        db_tx.set_account(&account.get_account_id(), &account.get_account_info())?;
        account.top_up_all()
    }
}

/// Create a deterministic path for an account identified by the `account_index`
fn make_account_path(chain_config: &ChainConfig, account_index: ChildNumber) -> DerivationPath {
    // The path is m/44'/<coin_type>'/<account_index>'
    let path = vec![BIP44_PATH, chain_config.bip44_coin_type(), account_index];
    path.try_into().expect("Path creation should not fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::chain::config::create_unit_test_config;
    use rstest::rstest;
    use std::str::FromStr;
    use test_utils::assert_encoded_eq;
    use wallet_storage::{DefaultBackend, Store, TransactionRw, Transactional};

    const ZERO_H: ChildNumber = ChildNumber::from_hardened(U31::from_u32_with_msb(0).0);
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[rstest]
    #[case(
        KeyPurpose::ReceiveFunds,
        "m/44'/19788'/0'/0/0",
        "8000002c80004d4c800000000000000000000000",
        "b870ce52f8ccb3204e7fcdbb84f122fee29ce3c462750c54d411201baa4cf23c",
        "03bf6f8d52dade77f95e9c6c9488fd8492a99c09ff23095caffb2e6409d1746ade",
        "0ae454a1024d0ddb9e10d23479cf8ef39fb400727fabd17844bd8362b1c70d7d"
    )]
    #[case(
        KeyPurpose::Change,
        "m/44'/19788'/0'/1/0",
        "8000002c80004d4c800000000000000100000000",
        "f2b1cb7118920fe9b3a0470bd67588fb4bdd4af1355ff39171ed41e968a8621b",
        "035df5d551bac1d61a5473615a70eb17b2f4ccbf7e354166639428941e4dbbcd81",
        "8d62d08e7a23e4b510b970ffa84b4a5ed22e6c03faecf32c5dafaf092938516d"
    )]
    #[case(
        KeyPurpose::ReceiveFunds,
        "m/44'/19788'/0'/0/1",
        "8000002c80004d4c800000000000000000000001",
        "f73943cf443cd5cdd6c35e3fc1c8f039dd92c29a3d9fc1f56c5145ad67535fba",
        "030d1d07a8e45110d14f4e2c8623e8db556c11a90c0aac6be9a88f2464e446ee95",
        "7ed12073a4cc61d8a79f3dc0dfc5ca1a23d9ce1fe3c1e92d3b6939cd5848a390"
    )]
    fn key_chain_creation(
        #[case] purpose: KeyPurpose,
        #[case] path_str: &str,
        #[case] path_encoded_str: &str,
        #[case] secret: &str,
        #[case] public: &str,
        #[case] chaincode: &str,
    ) {
        let chain_config = Arc::new(create_unit_test_config());
        let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
        let mut db_tx = db.transaction_rw(None).unwrap();
        let master_key_chain =
            MasterKeyChain::new_from_mnemonic(chain_config, &mut db_tx, MNEMONIC, None).unwrap();

        let mut key_chain = master_key_chain.create_account_key_chain(&mut db_tx, ZERO_H).unwrap();
        db_tx.commit().unwrap();

        let mut db_tx = db.transaction_rw(None).unwrap();
        let path = DerivationPath::from_str(path_str).unwrap();
        // Derive expected key
        let pk = {
            let key_index = path.as_vec().last().unwrap().get_index();
            // Derive previous key if necessary
            if key_index > 0 {
                for _ in 0..key_index {
                    let _ = key_chain.issue_new_key(&mut db_tx, purpose).unwrap();
                }
            }
            key_chain.issue_new_key(&mut db_tx, purpose).unwrap()
        };
        assert_eq!(pk.get_derivation_path().to_string(), path_str.to_string());
        let sk = key_chain.get_private_key(&master_key_chain.root_key, &pk).unwrap();
        let pk2 = ExtendedPublicKey::from_private_key(&sk);
        assert_eq!(pk2.get_derivation_path().to_string(), path_str.to_string());
        assert_eq!(pk, pk2);
        assert_eq!(sk.get_derivation_path(), &path);
        assert_eq!(pk.get_derivation_path(), &path);
        let path_len = path.len();
        assert_encoded_eq(
            &sk,
            format!("00{path_len:02x}{path_encoded_str}{chaincode}{secret}").as_str(),
        );
        assert_encoded_eq(
            &pk,
            format!("00{path_len:02x}{path_encoded_str}{chaincode}{public}").as_str(),
        );
    }

    #[rstest]
    #[case(KeyPurpose::ReceiveFunds)]
    #[case(KeyPurpose::Change)]
    fn key_lookahead(#[case] purpose: KeyPurpose) {
        let chain_config = Arc::new(create_unit_test_config());
        let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
        let mut db_tx = db.transaction_rw(None).unwrap();
        let master_key_chain =
            MasterKeyChain::new_from_mnemonic(chain_config, &mut db_tx, MNEMONIC, None).unwrap();
        let mut key_chain = master_key_chain.create_account_key_chain(&mut db_tx, ZERO_H).unwrap();
        db_tx.commit().unwrap();

        let id = key_chain.get_account_id();

        let mut db_tx = db.transaction_rw(None).unwrap();
        key_chain.set_lookahead_size(&mut db_tx, 5).unwrap();
        assert_eq!(key_chain.get_lookahead_size(), 5);

        // Issue new addresses until the lookahead size is reached
        for _ in 0..5 {
            key_chain.issue_new_address(&mut db_tx, purpose).unwrap();
        }
        assert_eq!(
            key_chain.issue_new_address(&mut db_tx, purpose),
            Err(KeyChainError::LookAheadExceeded)
        );
        db_tx.commit().unwrap();
        drop(key_chain);

        let mut key_chain = master_key_chain
            .load_keychain_from_database(&db.transaction_ro().unwrap(), &id)
            .unwrap();
        assert_eq!(key_chain.get_lookahead_size(), 5);
        assert_eq!(key_chain.get_usage_state(purpose).get_last_used(), None);
        assert_eq!(
            key_chain.get_usage_state(purpose).get_last_issued(),
            Some(ChildNumber::from_normal(U31::from_u32_with_msb(4).0))
        );

        let mut db_tx = db.transaction_rw(None).unwrap();

        // Increase the lookahead size
        key_chain.set_lookahead_size(&mut db_tx, 10).unwrap();

        // Should be able to issue more addresses
        for _ in 0..5 {
            key_chain.issue_new_address(&mut db_tx, purpose).unwrap();
        }
        assert_eq!(
            key_chain.issue_new_address(&mut db_tx, purpose),
            Err(KeyChainError::LookAheadExceeded)
        );

        // TODO mark an address as used and issue more addresses
    }
}
