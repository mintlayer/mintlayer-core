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

use crate::{
    schema::{self as db, Schema},
    WalletStorageEncryptionRead, WalletStorageEncryptionWrite, WalletStorageReadLocked,
    WalletStorageReadUnlocked, WalletStorageWriteLocked, WalletStorageWriteUnlocked,
};
use common::{
    address::Address,
    chain::{block::timestamp::BlockTimestamp, Destination, SignedTransaction},
};
use crypto::{
    kdf::KdfChallenge,
    key::{extended::ExtendedPublicKey, PrivateKey},
    symkey::SymmetricKey,
};
use serialization::{Codec, DecodeAll, Encode, EncodeLike};
use storage::{schema, MakeMapRef};
use utils::{
    ensure,
    maybe_encrypted::{MaybeEncrypted, MaybeEncryptedError},
};
use wallet_types::{
    account_id::{AccountAddress, AccountPublicKey},
    account_info::{
        AccountVrfKeys, StandaloneMultisig, StandalonePrivateKey, StandaloneWatchOnlyKey,
    },
    chain_info::ChainInfo,
    keys::{RootKeyConstant, RootKeys},
    seed_phrase::{SeedPhraseConstant, SerializableSeedPhrase},
    wallet_type::WalletType,
    AccountDerivationPathId, AccountId, AccountInfo, AccountKeyPurposeId, AccountWalletCreatedTxId,
    AccountWalletTxId, KeychainUsageState, WalletTx,
};

use wallet_types::hw_data;

mod well_known {
    use common::chain::block::timestamp::BlockTimestamp;
    use crypto::kdf::KdfChallenge;
    use wallet_types::hw_data;
    use wallet_types::{chain_info::ChainInfo, wallet_type};

    use super::Codec;

    /// Pre-defined database keys
    pub trait Entry {
        /// Key for this entry
        const KEY: &'static [u8];
        /// Value type for this entry
        type Value: Codec;
    }

    macro_rules! declare_entry {
        ($name:ident: $type:ty) => {
            pub struct $name;
            impl Entry for $name {
                const KEY: &'static [u8] = stringify!($name).as_bytes();
                type Value = $type;
            }
        };
    }

    declare_entry!(StoreVersion: u32);
    declare_entry!(EncryptionKeyKdfChallenge: KdfChallenge);
    declare_entry!(MedianTime: BlockTimestamp);
    declare_entry!(StoreChainInfo: ChainInfo);
    declare_entry!(LookaheadSize: u32);
    declare_entry!(WalletType: wallet_type::WalletType);
    declare_entry!(HardwareWalletData: hw_data::HardwareWalletData);
}

#[derive(PartialEq, Clone)]
pub enum EncryptionState {
    // The secret parts of the DB (the private keys) are encrypted and we don't have the key to decrypt them
    Locked,
    // If Key is Some then DB is encrypted but we have the key to decrypt it
    // if Key is None then DB is not encrypted
    Unlocked(Option<SymmetricKey>),
}

/// Read-only chainstate storage transaction
pub struct StoreTxRo<'st, B: storage::Backend> {
    storage: storage::TransactionRo<'st, B, Schema>,
}

/// Read-only chainstate storage transaction unlocked
pub struct StoreTxRoUnlocked<'st, B: storage::Backend> {
    storage: storage::TransactionRo<'st, B, Schema>,
    encryption_key: &'st Option<SymmetricKey>,
}

/// Read-write chainstate storage transaction
pub struct StoreTxRw<'st, B: storage::Backend> {
    storage: storage::TransactionRw<'st, B, Schema>,
}

/// Read-write chainstate storage transaction unlocked
pub struct StoreTxRwUnlocked<'st, B: storage::Backend> {
    storage: storage::TransactionRw<'st, B, Schema>,
    encryption_key: &'st Option<SymmetricKey>,
}

impl<'st, B: storage::Backend> StoreTxRo<'st, B> {
    pub fn new(storage: storage::TransactionRo<'st, B, Schema>) -> Self {
        Self { storage }
    }
}

impl<'st, B: storage::Backend> StoreTxRoUnlocked<'st, B> {
    pub fn new(
        storage: storage::TransactionRo<'st, B, Schema>,
        encryption_key: &'st Option<SymmetricKey>,
    ) -> Self {
        Self {
            storage,
            encryption_key,
        }
    }
}

impl<'st, B: storage::Backend> StoreTxRw<'st, B> {
    pub fn new(storage: storage::TransactionRw<'st, B, Schema>) -> Self {
        Self { storage }
    }
}

impl<'st, B: storage::Backend> StoreTxRwUnlocked<'st, B> {
    pub fn new(
        storage: storage::TransactionRw<'st, B, Schema>,
        encryption_key: &'st Option<SymmetricKey>,
    ) -> Self {
        Self {
            storage,
            encryption_key,
        }
    }

    // Delete a value for a well-known entry
    fn delete_value<E: well_known::Entry>(&mut self) -> crate::Result<()> {
        self.storage.get_mut::<db::DBValue, _>().del(E::KEY).map_err(Into::into)
    }
}

macro_rules! impl_read_ops {
    ($TxType:ident) => {
        /// Wallet data storage transaction
        impl<'st, B: storage::Backend> WalletStorageReadLocked for $TxType<'st, B> {
            fn get_storage_version(&self) -> crate::Result<u32> {
                self.read_value::<well_known::StoreVersion>().map(|v| v.unwrap_or_default())
            }

            fn get_wallet_type(&self) -> crate::Result<WalletType> {
                self.read_value::<well_known::WalletType>()
                    .and_then(|v| v.ok_or(crate::Error::WalletDbInconsistentState))
            }

            fn get_chain_info(&self) -> crate::Result<ChainInfo> {
                self.read_value::<well_known::StoreChainInfo>()
                    .and_then(|v| v.ok_or(crate::Error::WalletDbInconsistentState))
            }

            fn get_transaction(&self, id: &AccountWalletTxId) -> crate::Result<Option<WalletTx>> {
                self.read::<db::DBTxs, _, _>(id)
            }

            fn get_accounts_info(&self) -> crate::Result<BTreeMap<AccountId, AccountInfo>> {
                Ok(self.storage.get::<db::DBAccounts, _>().prefix_iter_decoded(&())?.collect())
            }

            fn get_address(&self, id: &AccountDerivationPathId) -> crate::Result<Option<String>> {
                self.read::<db::DBAddresses, _, _>(id)
            }

            fn get_addresses(
                &self,
                account_id: &AccountId,
            ) -> crate::Result<BTreeMap<AccountDerivationPathId, String>> {
                self.storage
                    .get::<db::DBAddresses, _>()
                    .prefix_iter_decoded(account_id)
                    .map_err(crate::Error::from)
                    .map(Iterator::collect)
            }

            fn check_root_keys_sanity(&self) -> crate::Result<()> {
                self.storage
                    .get::<db::DBRootKeys, _>()
                    .prefix_iter_decoded(&())
                    .map_err(crate::Error::from)
                    .map(Iterator::count)
                    .and_then(|count| {
                        ensure!(
                            count == 1,
                            crate::Error::WalletSanityErrorInvalidRootKeyCount(count)
                        );
                        Ok(())
                    })
            }

            /// Collect and return all transactions from the storage
            fn get_transactions(
                &self,
                account_id: &AccountId,
            ) -> crate::Result<Vec<(AccountWalletTxId, WalletTx)>> {
                self.storage
                    .get::<db::DBTxs, _>()
                    .prefix_iter_decoded(account_id)
                    .map_err(crate::Error::from)
                    .map(Iterator::collect)
            }

            /// Collect and return all signed transactions from the storage
            fn get_user_transactions(&self) -> crate::Result<Vec<SignedTransaction>> {
                self.storage
                    .get::<db::DBUserTx, _>()
                    .prefix_iter_decoded(&())
                    .map_err(crate::Error::from)
                    .map(|item| item.map(|item| item.1).collect())
            }

            fn get_account_unconfirmed_tx_counter(
                &self,
                account_id: &AccountId,
            ) -> crate::Result<Option<u64>> {
                self.read::<db::DBUnconfirmedTxCounters, _, _>(account_id)
            }

            fn get_account_vrf_public_keys(
                &self,
                account_id: &AccountId,
            ) -> crate::Result<Option<AccountVrfKeys>> {
                self.read::<db::DBVRFPublicKeys, _, _>(account_id)
            }

            fn get_account_standalone_watch_only_keys(
                &self,
                account_id: &AccountId,
            ) -> crate::Result<BTreeMap<Destination, StandaloneWatchOnlyKey>> {
                self.storage
                    .get::<db::DBStandaloneWatchOnlyKeys, _>()
                    .prefix_iter_decoded(account_id)
                    .map_err(crate::Error::from)
                    .map(|iter| {
                        iter.map(|(key, value): (AccountAddress, StandaloneWatchOnlyKey)| {
                            (key.into_item_id(), value)
                        })
                        .collect()
                    })
            }
            fn get_account_standalone_multisig_keys(
                &self,
                account_id: &AccountId,
            ) -> crate::Result<BTreeMap<Destination, StandaloneMultisig>> {
                self.storage
                    .get::<db::DBStandaloneMultisigKeys, _>()
                    .prefix_iter_decoded(account_id)
                    .map_err(crate::Error::from)
                    .map(|iter| {
                        iter.map(|(key, value): (AccountAddress, StandaloneMultisig)| {
                            (key.into_item_id(), value)
                        })
                        .collect()
                    })
            }

            fn get_account_standalone_private_keys(
                &self,
                account_id: &AccountId,
            ) -> crate::Result<Vec<(AccountPublicKey, Option<String>)>> {
                self.storage
                    .get::<db::DBStandalonePrivateKeys, _>()
                    .prefix_iter_decoded(account_id)
                    .map_err(crate::Error::from)
                    .map(|iter| iter.map(|(key, value)| (key, value.label)).collect())
            }

            fn get_keychain_usage_state(
                &self,
                id: &AccountKeyPurposeId,
            ) -> crate::Result<Option<KeychainUsageState>> {
                self.read::<db::DBKeychainUsageStates, _, _>(id)
            }

            fn get_vrf_keychain_usage_state(
                &self,
                id: &AccountId,
            ) -> crate::Result<Option<KeychainUsageState>> {
                self.read::<db::DBVrfKeychainUsageStates, _, _>(id)
            }

            fn get_keychain_usage_states(
                &self,
                account_id: &AccountId,
            ) -> crate::Result<BTreeMap<AccountKeyPurposeId, KeychainUsageState>> {
                self.storage
                    .get::<db::DBKeychainUsageStates, _>()
                    .prefix_iter_decoded(account_id)
                    .map_err(crate::Error::from)
                    .map(Iterator::collect)
            }

            fn get_public_key(
                &self,
                id: &AccountDerivationPathId,
            ) -> crate::Result<Option<ExtendedPublicKey>> {
                self.read::<db::DBPubKeys, _, _>(id)
            }

            fn get_public_keys(
                &self,
                account_id: &AccountId,
            ) -> crate::Result<BTreeMap<AccountDerivationPathId, ExtendedPublicKey>> {
                self.storage
                    .get::<db::DBPubKeys, _>()
                    .prefix_iter_decoded(account_id)
                    .map_err(crate::Error::from)
                    .map(Iterator::collect)
            }

            fn get_median_time(&self) -> crate::Result<Option<BlockTimestamp>> {
                self.read_value::<well_known::MedianTime>()
            }

            fn get_lookahead_size(&self) -> crate::Result<u32> {
                let lookahead = self.read_value::<well_known::LookaheadSize>()?;
                lookahead.ok_or(crate::Error::WalletDbInconsistentState)
            }

            fn get_hardware_wallet_data(
                &self,
            ) -> crate::Result<Option<hw_data::HardwareWalletData>> {
                self.read_value::<well_known::HardwareWalletData>()
            }
        }

        impl<'st, B: storage::Backend> $TxType<'st, B> {
            // Read a value from the database and decode it
            fn read<DbMap, I, K>(&self, key: K) -> crate::Result<Option<DbMap::Value>>
            where
                DbMap: schema::DbMap,
                Schema: schema::HasDbMap<DbMap, I>,
                K: EncodeLike<DbMap::Key>,
            {
                let map = self.storage.get::<DbMap, I>();
                map.get(key).map_err(crate::Error::from).map(|x| x.map(|x| x.decode()))
            }

            // Read a value for a well-known entry
            fn read_value<E: well_known::Entry>(&self) -> crate::Result<Option<E::Value>> {
                self.read::<db::DBValue, _, _>(E::KEY).map(|x| {
                    x.map(|x| {
                        E::Value::decode_all(&mut x.as_ref())
                            .expect("db values to be encoded correctly")
                    })
                })
            }
        }
    };
}

impl_read_ops!(StoreTxRo);
impl_read_ops!(StoreTxRw);
impl_read_ops!(StoreTxRoUnlocked);
impl_read_ops!(StoreTxRwUnlocked);

impl<T> WalletStorageReadLocked for &mut T
where
    T: WalletStorageReadLocked,
{
    fn get_storage_version(&self) -> crate::Result<u32> {
        (**self).get_storage_version()
    }

    fn get_wallet_type(&self) -> crate::Result<WalletType> {
        (**self).get_wallet_type()
    }

    fn get_chain_info(&self) -> crate::Result<ChainInfo> {
        (**self).get_chain_info()
    }

    fn get_transaction(&self, id: &AccountWalletTxId) -> crate::Result<Option<WalletTx>> {
        (**self).get_transaction(id)
    }

    fn get_accounts_info(&self) -> crate::Result<BTreeMap<AccountId, AccountInfo>> {
        (**self).get_accounts_info()
    }

    fn get_address(&self, id: &AccountDerivationPathId) -> crate::Result<Option<String>> {
        (**self).get_address(id)
    }

    fn get_addresses(
        &self,
        account_id: &AccountId,
    ) -> crate::Result<BTreeMap<AccountDerivationPathId, String>> {
        (**self).get_addresses(account_id)
    }

    fn check_root_keys_sanity(&self) -> crate::Result<()> {
        (**self).check_root_keys_sanity()
    }

    /// Collect and return all transactions from the storage
    fn get_transactions(
        &self,
        account_id: &AccountId,
    ) -> crate::Result<Vec<(AccountWalletTxId, WalletTx)>> {
        (**self).get_transactions(account_id)
    }

    /// Collect and return all signed transactions from the storage
    fn get_user_transactions(&self) -> crate::Result<Vec<SignedTransaction>> {
        (**self).get_user_transactions()
    }

    fn get_account_unconfirmed_tx_counter(
        &self,
        account_id: &AccountId,
    ) -> crate::Result<Option<u64>> {
        (**self).get_account_unconfirmed_tx_counter(account_id)
    }

    fn get_account_vrf_public_keys(
        &self,
        account_id: &AccountId,
    ) -> crate::Result<Option<AccountVrfKeys>> {
        (**self).get_account_vrf_public_keys(account_id)
    }

    fn get_account_standalone_watch_only_keys(
        &self,
        account_id: &AccountId,
    ) -> crate::Result<BTreeMap<Destination, StandaloneWatchOnlyKey>> {
        (**self).get_account_standalone_watch_only_keys(account_id)
    }

    fn get_account_standalone_multisig_keys(
        &self,
        account_id: &AccountId,
    ) -> crate::Result<BTreeMap<Destination, StandaloneMultisig>> {
        (**self).get_account_standalone_multisig_keys(account_id)
    }

    fn get_account_standalone_private_keys(
        &self,
        account_id: &AccountId,
    ) -> crate::Result<Vec<(AccountPublicKey, Option<String>)>> {
        (**self).get_account_standalone_private_keys(account_id)
    }

    fn get_keychain_usage_state(
        &self,
        id: &AccountKeyPurposeId,
    ) -> crate::Result<Option<KeychainUsageState>> {
        (**self).get_keychain_usage_state(id)
    }

    fn get_vrf_keychain_usage_state(
        &self,
        id: &AccountId,
    ) -> crate::Result<Option<KeychainUsageState>> {
        (**self).get_vrf_keychain_usage_state(id)
    }

    fn get_keychain_usage_states(
        &self,
        account_id: &AccountId,
    ) -> crate::Result<BTreeMap<AccountKeyPurposeId, KeychainUsageState>> {
        (**self).get_keychain_usage_states(account_id)
    }

    fn get_public_key(
        &self,
        id: &AccountDerivationPathId,
    ) -> crate::Result<Option<ExtendedPublicKey>> {
        (**self).get_public_key(id)
    }

    fn get_public_keys(
        &self,
        account_id: &AccountId,
    ) -> crate::Result<BTreeMap<AccountDerivationPathId, ExtendedPublicKey>> {
        (**self).get_public_keys(account_id)
    }

    fn get_median_time(&self) -> crate::Result<Option<BlockTimestamp>> {
        (**self).get_median_time()
    }

    fn get_lookahead_size(&self) -> crate::Result<u32> {
        (**self).get_lookahead_size()
    }

    fn get_hardware_wallet_data(&self) -> crate::Result<Option<hw_data::HardwareWalletData>> {
        (**self).get_hardware_wallet_data()
    }
}

impl<B: storage::Backend> WalletStorageEncryptionRead for StoreTxRo<'_, B> {
    fn get_encryption_key_kdf_challenge(&self) -> crate::Result<Option<KdfChallenge>> {
        self.read_value::<well_known::EncryptionKeyKdfChallenge>()
    }

    /// Check if the provided encryption_key can decrypt all of the root keys
    fn check_can_decrypt_all_root_keys(&self, encryption_key: &SymmetricKey) -> crate::Result<()> {
        self.storage
            .get::<db::DBRootKeys, _>()
            .prefix_iter_decoded(&())
            .map_err(crate::Error::from)
            .map(|mut item| {
                item.try_for_each(|(_, v)| {
                    let _decrypted_value =
                        v.try_decrypt_then_take(encryption_key).map_err(|err| match err {
                            MaybeEncryptedError::DecryptionError(_) => {
                                crate::Error::WalletInvalidPassword
                            }
                            MaybeEncryptedError::DecodingError(err) => {
                                panic!("corrupted DB error in decoding of root keys: {}", err)
                            }
                        })?;

                    Ok(())
                })
            })?
    }
}

macro_rules! impl_read_unlocked_ops {
    ($TxType:ident) => {
        /// Wallet data storage transaction
        impl<'st, B: storage::Backend> WalletStorageReadUnlocked for $TxType<'st, B> {
            fn get_root_key(&self) -> crate::Result<Option<RootKeys>> {
                Ok(
                    self.read::<db::DBRootKeys, _, _>(&RootKeyConstant {})?.map(|v| {
                        v.try_take(self.encryption_key).expect("key was checked when unlocked")
                    }),
                )
            }
            fn get_seed_phrase(&self) -> crate::Result<Option<SerializableSeedPhrase>> {
                Ok(
                    self.read::<db::DBSeedPhrase, _, _>(&SeedPhraseConstant {})?.map(|v| {
                        v.try_take(self.encryption_key).expect("key was checked when unlocked")
                    }),
                )
            }

            fn get_account_standalone_private_key(
                &self,
                account_pubkey: &AccountPublicKey,
            ) -> crate::Result<Option<PrivateKey>> {
                Ok(
                    self.read::<db::DBStandalonePrivateKeys, _, _>(account_pubkey)?.map(|v| {
                        v.private_key
                            .try_take(self.encryption_key)
                            .expect("key was checked when unlocked")
                    }),
                )
            }
        }
    };
}

impl_read_unlocked_ops!(StoreTxRoUnlocked);
impl_read_unlocked_ops!(StoreTxRwUnlocked);

impl<T> WalletStorageReadUnlocked for &mut T
where
    T: WalletStorageReadUnlocked,
{
    fn get_root_key(&self) -> crate::Result<Option<RootKeys>> {
        (**self).get_root_key()
    }

    fn get_seed_phrase(&self) -> crate::Result<Option<SerializableSeedPhrase>> {
        (**self).get_seed_phrase()
    }

    fn get_account_standalone_private_key(
        &self,
        account_pubkey: &AccountPublicKey,
    ) -> crate::Result<Option<PrivateKey>> {
        (**self).get_account_standalone_private_key(account_pubkey)
    }
}

macro_rules! impl_write_ops {
    ($TxType:ident) => {
        /// Wallet data storage transaction
        impl<'st, B: storage::Backend> WalletStorageWriteLocked for $TxType<'st, B> {
            fn set_storage_version(&mut self, version: u32) -> crate::Result<()> {
                self.write_value::<well_known::StoreVersion>(&version)
            }

            fn set_wallet_type(&mut self, wallet_type: WalletType) -> crate::Result<()> {
                self.write_value::<well_known::WalletType>(&wallet_type)
            }

            fn set_chain_info(&mut self, chain_info: &ChainInfo) -> crate::Result<()> {
                self.write_value::<well_known::StoreChainInfo>(chain_info)
            }

            fn set_transaction(
                &mut self,
                id: &AccountWalletTxId,
                tx: &WalletTx,
            ) -> crate::Result<()> {
                self.write::<db::DBTxs, _, _, _>(id, tx)
            }

            fn del_transaction(&mut self, id: &AccountWalletTxId) -> crate::Result<()> {
                self.storage.get_mut::<db::DBTxs, _>().del(id).map_err(Into::into)
            }

            fn clear_transactions(&mut self) -> crate::Result<()> {
                let transactions: Vec<_> =
                    self.storage.get::<db::DBTxs, _>().prefix_iter_keys(&())?.collect();

                transactions.into_iter().try_for_each(|id| self.del_transaction(&id))
            }

            fn clear_public_keys(&mut self) -> crate::Result<()> {
                let transactions: Vec<_> =
                    self.storage.get::<db::DBPubKeys, _>().prefix_iter_keys(&())?.collect();

                transactions.into_iter().try_for_each(|id| {
                    self.storage.get_mut::<db::DBPubKeys, _>().del(id).map_err(Into::into)
                })
            }

            fn clear_addresses(&mut self) -> crate::Result<()> {
                let transactions: Vec<_> =
                    self.storage.get::<db::DBAddresses, _>().prefix_iter_keys(&())?.collect();

                transactions.into_iter().try_for_each(|id| {
                    self.storage.get_mut::<db::DBAddresses, _>().del(id).map_err(Into::into)
                })
            }

            fn set_account_unconfirmed_tx_counter(
                &mut self,
                id: &AccountId,
                counter: u64,
            ) -> crate::Result<()> {
                self.write::<db::DBUnconfirmedTxCounters, _, _, _>(id, counter)
            }

            fn set_account_vrf_public_keys(
                &mut self,
                id: &AccountId,
                account_vrf_keys: &AccountVrfKeys,
            ) -> crate::Result<()> {
                self.write::<db::DBVRFPublicKeys, _, _, _>(id, account_vrf_keys)
            }

            fn set_user_transaction(
                &mut self,
                id: &AccountWalletCreatedTxId,
                tx: &SignedTransaction,
            ) -> crate::Result<()> {
                self.write::<db::DBUserTx, _, _, _>(id, tx)
            }

            fn del_user_transaction(&mut self, id: &AccountWalletCreatedTxId) -> crate::Result<()> {
                self.storage.get_mut::<db::DBUserTx, _>().del(id).map_err(Into::into)
            }

            fn set_standalone_watch_only_key(
                &mut self,
                id: &AccountAddress,
                key: &StandaloneWatchOnlyKey,
            ) -> crate::Result<()> {
                self.write::<db::DBStandaloneWatchOnlyKeys, _, _, _>(id, key)
            }
            fn set_standalone_multisig_key(
                &mut self,
                id: &AccountAddress,
                key: &StandaloneMultisig,
            ) -> crate::Result<()> {
                self.write::<db::DBStandaloneMultisigKeys, _, _, _>(id, key)
            }

            fn set_account(&mut self, id: &AccountId, tx: &AccountInfo) -> crate::Result<()> {
                self.write::<db::DBAccounts, _, _, _>(id, tx)
            }

            fn del_account(&mut self, id: &AccountId) -> crate::Result<()> {
                self.storage.get_mut::<db::DBAccounts, _>().del(id).map_err(Into::into)
            }

            fn set_address(
                &mut self,
                id: &AccountDerivationPathId,
                address: &Address<Destination>,
            ) -> crate::Result<()> {
                self.write::<db::DBAddresses, _, _, _>(id, address.to_string())
            }

            fn del_address(&mut self, id: &AccountDerivationPathId) -> crate::Result<()> {
                self.storage.get_mut::<db::DBAddresses, _>().del(id).map_err(Into::into)
            }

            fn set_keychain_usage_state(
                &mut self,
                id: &AccountKeyPurposeId,
                usage_state: &KeychainUsageState,
            ) -> crate::Result<()> {
                self.write::<db::DBKeychainUsageStates, _, _, _>(id, usage_state)
            }

            fn set_vrf_keychain_usage_state(
                &mut self,
                id: &AccountId,
                usage_state: &KeychainUsageState,
            ) -> crate::Result<()> {
                self.write::<db::DBVrfKeychainUsageStates, _, _, _>(id, usage_state)
            }

            fn del_keychain_usage_state(&mut self, id: &AccountKeyPurposeId) -> crate::Result<()> {
                self.storage
                    .get_mut::<db::DBKeychainUsageStates, _>()
                    .del(id)
                    .map_err(Into::into)
            }

            fn del_vrf_keychain_usage_state(&mut self, id: &AccountId) -> crate::Result<()> {
                self.storage
                    .get_mut::<db::DBVrfKeychainUsageStates, _>()
                    .del(id)
                    .map_err(Into::into)
            }

            fn set_public_key(
                &mut self,
                id: &AccountDerivationPathId,
                pub_key: &ExtendedPublicKey,
            ) -> crate::Result<()> {
                self.write::<db::DBPubKeys, _, _, _>(id, pub_key)
            }

            fn del_public_key(&mut self, id: &AccountDerivationPathId) -> crate::Result<()> {
                self.storage.get_mut::<db::DBPubKeys, _>().del(id).map_err(Into::into)
            }

            fn set_median_time(&mut self, median_time: BlockTimestamp) -> crate::Result<()> {
                self.write_value::<well_known::MedianTime>(&median_time)
            }

            fn set_lookahead_size(&mut self, lookahead_size: u32) -> crate::Result<()> {
                self.write_value::<well_known::LookaheadSize>(&lookahead_size)
            }

            fn set_hardware_wallet_data(
                &mut self,
                data: hw_data::HardwareWalletData,
            ) -> crate::Result<()> {
                self.write_value::<well_known::HardwareWalletData>(&data)
            }
        }

        impl<'st, B: storage::Backend> $TxType<'st, B> {
            // Encode a value and write it to the database
            fn write<DbMap, I, K, V>(&mut self, key: K, value: V) -> crate::Result<()>
            where
                DbMap: schema::DbMap,
                Schema: schema::HasDbMap<DbMap, I>,
                K: EncodeLike<<DbMap as schema::DbMap>::Key>,
                V: EncodeLike<<DbMap as schema::DbMap>::Value>,
            {
                self.storage.get_mut::<DbMap, I>().put(key, value).map_err(Into::into)
            }

            // Write a value for a well-known entry
            fn write_value<E: well_known::Entry>(&mut self, val: &E::Value) -> crate::Result<()> {
                self.write::<db::DBValue, _, _, _>(E::KEY, val.encode())
            }
        }
    };
}

impl_write_ops!(StoreTxRw);
impl_write_ops!(StoreTxRwUnlocked);

impl<B: storage::Backend> WalletStorageEncryptionWrite for StoreTxRwUnlocked<'_, B> {
    fn set_encryption_kdf_challenge(&mut self, salt: &KdfChallenge) -> crate::Result<()> {
        self.write_value::<well_known::EncryptionKeyKdfChallenge>(salt)
    }
    fn del_encryption_kdf_challenge(&mut self) -> crate::Result<()> {
        self.delete_value::<well_known::EncryptionKeyKdfChallenge>()
    }

    fn encrypt_root_keys(
        &mut self,
        new_encryption_key: &Option<SymmetricKey>,
    ) -> crate::Result<()> {
        let changed_root_keys: Vec<_> = self
            .storage
            .get::<db::DBRootKeys, _>()
            .prefix_iter_decoded(&())?
            .map(|(k, v)| {
                let decrypted =
                    v.try_take(self.encryption_key).expect("key was checked when unlocked");
                (k, MaybeEncrypted::new(&decrypted, new_encryption_key))
            })
            .collect();

        changed_root_keys
            .into_iter()
            .try_for_each(|(k, v)| self.write::<db::DBRootKeys, _, _, _>(k, v))
    }

    fn encrypt_seed_phrase(
        &mut self,
        new_encryption_key: &Option<SymmetricKey>,
    ) -> crate::Result<()> {
        let encrypted_seed_phrase: Vec<_> = self
            .storage
            .get::<db::DBSeedPhrase, _>()
            .prefix_iter_decoded(&())?
            .map(|(k, v)| {
                let decrypted =
                    v.try_take(self.encryption_key).expect("key was checked when unlocked");
                (k, MaybeEncrypted::new(&decrypted, new_encryption_key))
            })
            .collect();

        encrypted_seed_phrase
            .into_iter()
            .try_for_each(|(k, v)| self.write::<db::DBSeedPhrase, _, _, _>(k, v))
    }

    fn encrypt_standalone_private_keys(
        &mut self,
        new_encryption_key: &Option<SymmetricKey>,
    ) -> crate::Result<()> {
        let encrypted_standalone_private_keys: Vec<_> = self
            .storage
            .get::<db::DBStandalonePrivateKeys, _>()
            .prefix_iter_decoded(&())?
            .map(|(k, v)| {
                let decrypted = v
                    .private_key
                    .try_take(self.encryption_key)
                    .expect("key was checked when unlocked");
                (
                    k,
                    StandalonePrivateKey {
                        label: v.label,
                        private_key: MaybeEncrypted::new(&decrypted, new_encryption_key),
                    },
                )
            })
            .collect();

        encrypted_standalone_private_keys
            .into_iter()
            .try_for_each(|(k, v)| self.write::<db::DBStandalonePrivateKeys, _, _, _>(k, v))
    }
}

/// Wallet data storage transaction
impl<B: storage::Backend> WalletStorageWriteUnlocked for StoreTxRwUnlocked<'_, B> {
    fn set_root_key(&mut self, tx: &RootKeys) -> crate::Result<()> {
        let value = MaybeEncrypted::new(tx, self.encryption_key);
        self.write::<db::DBRootKeys, _, _, _>(RootKeyConstant, value)
    }

    fn del_root_key(&mut self) -> crate::Result<()> {
        self.storage
            .get_mut::<db::DBRootKeys, _>()
            .del(&RootKeyConstant {})
            .map_err(Into::into)
    }

    fn set_standalone_private_key(
        &mut self,
        id: &AccountPublicKey,
        key: &PrivateKey,
        label: Option<String>,
    ) -> crate::Result<()> {
        self.write::<db::DBStandalonePrivateKeys, _, _, _>(
            id,
            StandalonePrivateKey {
                label,
                private_key: MaybeEncrypted::new(key, self.encryption_key),
            },
        )
    }

    fn set_seed_phrase(&mut self, seed_phrase: SerializableSeedPhrase) -> crate::Result<()> {
        let value = MaybeEncrypted::new(&seed_phrase, self.encryption_key);
        self.write::<db::DBSeedPhrase, _, _, _>(SeedPhraseConstant, value)
    }

    fn del_seed_phrase(&mut self) -> crate::Result<Option<SerializableSeedPhrase>> {
        let phrase = self.get_seed_phrase()?;
        // overwrite the old seed phrase
        self.set_seed_phrase(SerializableSeedPhrase::zero_seed_phrase())?;
        self.storage.get_mut::<db::DBSeedPhrase, _>().del(&SeedPhraseConstant {})?;
        // TODO: probably will need to VACUUM the sqlite DB to make sure it is deleted
        Ok(phrase)
    }
}

impl<B: storage::Backend> crate::TransactionRoLocked for StoreTxRo<'_, B> {
    fn close(self) {
        self.storage.close()
    }
}

impl<B: storage::Backend> crate::TransactionRoUnlocked for StoreTxRoUnlocked<'_, B> {
    fn close(self) {
        self.storage.close()
    }
}

impl<B: storage::Backend> crate::TransactionRwLocked for StoreTxRw<'_, B> {
    fn commit(self) -> crate::Result<()> {
        self.storage.commit().map_err(Into::into)
    }

    fn abort(self) {
        self.storage.abort()
    }
}

impl<B: storage::Backend> crate::TransactionRwUnlocked for StoreTxRwUnlocked<'_, B> {
    fn commit(self) -> crate::Result<()> {
        self.storage.commit().map_err(Into::into)
    }

    fn abort(self) {
        self.storage.abort()
    }
}

impl<B: storage::Backend> crate::IsTransaction for StoreTxRo<'_, B> {}
impl<B: storage::Backend> crate::IsTransaction for StoreTxRw<'_, B> {}
impl<B: storage::Backend> crate::IsTransaction for StoreTxRoUnlocked<'_, B> {}
impl<B: storage::Backend> crate::IsTransaction for StoreTxRwUnlocked<'_, B> {}
