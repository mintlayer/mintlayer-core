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

use common::address::Address;
use crypto::key::extended::ExtendedPublicKey;
use serialization::{Codec, DecodeAll, Encode, EncodeLike};
use storage::schema;
use utxo::Utxo;
use wallet_types::{
    AccountDerivationPathId, AccountId, AccountInfo, AccountKeyPurposeId, AccountOutPointId,
    AccountTxId, KeychainUsageState, RootKeyContent, RootKeyId, WalletTx,
};

use crate::{
    schema::{self as db, Schema},
    WalletStorageRead, WalletStorageWrite,
};

mod well_known {
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
}

/// Read-only chainstate storage transaction
pub struct StoreTxRo<'st, B: storage::Backend>(pub(super) storage::TransactionRo<'st, B, Schema>);

/// Read-write chainstate storage transaction
pub struct StoreTxRw<'st, B: storage::Backend>(pub(super) storage::TransactionRw<'st, B, Schema>);

macro_rules! impl_read_ops {
    ($TxType:ident) => {
        /// Wallet data storage transaction
        impl<'st, B: storage::Backend> WalletStorageRead for $TxType<'st, B> {
            fn get_storage_version(&self) -> crate::Result<u32> {
                self.read_value::<well_known::StoreVersion>().map(|v| v.unwrap_or_default())
            }

            fn get_utxo(&self, outpoint: &AccountOutPointId) -> crate::Result<Option<Utxo>> {
                self.read::<db::DBUtxo, _, _>(outpoint)
            }

            /// Collect and return all utxos from the storage
            fn get_utxo_set(
                &self,
                account_id: &AccountId,
            ) -> crate::Result<BTreeMap<AccountOutPointId, Utxo>> {
                self.0
                    .get::<db::DBUtxo, _>()
                    .prefix_iter_decoded(account_id)
                    .map(Iterator::collect)
            }

            fn get_transaction(&self, id: &AccountTxId) -> crate::Result<Option<WalletTx>> {
                self.read::<db::DBTxs, _, _>(id)
            }

            fn get_account(&self, id: &AccountId) -> crate::Result<Option<AccountInfo>> {
                self.read::<db::DBAccounts, _, _>(id)
            }

            fn get_address(&self, id: &AccountDerivationPathId) -> crate::Result<Option<Address>> {
                self.read::<db::DBAddresses, _, _>(id)
            }

            fn get_addresses(
                &self,
                account_id: &AccountId,
            ) -> crate::Result<BTreeMap<AccountDerivationPathId, Address>> {
                self.0
                    .get::<db::DBAddresses, _>()
                    .prefix_iter_decoded(account_id)
                    .map(Iterator::collect)
            }

            fn get_root_key(&self, id: &RootKeyId) -> crate::Result<Option<RootKeyContent>> {
                self.read::<db::DBPrivateKeys, _, _>(id)
            }

            /// Collect and return all keys from the storage
            fn get_all_root_keys(&self) -> crate::Result<BTreeMap<RootKeyId, RootKeyContent>> {
                self.0
                    .get::<db::DBPrivateKeys, _>()
                    .prefix_iter_decoded(&())
                    .map(Iterator::collect)
            }

            /// Collect and return all transactions from the storage
            fn get_transactions(
                &self,
                account_id: &AccountId,
            ) -> crate::Result<BTreeMap<AccountTxId, WalletTx>> {
                self.0
                    .get::<db::DBTxs, _>()
                    .prefix_iter_decoded(account_id)
                    .map(Iterator::collect)
            }

            fn get_keychain_usage_state(
                &self,
                id: &AccountKeyPurposeId,
            ) -> crate::Result<Option<KeychainUsageState>> {
                self.read::<db::DBKeychainUsageStates, _, _>(id)
            }

            fn get_keychain_usage_states(
                &self,
                account_id: &AccountId,
            ) -> crate::Result<BTreeMap<AccountKeyPurposeId, KeychainUsageState>> {
                self.0
                    .get::<db::DBKeychainUsageStates, _>()
                    .prefix_iter_decoded(account_id)
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
                self.0
                    .get::<db::DBPubKeys, _>()
                    .prefix_iter_decoded(account_id)
                    .map(Iterator::collect)
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
                let map = self.0.get::<DbMap, I>();
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

impl<'st, B: storage::Backend> WalletStorageWrite for StoreTxRw<'st, B> {
    fn set_storage_version(&mut self, version: u32) -> crate::Result<()> {
        self.write_value::<well_known::StoreVersion>(&version)
    }

    fn set_utxo(&mut self, outpoint: &AccountOutPointId, entry: Utxo) -> crate::Result<()> {
        self.write::<db::DBUtxo, _, _, _>(outpoint, entry)
    }

    fn del_utxo(&mut self, outpoint: &AccountOutPointId) -> crate::Result<()> {
        self.0.get_mut::<db::DBUtxo, _>().del(outpoint).map_err(Into::into)
    }

    fn set_transaction(&mut self, id: &AccountTxId, tx: &WalletTx) -> crate::Result<()> {
        self.write::<db::DBTxs, _, _, _>(id, tx)
    }

    fn del_transaction(&mut self, id: &AccountTxId) -> crate::Result<()> {
        self.0.get_mut::<db::DBTxs, _>().del(id).map_err(Into::into)
    }

    fn set_account(&mut self, id: &AccountId, tx: &AccountInfo) -> crate::Result<()> {
        self.write::<db::DBAccounts, _, _, _>(id, tx)
    }

    fn del_account(&mut self, id: &AccountId) -> crate::Result<()> {
        self.0.get_mut::<db::DBAccounts, _>().del(id).map_err(Into::into)
    }

    fn set_address(
        &mut self,
        id: &AccountDerivationPathId,
        address: &Address,
    ) -> crate::Result<()> {
        self.write::<db::DBAddresses, _, _, _>(id, address)
    }

    fn del_address(&mut self, id: &AccountDerivationPathId) -> crate::Result<()> {
        self.0.get_mut::<db::DBAddresses, _>().del(id).map_err(Into::into)
    }

    fn set_root_key(&mut self, id: &RootKeyId, tx: &RootKeyContent) -> crate::Result<()> {
        self.write::<db::DBPrivateKeys, _, _, _>(id, tx)
    }

    fn del_root_key(&mut self, id: &RootKeyId) -> crate::Result<()> {
        self.0.get_mut::<db::DBPrivateKeys, _>().del(id).map_err(Into::into)
    }

    fn set_keychain_usage_state(
        &mut self,
        id: &AccountKeyPurposeId,
        usage_state: &KeychainUsageState,
    ) -> crate::Result<()> {
        self.write::<db::DBKeychainUsageStates, _, _, _>(id, usage_state)
    }

    fn del_keychain_usage_state(&mut self, id: &AccountKeyPurposeId) -> crate::Result<()> {
        self.0.get_mut::<db::DBKeychainUsageStates, _>().del(id).map_err(Into::into)
    }

    fn set_public_key(
        &mut self,
        id: &AccountDerivationPathId,
        pub_key: &ExtendedPublicKey,
    ) -> crate::Result<()> {
        self.write::<db::DBPubKeys, _, _, _>(id, pub_key)
    }
    fn det_public_key(&mut self, id: &AccountDerivationPathId) -> crate::Result<()> {
        self.0.get_mut::<db::DBPubKeys, _>().del(id).map_err(Into::into)
    }
}

impl<'st, B: storage::Backend> StoreTxRw<'st, B> {
    // Encode a value and write it to the database
    fn write<DbMap, I, K, V>(&mut self, key: K, value: V) -> crate::Result<()>
    where
        DbMap: schema::DbMap,
        Schema: schema::HasDbMap<DbMap, I>,
        K: EncodeLike<<DbMap as schema::DbMap>::Key>,
        V: EncodeLike<<DbMap as schema::DbMap>::Value>,
    {
        self.0.get_mut::<DbMap, I>().put(key, value).map_err(Into::into)
    }

    // Write a value for a well-known entry
    fn write_value<E: well_known::Entry>(&mut self, val: &E::Value) -> crate::Result<()> {
        self.write::<db::DBValue, _, _, _>(E::KEY, val.encode())
    }
}

impl<'st, B: storage::Backend> crate::TransactionRo for StoreTxRo<'st, B> {
    fn close(self) {
        self.0.close()
    }
}

impl<'st, B: storage::Backend> crate::TransactionRw for StoreTxRw<'st, B> {
    fn commit(self) -> crate::Result<()> {
        self.0.commit().map_err(Into::into)
    }

    fn abort(self) {
        self.0.abort()
    }
}

impl<'st, B: storage::Backend> crate::IsTransaction for StoreTxRo<'st, B> {}
impl<'st, B: storage::Backend> crate::IsTransaction for StoreTxRw<'st, B> {}
