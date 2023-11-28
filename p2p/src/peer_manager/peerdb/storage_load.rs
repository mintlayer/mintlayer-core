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

use std::collections::{BTreeMap, BTreeSet};

use common::primitives::time::Time;
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress};

use crate::{
    error::P2pError,
    peer_manager::peerdb_common::{TransactionRo, TransactionRw, Transactional},
};

use super::{
    address_tables,
    config::PeerDbConfig,
    storage::{
        KnownAddressState, PeerDbStorage, PeerDbStorageRead, PeerDbStorageWrite, StorageVersion,
    },
    storage_impl::PeerDbStorageImpl,
};

const CURRENT_STORAGE_VERSION: StorageVersion = StorageVersion::new(2);

pub struct LoadedStorage {
    pub known_addresses: BTreeMap<SocketAddress, KnownAddressState>,
    pub banned_addresses: BTreeMap<BannableAddress, Time>,
    pub anchor_addresses: BTreeSet<SocketAddress>,
    pub addr_tables_random_key: address_tables::RandomKey,
}

impl LoadedStorage {
    pub fn load_storage<S: PeerDbStorage>(
        storage: &S,
        peerdb_config: &PeerDbConfig,
    ) -> crate::Result<LoadedStorage> {
        let tx = storage.transaction_ro()?;
        let version = tx.get_version()?;
        tx.close();

        match version {
            None => Self::init_storage(storage, peerdb_config),
            Some(CURRENT_STORAGE_VERSION) => Self::load_storage_v2(storage),
            Some(version) => Err(P2pError::PeerDbStorageVersionMismatch {
                expected_version: CURRENT_STORAGE_VERSION,
                actual_version: version,
            }),
        }
    }

    fn init_storage<S: PeerDbStorage>(
        storage: &S,
        peerdb_config: &PeerDbConfig,
    ) -> crate::Result<LoadedStorage> {
        let addr_tables_random_key = peerdb_config
            .addr_tables_initial_random_key
            .unwrap_or_else(address_tables::RandomKey::new_random);

        let mut tx = storage.transaction_rw()?;
        tx.set_version(CURRENT_STORAGE_VERSION)?;
        tx.set_addr_tables_random_key(addr_tables_random_key)?;
        tx.commit()?;

        Ok(LoadedStorage {
            known_addresses: BTreeMap::new(),
            banned_addresses: BTreeMap::new(),
            anchor_addresses: BTreeSet::new(),
            addr_tables_random_key,
        })
    }

    fn load_storage_v2<S: PeerDbStorage>(storage: &S) -> crate::Result<LoadedStorage> {
        let tx = storage.transaction_ro()?;

        let known_addresses = tx.get_known_addresses()?.iter().copied().collect::<BTreeMap<_, _>>();

        let banned_addresses =
            tx.get_banned_addresses()?.iter().copied().collect::<BTreeMap<_, _>>();

        let anchor_addresses = tx.get_anchor_addresses()?.iter().copied().collect::<BTreeSet<_>>();

        let addr_tables_random_key = tx.get_addr_tables_random_key()?.ok_or_else(|| {
            P2pError::InvalidStorageState("Missing addr tables random key".to_owned())
        })?;

        Ok(LoadedStorage {
            known_addresses,
            banned_addresses,
            anchor_addresses,
            addr_tables_random_key,
        })
    }
}

pub fn open_storage<Backend>(backend: Backend) -> crate::Result<PeerDbStorageImpl<Backend>>
where
    Backend: storage::Backend,
{
    let storage = PeerDbStorageImpl::new(backend)?;
    let version = storage.transaction_ro()?.get_version()?;

    match version {
        None | Some(CURRENT_STORAGE_VERSION) => Ok(storage),
        Some(version) => Err(P2pError::PeerDbStorageVersionMismatch {
            expected_version: CURRENT_STORAGE_VERSION,
            actual_version: version,
        }),
    }
}
