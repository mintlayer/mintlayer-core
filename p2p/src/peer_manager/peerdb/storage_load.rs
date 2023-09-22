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

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress};

use crate::{
    error::P2pError,
    peer_manager::peerdb_common::{TransactionRo, TransactionRw},
};

use super::storage::{PeerDbStorage, PeerDbStorageRead, PeerDbStorageWrite};

const STORAGE_VERSION: u32 = 1;

pub struct LoadedStorage {
    pub known_addresses: BTreeSet<SocketAddress>,
    pub banned_addresses: BTreeMap<BannableAddress, Duration>,
    pub anchor_addresses: BTreeSet<SocketAddress>,
}

impl LoadedStorage {
    pub fn load_storage<S: PeerDbStorage>(storage: &S) -> crate::Result<LoadedStorage> {
        let tx = storage.transaction_ro()?;
        let version = tx.get_version()?;
        tx.close();

        match version {
            None => Self::init_storage(storage),
            Some(STORAGE_VERSION) => Self::load_storage_v1(storage),
            Some(version) => Err(P2pError::InvalidStorageState(format!(
                "Unexpected PeerDb storage version: {version}"
            ))),
        }
    }

    fn init_storage<S: PeerDbStorage>(storage: &S) -> crate::Result<LoadedStorage> {
        let mut tx = storage.transaction_rw()?;
        tx.set_version(STORAGE_VERSION)?;
        tx.commit()?;
        Ok(LoadedStorage {
            known_addresses: BTreeSet::new(),
            banned_addresses: BTreeMap::new(),
            anchor_addresses: BTreeSet::new(),
        })
    }

    fn load_storage_v1<S: PeerDbStorage>(storage: &S) -> crate::Result<LoadedStorage> {
        let tx = storage.transaction_ro()?;

        // TODO: Is there a concern that the number of addresses will be so huge that it'll cause a hiccup?
        let known_addresses = tx
            .get_known_addresses()?
            .iter()
            .map(|addr| {
                addr.parse::<SocketAddress>().map_err(|_err| {
                    P2pError::InvalidStorageState(format!(
                        "Invalid address in PeerDb storage: {addr}"
                    ))
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;

        let banned_addresses = tx
            .get_banned_addresses()?
            .iter()
            .map(|(addr, duration)| {
                addr.parse::<BannableAddress>()
                    .map_err(|_err| {
                        P2pError::InvalidStorageState(format!(
                            "Invalid banned address in PeerDb storage: {addr}"
                        ))
                    })
                    .map(|addr| (addr, *duration))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let anchor_addresses = tx
            .get_anchor_addresses()?
            .iter()
            .map(|addr| {
                addr.parse::<SocketAddress>().map_err(|_err| {
                    P2pError::InvalidStorageState(format!(
                        "Invalid address in PeerDb storage: {addr}"
                    ))
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;

        Ok(LoadedStorage {
            known_addresses,
            banned_addresses,
            anchor_addresses,
        })
    }
}
