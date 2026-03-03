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

use std::time::Duration;

use common::primitives::time::Time;
use p2p::{
    peer_manager::peerdb_common::{StorageVersion, TransactionRo, TransactionRw, Transactional},
    types::{bannable_address::BannableAddress, socket_address::SocketAddress},
};
use serialization::{Decode, Encode};

use crate::{crawler_p2p::crawler::address_data::SoftwareInfo, error::DnsServerError};

use super::{storage_impl::DnsServerStorageImpl, CURRENT_STORAGE_VERSION};

#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub struct AddressInfo {
    /// Peer's software info.
    pub software_info: SoftwareInfo,
    /// Last time we've requested addresses from this peer (as duration since unix epoch).
    pub last_addr_list_request_time: Option<Duration>,
}

pub trait DnsServerStorageRead {
    fn get_version(&self) -> crate::Result<Option<StorageVersion>>;

    fn get_addresses(&self) -> crate::Result<Vec<(SocketAddress, AddressInfo)>>;

    fn get_banned_addresses(&self) -> crate::Result<Vec<(BannableAddress, Time)>>;
}

pub trait DnsServerStorageWrite {
    fn set_version(&mut self, version: StorageVersion) -> crate::Result<()>;

    fn add_address(&mut self, address: &SocketAddress, info: &AddressInfo) -> crate::Result<()>;

    fn del_address(&mut self, address: &SocketAddress) -> crate::Result<()>;

    fn add_banned_address(&mut self, address: &BannableAddress, time: Time) -> crate::Result<()>;

    fn del_banned_address(&mut self, address: &BannableAddress) -> crate::Result<()>;
}

// Note: here we want to say something like:
//  pub trait DnsServerStorage: for<'t> Transactional<'t> + Send
//      where for<'t> <Self as Transactional<'t>>::TransactionRo: DnsServerStorageRead,
//            for<'t> <Self as Transactional<'t>>::TransactionRw: DnsServerStorageWrite {}
// But currently Rust would require us to duplicate the "where" constrains in all places
// where DnsServerStorage is used, so we use this "Helper" approach instead.
pub trait DnsServerStorage: for<'t> DnsServerStorageHelper<'t> + Send {}

pub trait DnsServerStorageHelper<'t>:
    Transactional<'t, TransactionRo = Self::TxRo, TransactionRw = Self::TxRw>
{
    type TxRo: TransactionRo + DnsServerStorageRead + 't;
    type TxRw: TransactionRw + DnsServerStorageWrite + 't;
}

impl<'t, T> DnsServerStorageHelper<'t> for T
where
    T: Transactional<'t>,
    Self::TransactionRo: DnsServerStorageRead + 't,
    Self::TransactionRw: DnsServerStorageWrite + 't,
{
    type TxRo = Self::TransactionRo;
    type TxRw = Self::TransactionRw;
}

pub fn open_storage<Backend>(backend: Backend) -> crate::Result<DnsServerStorageImpl<Backend>>
where
    Backend: storage::SharedBackend,
{
    let storage = DnsServerStorageImpl::new(backend)?;
    let version = storage.transaction_ro()?.get_version()?;

    match version {
        None | Some(CURRENT_STORAGE_VERSION) => Ok(storage),
        Some(version) => Err(DnsServerError::StorageVersionMismatch {
            expected_version: CURRENT_STORAGE_VERSION,
            actual_version: version,
        }),
    }
}
