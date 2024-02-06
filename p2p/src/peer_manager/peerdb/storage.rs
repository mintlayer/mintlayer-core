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

use common::primitives::time::Time;
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress};
use serialization::{Decode, Encode};

use crate::peer_manager::peerdb_common::{
    StorageVersion, TransactionRo, TransactionRw, Transactional,
};

use super::salt::Salt;

#[derive(Debug, Clone, Copy, Encode, Decode, Eq, PartialEq)]
pub enum KnownAddressState {
    #[codec(index = 0)]
    New,
    #[codec(index = 1)]
    Tried,
}

pub trait PeerDbStorageRead {
    fn get_version(&self) -> crate::Result<Option<StorageVersion>>;

    fn get_salt(&self) -> crate::Result<Option<Salt>>;

    fn get_known_addresses(&self) -> crate::Result<Vec<(SocketAddress, KnownAddressState)>>;

    fn get_banned_addresses(&self) -> crate::Result<Vec<(BannableAddress, Time)>>;

    fn get_discouraged_addresses(&self) -> crate::Result<Vec<(BannableAddress, Time)>>;

    fn get_anchor_addresses(&self) -> crate::Result<Vec<SocketAddress>>;
}

pub trait PeerDbStorageWrite {
    fn set_version(&mut self, version: StorageVersion) -> crate::Result<()>;

    fn set_salt(&mut self, salt: Salt) -> crate::Result<()>;

    // Note: the "add" methods below will overwrite the existing value if it's present.

    fn add_known_address(
        &mut self,
        address: &SocketAddress,
        state: KnownAddressState,
    ) -> crate::Result<()>;
    fn del_known_address(&mut self, address: &SocketAddress) -> crate::Result<()>;

    fn add_banned_address(&mut self, address: &BannableAddress, time: Time) -> crate::Result<()>;
    fn del_banned_address(&mut self, address: &BannableAddress) -> crate::Result<()>;

    fn add_discouraged_address(
        &mut self,
        address: &BannableAddress,
        time: Time,
    ) -> crate::Result<()>;
    fn del_discouraged_address(&mut self, address: &BannableAddress) -> crate::Result<()>;

    fn add_anchor_address(&mut self, address: &SocketAddress) -> crate::Result<()>;
    fn del_anchor_address(&mut self, address: &SocketAddress) -> crate::Result<()>;
}

// Note: here we want to say something like:
//  pub trait PeerDbStorage: for<'t> Transactional<'t> + Send
//      where for<'t> <Self as Transactional<'t>>::TransactionRo: PeerDbStorageRead,
//            for<'t> <Self as Transactional<'t>>::TransactionRw: PeerDbStorageWrite {}
// But currently Rust would require us to duplicate the "where" constrains in all places
// where PeerDbStorage is used, so we use this "Helper" approach instead.
pub trait PeerDbStorage: for<'t> PeerDbStorageHelper<'t> + Send {}

pub trait PeerDbStorageHelper<'t>:
    Transactional<'t, TransactionRo = Self::TxRo, TransactionRw = Self::TxRw>
{
    type TxRo: TransactionRo + PeerDbStorageRead + 't;
    type TxRw: TransactionRw + PeerDbStorageWrite + 't;
}

impl<'t, T> PeerDbStorageHelper<'t> for T
where
    T: Transactional<'t>,
    Self::TransactionRo: PeerDbStorageRead + 't,
    Self::TransactionRw: PeerDbStorageWrite + 't,
{
    type TxRo = Self::TransactionRo;
    type TxRw = Self::TransactionRw;
}
