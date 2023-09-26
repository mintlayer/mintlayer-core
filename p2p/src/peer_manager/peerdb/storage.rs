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

use crate::peer_manager::peerdb_common::{TransactionRo, TransactionRw, Transactional};

pub trait PeerDbStorageRead {
    fn get_version(&self) -> Result<Option<u32>, storage::Error>;

    fn get_known_addresses(&self) -> Result<Vec<String>, storage::Error>;

    fn get_banned_addresses(&self) -> Result<Vec<(String, Time)>, storage::Error>;

    fn get_anchor_addresses(&self) -> Result<Vec<String>, storage::Error>;
}

pub trait PeerDbStorageWrite {
    fn set_version(&mut self, version: u32) -> Result<(), storage::Error>;

    fn add_known_address(&mut self, address: &str) -> Result<(), storage::Error>;

    fn del_known_address(&mut self, address: &str) -> Result<(), storage::Error>;

    fn add_banned_address(&mut self, address: &str, time: Time) -> Result<(), storage::Error>;

    fn del_banned_address(&mut self, address: &str) -> Result<(), storage::Error>;

    fn add_anchor_address(&mut self, address: &str) -> Result<(), storage::Error>;

    fn del_anchor_address(&mut self, address: &str) -> Result<(), storage::Error>;
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
