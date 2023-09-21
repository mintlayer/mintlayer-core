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

use crate::decl_storage_trait;

pub trait PeerDbStorageRead {
    fn get_version(&self) -> Result<Option<u32>, storage::Error>;

    fn get_known_addresses(&self) -> Result<Vec<String>, storage::Error>;

    fn get_banned_addresses(&self) -> Result<Vec<(String, Duration)>, storage::Error>;

    fn get_anchor_addresses(&self) -> Result<Vec<String>, storage::Error>;
}

pub trait PeerDbStorageWrite {
    fn set_version(&mut self, version: u32) -> Result<(), storage::Error>;

    fn add_known_address(&mut self, address: &str) -> Result<(), storage::Error>;

    fn del_known_address(&mut self, address: &str) -> Result<(), storage::Error>;

    fn add_banned_address(
        &mut self,
        address: &str,
        duration: Duration,
    ) -> Result<(), storage::Error>;

    fn del_banned_address(&mut self, address: &str) -> Result<(), storage::Error>;

    fn add_anchor_address(&mut self, address: &str) -> Result<(), storage::Error>;

    fn del_anchor_address(&mut self, address: &str) -> Result<(), storage::Error>;
}

decl_storage_trait!(PeerDbStorage, PeerDbStorageRead, PeerDbStorageWrite);
