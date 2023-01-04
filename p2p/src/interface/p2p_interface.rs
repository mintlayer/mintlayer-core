// Copyright (c) 2021-2022 RBB S.r.l
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

#[derive(Debug, serde::Serialize)]
pub struct ConnectedPeer {
    pub peer_id: String,
    pub addr: String,
}

#[async_trait::async_trait]
pub trait P2pInterface: Send + Sync {
    async fn connect(&mut self, addr: String) -> crate::Result<()>;

    async fn disconnect(&mut self, peer_id: String) -> crate::Result<()>;

    async fn get_peer_count(&self) -> crate::Result<usize>;

    async fn get_bind_address(&self) -> crate::Result<String>;

    async fn get_connected_peers(&self) -> crate::Result<Vec<ConnectedPeer>>;
}
