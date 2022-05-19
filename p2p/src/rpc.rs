// Copyright (c) 2021-2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): L. Kuklinek, A. Altonen

use crate::{error::P2pError, net::NetworkingService};
use common::chain::block;
use std::{fmt::Debug, str::FromStr};
use subsystem::subsystem::CallError;

#[rpc::rpc(server, namespace = "p2p")]
trait P2pRpc {
    /// Connect to remote node
    #[method(name = "connect")]
    async fn connect(&self, addr: String) -> rpc::Result<()>;

    /// Get the number of peers
    #[method(name = "get_peer_count")]
    async fn get_peer_count(&self) -> rpc::Result<usize>;
}

#[async_trait::async_trait]
impl<T> P2pRpcServer for super::P2pHandle<T>
where
    T: NetworkingService + 'static,
    <T as NetworkingService>::Address: FromStr,
    <<T as NetworkingService>::Address as FromStr>::Err: Debug + Send,
{
    async fn connect(&self, addr: String) -> rpc::Result<()> {
        let res = self.call_async_mut(|this| Box::pin(this.connect(addr))).await;
        Ok(())
        // handle_error(res)
    }

    async fn get_peer_count(&self) -> rpc::Result<usize> {
        let res = self.call_async(|this| Box::pin(this.get_peer_count())).await;
        Ok(0)
        // handle_error(res)
    }
}

// fn handle_error<T>(e: Result<Result<T, P2pError>, CallError>) -> rpc::Result<T> {
//     e.map_err(rpc::Error::to_call_error)
//         .and_then(|r| r.map_err(rpc::Error::to_call_error))
// }
