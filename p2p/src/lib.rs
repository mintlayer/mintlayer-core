// Copyright (c) 2021 RBB S.r.l
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
// Author(s): A. Altonen
use crate::net::NetworkService;

pub mod error;
pub mod net;
pub mod peer;

#[allow(unused)]
struct NetworkManager<NetworkingBackend> {
    network: NetworkingBackend,
}

#[allow(unused)]
impl<NetworkingBackend: NetworkService> NetworkManager<NetworkingBackend> {
    /// Create new NetworkManager
    ///
    /// # Arguments
    /// `addr` - socket address where the local node binds itself to
    pub async fn new(addr: NetworkingBackend::Address) -> error::Result<Self> {
        Ok(Self {
            network: NetworkingBackend::new(addr).await?,
        })
    }
}

#[allow(unused)]
struct P2P<NetworkingBackend> {
    mgr: NetworkManager<NetworkingBackend>,
}

#[allow(unused)]
impl<NetworkingBackend: NetworkService> P2P<NetworkingBackend> {
    /// Create new P2P object
    ///
    /// # Arguments
    /// `addr` - socket address where the local node binds itself to
    pub async fn new(addr: NetworkingBackend::Address) -> error::Result<Self> {
        Ok(Self {
            mgr: NetworkManager::new(addr).await?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net::mock::MockService;

    #[tokio::test]
    async fn test_p2p_new() {
        let addr: <MockService as NetworkService>::Address = "[::1]:8888".parse().unwrap();
        let res = P2P::<MockService>::new(addr).await;
        assert_eq!(res.is_ok(), true);

        // try to create new P2P object to the same address, should fail
        let addr: <MockService as NetworkService>::Address = "[::1]:8888".parse().unwrap();
        let res = P2P::<MockService>::new(addr).await;
        assert_eq!(res.is_err(), true);

        // try to create new P2P object to different address, should succeed
        let addr: <MockService as NetworkService>::Address = "127.0.0.1:8888".parse().unwrap();
        let res = P2P::<MockService>::new(addr).await;
        assert_eq!(res.is_ok(), true);
    }

    #[tokio::test]
    async fn test_network_manager_new() {
        let addr: <MockService as NetworkService>::Address = "[::1]:1111".parse().unwrap();
        let res = NetworkManager::<MockService>::new(addr).await;
        assert_eq!(res.is_ok(), true);

        // try to create new NetworkManager to the same address, should fail
        let addr: <MockService as NetworkService>::Address = "[::1]:1111".parse().unwrap();
        let res = NetworkManager::<MockService>::new(addr).await;
        assert_eq!(res.is_err(), true);

        // try to create new NetworkManager to different address, should succeed
        let addr: <MockService as NetworkService>::Address = "127.0.0.1:1111".parse().unwrap();
        let res = NetworkManager::<MockService>::new(addr).await;
        assert_eq!(res.is_ok(), true);
    }
}
