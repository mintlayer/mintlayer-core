// Copyright (c) 2022 RBB S.r.l
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
#[cfg(test)]
mod tmp;

use crate::{
    net::{ConnectivityService, NetworkingService},
    swarm::PeerManager,
};
use std::{fmt::Debug, str::FromStr, sync::Arc};

async fn make_peer_manager<T>(
    addr: T::Address,
    config: Arc<common::chain::ChainConfig>,
) -> PeerManager<T>
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    <T as NetworkingService>::Address: FromStr,
    <<T as NetworkingService>::Address as FromStr>::Err: Debug,
{
    let (conn, _, _) = T::start(
        addr,
        &[],
        &[],
        Arc::clone(&config),
        std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();
    let (_, rx) = tokio::sync::mpsc::channel(16);
    let (tx_sync, mut rx_sync) = tokio::sync::mpsc::channel(16);

    tokio::spawn(async move {
        loop {
            let _ = rx_sync.recv().await;
        }
    });

    PeerManager::<T>::new(Arc::clone(&config), conn, rx, tx_sync)
}
