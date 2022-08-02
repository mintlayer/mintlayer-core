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

use super::*;
use crate::{
    event::{PubSubControlEvent, SwarmEvent, SyncControlEvent},
    net::{libp2p::Libp2pService, types::ConnectivityEvent, ConnectivityService},
};
use chainstate::{make_chainstate, ChainstateConfig};
use libp2p::PeerId;

#[cfg(test)]
mod block_response;
#[cfg(test)]
mod connection;
#[cfg(test)]
mod header_response;
#[cfg(test)]
mod request_response;

async fn make_sync_manager<T>(
    addr: T::Address,
) -> (
    SyncManager<T>,
    T::ConnectivityHandle,
    mpsc::Sender<SyncControlEvent<T>>,
    mpsc::Receiver<PubSubControlEvent>,
    mpsc::Receiver<SwarmEvent<T>>,
)
where
    T: NetworkingService,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingCodecHandle: SyncingCodecService<T>,
{
    let (tx_p2p_sync, rx_p2p_sync) = mpsc::channel(16);
    let (tx_pubsub, rx_pubsub) = mpsc::channel(16);
    let (tx_swarm, rx_swarm) = mpsc::channel(16);
    let storage = chainstate_storage::Store::new_empty().unwrap();
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let chainstate_config = ChainstateConfig::new();
    let mut man = subsystem::Manager::new("TODO");
    let handle = man.add_subsystem(
        "consensus",
        make_chainstate(
            chain_config,
            chainstate_config,
            storage,
            None,
            Default::default(),
        )
        .unwrap(),
    );
    tokio::spawn(async move { man.main().await });

    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (conn, _, sync) = T::start(addr, Arc::clone(&config), Default::default()).await.unwrap();

    (
        SyncManager::<T>::new(
            Arc::clone(&config),
            sync,
            handle,
            rx_p2p_sync,
            tx_swarm,
            tx_pubsub,
        ),
        conn,
        tx_p2p_sync,
        rx_pubsub,
        rx_swarm,
    )
}

async fn get_address<T>(handle: &mut T::ConnectivityHandle) -> T::Address
where
    T: NetworkingService,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    loop {
        if let Some(addr) = handle.local_addr().await.unwrap() {
            return addr;
        }
    }
}

async fn connect_services<T>(conn1: &mut T::ConnectivityHandle, conn2: &mut T::ConnectivityHandle)
where
    T: NetworkingService,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr = get_address::<T>(conn2).await;
    let (_conn1_res, conn2_res) = tokio::join!(conn1.connect(addr), conn2.poll_next());
    let conn2_res: ConnectivityEvent<T> = conn2_res.unwrap();
    let _conn1_id = match conn2_res {
        ConnectivityEvent::InboundAccepted { peer_info, .. } => peer_info.peer_id,
        _ => panic!("invalid event received, expected incoming connection"),
    };
}
