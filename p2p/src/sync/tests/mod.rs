// Copyright (c) 2022 RBB S.r.l
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

use libp2p::PeerId;

use chainstate::{make_chainstate, ChainstateConfig, DefaultTransactionVerificationStrategy};

use super::*;
use crate::{
    event::{PeerManagerEvent, SyncControlEvent},
    net::{libp2p::Libp2pService, mock::types::MockPeerId, ConnectivityService},
};

mod block_response;
mod connection;
mod header_response;
mod request_response;

async fn make_sync_manager<T>(
    addr: T::Address,
) -> (
    BlockSyncManager<T>,
    T::ConnectivityHandle,
    mpsc::UnboundedSender<SyncControlEvent<T>>,
    mpsc::UnboundedReceiver<PeerManagerEvent<T>>,
)
where
    T: NetworkingService,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
    T::SyncingPeerRequestId: 'static,
    T::PeerId: 'static,
{
    let (tx_p2p_sync, rx_p2p_sync) = mpsc::unbounded_channel();
    let (tx_pm, rx_pm) = mpsc::unbounded_channel();
    let storage = chainstate_storage::inmemory::Store::new_empty().unwrap();
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let chainstate_config = ChainstateConfig::new();
    let mut man = subsystem::Manager::new("TODO");
    let handle = man.add_subsystem(
        "chainstate",
        make_chainstate(
            chain_config,
            chainstate_config,
            storage,
            DefaultTransactionVerificationStrategy::new(),
            None,
            Default::default(),
        )
        .unwrap(),
    );
    tokio::spawn(async move { man.main().await });

    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(P2pConfig::default());
    let (conn, sync) = T::start(addr, Arc::clone(&chain_config), Arc::clone(&p2p_config))
        .await
        .unwrap();

    (
        BlockSyncManager::<T>::new(chain_config, p2p_config, sync, handle, rx_p2p_sync, tx_pm),
        conn,
        tx_p2p_sync,
        rx_pm,
    )
}

async fn register_peer<T>(mgr: &mut BlockSyncManager<T>, peer_id: T::PeerId)
where
    T: NetworkingService,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let locator = mgr.chainstate_handle.call(|this| this.get_locator()).await.unwrap().unwrap();

    mgr.peers.insert(
        peer_id,
        peer::PeerContext::new_with_locator(peer_id, locator),
    );
}

pub trait MakeTestPeerId {
    type PeerId;

    fn random() -> Self::PeerId;
}

impl MakeTestPeerId for PeerId {
    type PeerId = Self;

    fn random() -> Self::PeerId {
        PeerId::random()
    }
}

impl MakeTestPeerId for MockPeerId {
    type PeerId = Self;

    fn random() -> Self::PeerId {
        MockPeerId::random()
    }
}
