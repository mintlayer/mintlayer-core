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

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use common::{chain::config, primitives::user_agent::mintlayer_core_user_agent};

use crate::{
    net::{
        default_backend::{
            transport::{MpscChannelTransport, TransportAddress},
            DefaultNetworkingService,
        },
        types::{PeerInfo, Role},
        ConnectivityService, NetworkingService,
    },
    peer_manager::tests::make_peer_manager_custom,
    testing_utils::{
        test_p2p_config, P2pBasicTestTimeGetter, RandomAddressMaker, TestTcpAddressMaker,
        TestTransportChannel, TestTransportMaker,
    },
    types::peer_id::PeerId,
};

async fn test_address_rate_limiter<A, T, B>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
    B: RandomAddressMaker<Address = T::Address>,
{
    let addr = A::make_address();
    let config = Arc::new(config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let time_getter = P2pBasicTestTimeGetter::new();
    let (mut pm, _tx) = make_peer_manager_custom::<T>(
        A::make_transport(),
        addr,
        Arc::clone(&config),
        p2p_config,
        time_getter.get_time_getter(),
    )
    .await;

    let address = B::new();
    let peer_id = PeerId::new();
    let peer_info = PeerInfo {
        peer_id,
        network: *config.magic_bytes(),
        version: *config.version(),
        user_agent: mintlayer_core_user_agent(),
        subscriptions: BTreeSet::new(),
    };
    pm.accept_connection(address, Role::Inbound, peer_info, None);
    assert_eq!(pm.peers.len(), 1);

    let get_new_public_address = || loop {
        let address = B::new().as_peer_address();
        if T::Address::from_peer_address(&address, false).is_some() {
            return address;
        }
    };

    // Check that nodes are allowed to send own address immediately after connecting
    let address = get_new_public_address();
    pm.handle_announce_addr_request(peer_id, address);
    let accepted_count = pm.peerdb.known_addresses().count();
    assert_eq!(accepted_count, 1);

    for _ in 0..120 {
        time_getter.advance_time(Duration::from_secs(1));
        for _ in 0..100 {
            pm.handle_announce_addr_request(peer_id, B::new().as_peer_address());
        }
    }
    let accepted_count = pm.peerdb.known_addresses().count();
    // The average expected count is 13 (1 + 120 * 0.1), but the exact number is not very important
    assert!(
        accepted_count >= 5 && accepted_count <= 20,
        "Unexpected accepted address count: {accepted_count}"
    );
}

// Test only TestTransportChannel because actual networking is not used
#[tokio::test]
async fn test_address_rate_limiter_channels() {
    test_address_rate_limiter::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
        TestTcpAddressMaker,
    >()
    .await;
}
