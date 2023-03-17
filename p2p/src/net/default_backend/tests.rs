// Copyright (c) 2021-2023 RBB S.r.l
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

use super::{transport::NoiseTcpTransport, *};
use crate::error::DialError;
use crate::testing_utils::{
    test_p2p_config, TestTransportChannel, TestTransportMaker, TestTransportTcp,
};
use crate::{
    net::default_backend::transport::{MpscChannelTransport, TcpTransportSocket},
    testing_utils::TestTransportNoise,
};
use common::primitives::semver::SemVer;
use std::fmt::Debug;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

async fn connect_to_remote<A, T>()
where
    A: TestTransportMaker<Transport = T, Address = T::Address>,
    T: TransportSocket + Debug,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());

    let (mut conn1, _, _) = DefaultNetworkingService::<T>::start(
        A::make_transport(),
        vec![A::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
    )
    .await
    .unwrap();

    let (conn2, _, _) = DefaultNetworkingService::<T>::start(
        A::make_transport(),
        vec![A::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
    )
    .await
    .unwrap();

    let addr = conn2.local_addresses();
    conn1.connect(addr[0].clone()).unwrap();

    if let Ok(ConnectivityEvent::OutboundAccepted {
        address,
        peer_info,
        receiver_address: _,
    }) = conn1.poll_next().await
    {
        assert_eq!(address, conn2.local_addresses()[0]);
        assert_eq!(peer_info.network, *config.magic_bytes());
        assert_eq!(peer_info.version, SemVer::new(0, 1, 0));
        assert_eq!(peer_info.user_agent, p2p_config.user_agent);
        assert_eq!(
            peer_info.subscriptions,
            [PubSubTopic::Blocks, PubSubTopic::Transactions, PubSubTopic::PeerAddresses]
                .into_iter()
                .collect()
        );
    } else {
        panic!("invalid event received");
    }
}

#[tokio::test]
async fn connect_to_remote_tcp() {
    connect_to_remote::<TestTransportTcp, TcpTransportSocket>().await;
}

#[tokio::test]
async fn connect_to_remote_channels() {
    connect_to_remote::<TestTransportChannel, MpscChannelTransport>().await;
}

#[tokio::test]
async fn connect_to_remote_noise() {
    connect_to_remote::<TestTransportNoise, NoiseTcpTransport>().await;
}

async fn accept_incoming<A, T>()
where
    A: TestTransportMaker<Transport = T, Address = T::Address>,
    T: TransportSocket,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());

    let (mut conn1, _, _) = DefaultNetworkingService::<T>::start(
        A::make_transport(),
        vec![A::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
    )
    .await
    .unwrap();

    let (mut conn2, _, _) = DefaultNetworkingService::<T>::start(
        A::make_transport(),
        vec![A::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
    )
    .await
    .unwrap();

    let bind_address = conn2.local_addresses();
    conn1.connect(bind_address[0].clone()).unwrap();
    let res2 = conn2.poll_next().await;
    match res2.unwrap() {
        ConnectivityEvent::InboundAccepted {
            address: _,
            peer_info,
            receiver_address: _,
        } => {
            assert_eq!(peer_info.network, *config.magic_bytes());
            assert_eq!(peer_info.version, SemVer::new(0, 1, 0),);
            assert_eq!(peer_info.user_agent, p2p_config.user_agent);
        }
        _ => panic!("invalid event received, expected incoming connection"),
    }
}

#[tokio::test]
async fn accept_incoming_tcp() {
    accept_incoming::<TestTransportTcp, TcpTransportSocket>().await;
}

#[tokio::test]
async fn accept_incoming_channels() {
    accept_incoming::<TestTransportChannel, MpscChannelTransport>().await;
}

#[tokio::test]
async fn accept_incoming_noise() {
    accept_incoming::<TestTransportNoise, NoiseTcpTransport>().await;
}

async fn disconnect<A, T>()
where
    A: TestTransportMaker<Transport = T, Address = T::Address>,
    T: TransportSocket,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());

    let (mut conn1, _, _) = DefaultNetworkingService::<T>::start(
        A::make_transport(),
        vec![A::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
    )
    .await
    .unwrap();
    let (mut conn2, _, _) = DefaultNetworkingService::<T>::start(
        A::make_transport(),
        vec![A::make_address()],
        config,
        p2p_config,
    )
    .await
    .unwrap();

    conn1.connect(conn2.local_addresses()[0].clone()).unwrap();
    let res2 = conn2.poll_next().await;

    match res2.unwrap() {
        ConnectivityEvent::InboundAccepted {
            address: _,
            peer_info,
            receiver_address: _,
        } => {
            conn2.disconnect(peer_info.peer_id).unwrap();
        }
        _ => panic!("invalid event received, expected incoming connection"),
    }
}

#[tokio::test]
async fn disconnect_tcp() {
    disconnect::<TestTransportTcp, TcpTransportSocket>().await;
}

#[tokio::test]
async fn disconnect_channels() {
    disconnect::<TestTransportChannel, MpscChannelTransport>().await;
}

#[tokio::test]
async fn disconnect_noise() {
    disconnect::<TestTransportNoise, NoiseTcpTransport>().await;
}

async fn self_connect<A, T>()
where
    A: TestTransportMaker<Transport = T, Address = T::Address>,
    T: TransportSocket + Debug,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());

    let (mut conn1, _, _) = DefaultNetworkingService::<T>::start(
        A::make_transport(),
        vec![A::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
    )
    .await
    .unwrap();

    let (conn2, _, _) = DefaultNetworkingService::<T>::start(
        A::make_transport(),
        vec![A::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
    )
    .await
    .unwrap();

    // Try connect to self
    let addr = conn1.local_addresses();
    conn1.connect(addr[0].clone()).unwrap();

    // ConnectionError should be reported
    if let Ok(ConnectivityEvent::ConnectionError { address, error }) = conn1.poll_next().await {
        assert_eq!(address, conn1.local_addresses()[0]);
        assert_eq!(error, P2pError::DialError(DialError::AttemptToDialSelf));
    } else {
        panic!("invalid event received");
    }

    // Check that we can still connect normally after
    let addr = conn2.local_addresses();
    conn1.connect(addr[0].clone()).unwrap();
    if let Ok(ConnectivityEvent::OutboundAccepted {
        address,
        peer_info,
        receiver_address: _,
    }) = conn1.poll_next().await
    {
        assert_eq!(address, conn2.local_addresses()[0]);
        assert_eq!(peer_info.network, *config.magic_bytes());
        assert_eq!(peer_info.version, SemVer::new(0, 1, 0));
        assert_eq!(peer_info.user_agent, p2p_config.user_agent);
        assert_eq!(
            peer_info.subscriptions,
            [PubSubTopic::Blocks, PubSubTopic::Transactions, PubSubTopic::PeerAddresses]
                .into_iter()
                .collect()
        );
    } else {
        panic!("invalid event received");
    }
}

#[tokio::test]
async fn self_connect_tcp() {
    self_connect::<TestTransportTcp, TcpTransportSocket>().await;
}

#[tokio::test]
async fn self_connect_channels() {
    self_connect::<TestTransportChannel, MpscChannelTransport>().await;
}

#[tokio::test]
async fn self_connect_noise() {
    self_connect::<TestTransportNoise, NoiseTcpTransport>().await;
}

async fn invalid_outbound_peer_connect<A, T>()
where
    A: TestTransportMaker<Transport = T, Address = T::Address>,
    T: TransportSocket + Debug,
{
    let transport = A::make_transport();
    let mut listener = transport.bind(vec![A::make_address()]).await.unwrap();
    let addr = listener.local_addresses().unwrap();
    tokio::spawn(async move {
        let (mut socket, _address) = listener.accept().await.unwrap();
        let _ = socket.write_all(b"invalid message").await;
    });

    let config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let (mut conn, _, _) = DefaultNetworkingService::<T>::start(
        A::make_transport(),
        vec![],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
    )
    .await
    .unwrap();

    // Try to connect to some broken peer
    conn.connect(addr[0].clone()).unwrap();
    // `ConnectionError` should be reported
    let event = timeout(Duration::from_secs(60), conn.poll_next()).await.unwrap().unwrap();

    match event {
        ConnectivityEvent::ConnectionError { address, error: _ } => {
            assert_eq!(address, addr[0]);
        }
        event => panic!("invalid event received: {event:?}"),
    }
}

#[tokio::test]
async fn invalid_outbound_peer_connect_tcp() {
    invalid_outbound_peer_connect::<TestTransportTcp, TcpTransportSocket>().await;
}

#[tokio::test]
async fn invalid_outbound_peer_connect_channels() {
    invalid_outbound_peer_connect::<TestTransportChannel, MpscChannelTransport>().await;
}

#[tokio::test]
async fn invalid_outbound_peer_connect_noise() {
    invalid_outbound_peer_connect::<TestTransportNoise, NoiseTcpTransport>().await;
}
