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
use crate::{
    error::P2pError,
    net::libp2p::{backend::Backend, types},
};
use libp2p::{mdns::MdnsEvent, Multiaddr, PeerId};

impl Backend {
    async fn send_mdns_event(
        &mut self,
        peers: Vec<(PeerId, Multiaddr)>,
        event_fn: impl FnOnce(Vec<(PeerId, Multiaddr)>) -> types::ConnectivityEvent,
    ) -> crate::Result<()> {
        if !self.relay_mdns || peers.is_empty() {
            return Ok(());
        }

        self.conn_tx.send(event_fn(peers)).await.map_err(P2pError::from)
    }

    pub async fn on_mdns_event(&mut self, event: MdnsEvent) -> crate::Result<()> {
        match event {
            MdnsEvent::Discovered(peers) => {
                self.send_mdns_event(peers.collect(), |peers| {
                    types::ConnectivityEvent::Discovered { peers }
                })
                .await
            }
            MdnsEvent::Expired(expired) => {
                self.send_mdns_event(expired.collect(), |peers| {
                    types::ConnectivityEvent::Expired { peers }
                })
                .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{
        self,
        libp2p::{behaviour, proto::util},
    };
    use futures::StreamExt;
    use libp2p::{
        identify::Identify,
        swarm::{SwarmBuilder, SwarmEvent},
    };

    #[ignore]
    #[tokio::test]
    async fn test_on_discovered() {
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend1, _, mut conn_rx, _gossip_rx, _) =
            util::make_libp2p(common::chain::config::create_mainnet(), addr.clone(), &[]).await;

        let (mut backend2, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;

        util::connect_swarms::<behaviour::Libp2pBehaviour, behaviour::Libp2pBehaviour>(
            addr,
            &mut backend1.swarm,
            &mut backend2.swarm,
        )
        .await;

        loop {
            tokio::select! {
                event = backend1.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::ComposedEvent::MdnsEvent(event))) => {
                        assert!(std::matches!(event, MdnsEvent::Discovered(_)));
                        assert_eq!(
                            backend1.on_mdns_event(event).await,
                            Ok(())
                        );
                        assert!(std::matches!(
                            conn_rx.try_recv(),
                            Ok(types::ConnectivityEvent::Discovered { .. })
                        ));
                        break;
                    }
                    Some(_) => {},
                    None => panic!("got None"),
                },
                _ = backend2.swarm.next() => {}
            }
        }
    }

    #[ignore]
    #[tokio::test]
    async fn test_on_discovered_no_relay() {
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend1, _, mut conn_rx, _gossip_rx, _) =
            util::make_libp2p(common::chain::config::create_mainnet(), addr.clone(), &[]).await;

        let (mut backend2, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;

        backend1.relay_mdns = false;
        backend2.relay_mdns = false;

        util::connect_swarms::<behaviour::Libp2pBehaviour, behaviour::Libp2pBehaviour>(
            addr,
            &mut backend1.swarm,
            &mut backend2.swarm,
        )
        .await;

        loop {
            tokio::select! {
                event = backend1.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::ComposedEvent::MdnsEvent(event))) => {
                        assert!(std::matches!(event, MdnsEvent::Discovered(_)));
                        assert_eq!(
                            backend1.on_mdns_event(event).await,
                            Ok(())
                        );
                        assert!(std::matches!(
                            conn_rx.try_recv(),
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty),
                        ));
                        break;
                    }
                    Some(_) => {},
                    None => panic!("got None"),
                },
                _ = backend2.swarm.next() => {}
            }
        }
    }

    #[ignore]
    #[tokio::test]
    async fn test_on_expired() {
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend1, _, mut conn_rx, _, _) =
            util::make_libp2p(common::chain::config::create_mainnet(), addr.clone(), &[]).await;

        let (mut backend2, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;

        util::connect_swarms::<behaviour::Libp2pBehaviour, behaviour::Libp2pBehaviour>(
            addr,
            &mut backend1.swarm,
            &mut backend2.swarm,
        )
        .await;

        loop {
            tokio::select! {
                event = backend1.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::ComposedEvent::MdnsEvent(event))) => {
                        assert_eq!(
                            backend1.on_mdns_event(event).await,
                            Ok(())
                        );

                        match conn_rx.try_recv() {
                            Ok(types::ConnectivityEvent::Discovered { peers }) => {
                                if peers.iter().any(|(peer_id, _)| peer_id == backend2.swarm.local_peer_id()) {
                                    backend1.swarm.disconnect_peer_id(*backend2.swarm.local_peer_id()).unwrap();
                                }
                            }
                            Ok(types::ConnectivityEvent::Expired { peers }) => {
                                if peers.iter().any(|(peer_id, _)| peer_id == backend2.swarm.local_peer_id()) {
                                    break;
                                }
                            }
                            _ => {
                                panic!("channel empty or invalid event received");
                            }
                        }
                    }
                    Some(_) => {}
                    None => panic!("got None"),
                },
                _event = backend2.swarm.next() => {}
            }
        }
    }

    #[ignore]
    #[tokio::test]
    async fn test_on_expired_no_relay() {
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend1, _, mut conn_rx, _gossip_rx, _) =
            util::make_libp2p(common::chain::config::create_mainnet(), addr.clone(), &[]).await;

        let (mut backend2, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;

        backend1.relay_mdns = false;
        backend2.relay_mdns = false;

        util::connect_swarms::<behaviour::Libp2pBehaviour, behaviour::Libp2pBehaviour>(
            addr,
            &mut backend1.swarm,
            &mut backend2.swarm,
        )
        .await;

        loop {
            tokio::select! {
                event = backend1.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::ComposedEvent::MdnsEvent(event))) => {
                        assert_eq!(
                            backend1.on_mdns_event(event).await,
                            Ok(())
                        );

                        if let Err(tokio::sync::mpsc::error::TryRecvError::Empty) = conn_rx.try_recv() {
                            break;
                        }
                    }
                    Some(_) => {},
                    None => panic!("got None"),
                },
                _event = backend2.swarm.next() => {}
            }
        }
    }

    #[ignore]
    #[tokio::test]
    async fn test_mdns_not_supported() {
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let config = common::chain::config::create_mainnet();
        let (mut backend1, _, _conn_rx, _gossip_rx, _) = util::make_libp2p(
            config.clone(),
            addr.clone(),
            &[net::types::PubSubTopic::Blocks],
        )
        .await;

        let (transport, peer_id, id_keys) = util::make_transport_and_keys();
        let mut swarm =
            SwarmBuilder::new(transport, util::make_identify(config, id_keys), peer_id).build();

        util::connect_swarms::<behaviour::Libp2pBehaviour, Identify>(
            addr,
            &mut backend1.swarm,
            &mut swarm,
        )
        .await;

        loop {
            tokio::select! {
                event = backend1.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::ComposedEvent::MdnsEvent(MdnsEvent::Discovered(peers)))) => {
                        for (peer, _addr) in peers {
                            assert_ne!(peer, *swarm.local_peer_id());
                        }
                    }
                    Some(SwarmEvent::Behaviour(types::ComposedEvent::MdnsEvent(MdnsEvent::Expired(peers)))) => {
                        for (peer, _addr) in peers {
                            assert_ne!(peer, *swarm.local_peer_id());
                        }
                    }
                    Some(_) => {},
                    None => panic!("got None"),
                },
                _event = swarm.next() => {},
                _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {
                    break;
                }
            }
        }
    }
}
