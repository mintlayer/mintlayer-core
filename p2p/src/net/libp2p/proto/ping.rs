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
use libp2p::ping::{self, PingEvent};
use logging::log;

impl Backend {
    pub async fn on_ping_event(&mut self, event: PingEvent) -> crate::Result<()> {
        match event {
            ping::Event {
                peer,
                result: Result::Ok(ping::Success::Ping { rtt }),
            } => {
                // TODO: report rtt to swarm manager?
                log::debug!("peer {:?} responded to ping, rtt {:?}", peer, rtt);
                Ok(())
            }
            ping::Event {
                peer,
                result: Result::Ok(ping::Success::Pong),
            } => {
                log::debug!("peer {:?} responded to pong", peer);
                Ok(())
            }
            ping::Event {
                peer,
                result: Result::Err(ping::Failure::Timeout),
            } => {
                log::warn!("ping timeout for peer {:?}", peer);
                Ok(())
            }
            ping::Event {
                peer,
                result: Result::Err(ping::Failure::Unsupported),
            } => {
                log::error!("peer {:?} doesn't support libp2p::ping", peer);

                let _ = self.swarm.disconnect_peer_id(peer);
                self.conn_tx
                    .send(types::ConnectivityEvent::Disconnected { peer_id: peer })
                    .await
                    .map_err(P2pError::from)
            }
            ping::Event {
                peer: _,
                result: Result::Err(ping::Failure::Other { error }),
            } => {
                log::error!("unknown ping failure: {:?}", error);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::net::libp2p::{behaviour, proto::util, types};
    use futures::StreamExt;
    use libp2p::{
        ping,
        swarm::{SwarmBuilder, SwarmEvent},
        Multiaddr,
    };
    use std::time::Duration;

    #[tokio::test]
    async fn test_successful_ping_pong() {
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend1, _, _conn_rx, _gossip_rx, _) =
            util::make_libp2p(common::chain::config::create_mainnet(), addr.clone(), &[]).await;

        let addr2: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend2, _, _, _, _) =
            util::make_libp2p(common::chain::config::create_mainnet(), addr2.clone(), &[]).await;

        util::connect_swarms::<behaviour::Libp2pBehaviour, behaviour::Libp2pBehaviour>(
            addr,
            &mut backend1.swarm,
            &mut backend2.swarm,
        )
        .await;

        let mut needed_events: i32 = 2;

        loop {
            tokio::select! {
                event = backend1.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::Libp2pBehaviourEvent::PingEvent(
                        ping::Event { result: Result::Ok(_), .. }
                    ))) => {
                        needed_events -= 1;
                    }
                    Some(_) => {}
                    None => panic!("channel closed"),
                },
                event = backend2.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::Libp2pBehaviourEvent::PingEvent(
                        ping::Event { result: Result::Ok(_), .. }
                    ))) => {
                        needed_events -= 1;
                    }
                    Some(_) => {}
                    None => panic!("channel closed"),
                },
            }

            if needed_events == 0 {
                break;
            }
        }
    }

    #[tokio::test]
    async fn test_remote_doesnt_respond() {
        // TODO: add better test utilites
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend1, _, _conn_rx, _gossip_rx, _) = util::make_libp2p_with_ping(
            common::chain::config::create_mainnet(),
            addr.clone(),
            &[],
            util::make_ping(
                Some(Duration::from_secs(2)),
                Some(Duration::from_secs(2)),
                Some(3),
            ),
        )
        .await;

        let (transport, peer_id, _id_keys) = util::make_transport_and_keys();
        let mut swarm = SwarmBuilder::new(
            transport,
            util::make_ping(
                Some(Duration::from_secs(2)),
                Some(Duration::from_secs(2)),
                Some(3),
            ),
            peer_id,
        )
        .build();

        util::connect_swarms::<behaviour::Libp2pBehaviour, ping::Behaviour>(
            addr,
            &mut backend1.swarm,
            &mut swarm,
        )
        .await;
        let mut needed_events: i32 = 2;

        loop {
            tokio::select! {
                event = backend1.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::Libp2pBehaviourEvent::PingEvent(
                        ping::Event { result: Result::Err(e), .. }
                    ))) => {
                        if let ping::Failure::Timeout = e {
                            needed_events -= 1;
                        } else {
                            panic!("invalid ping event received");
                        }
                    }
                    Some(_) => {}
                    None => panic!("channel closed"),
                },
            }

            if needed_events == 0 {
                break;
            }
        }
    }

    #[tokio::test]
    async fn test_ping_not_supported() {
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let config = common::chain::config::create_mainnet();
        let (mut backend1, _, mut conn_rx, _gossip_rx, _) = util::make_libp2p_with_ping(
            config.clone(),
            addr.clone(),
            &[],
            util::make_ping(
                Some(Duration::from_secs(2)),
                Some(Duration::from_secs(2)),
                Some(3),
            ),
        )
        .await;

        let (transport, peer_id, id_keys) = util::make_transport_and_keys();
        let mut swarm =
            SwarmBuilder::new(transport, util::make_identify(config, id_keys), peer_id).build();

        util::connect_swarms::<behaviour::Libp2pBehaviour, libp2p::identify::Identify>(
            addr,
            &mut backend1.swarm,
            &mut swarm,
        )
        .await;

        let mut needed_events: i32 = 2;
        loop {
            tokio::select! {
                event = backend1.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::Libp2pBehaviourEvent::PingEvent(inner))) => {
                        if let ping::Event { result: Result::Err(ping::Failure::Unsupported), peer } = inner {
                            assert_eq!(
                                backend1.on_ping_event(inner).await,
                                Ok(())
                            );
                            assert_eq!(
                                conn_rx.try_recv(),
                                Ok(types::ConnectivityEvent::Disconnected { peer_id: peer })
                            );
                            needed_events -= 1;
                        }
                    }
                    Some(SwarmEvent::ConnectionClosed { .. }) => {
                        needed_events -= 1;
                    }
                    Some(_) => {}
                    None => panic!("channel closed"),
                },
                event = swarm.next() => match event {
                    Some(_) => {}
                    None => panic!("channel closed"),
                }
            }

            if needed_events == 0 {
                break;
            }
        }
    }
}
