// Copyright (c) 2021 Protocol Labs
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
    error::{self, P2pError, ProtocolError},
    message::{Message, MessageType, PubSubMessage},
    net::libp2p::{backend::Backend, types},
};
use libp2p::{gossipsub::GossipsubEvent, identify::Identify, swarm::SwarmBuilder};
use logging::log;
use serialization::Decode;

impl Backend {
    pub async fn on_gossipsub_event(&mut self, event: GossipsubEvent) -> error::Result<()> {
        match event {
            GossipsubEvent::Unsubscribed { peer_id, topic } => {
                log::trace!("peer {:?} unsubscribed from topic {:?}", peer_id, topic);
                Ok(())
            }
            GossipsubEvent::Subscribed { peer_id, topic } => {
                log::trace!("peer {:?} subscribed to topic {:?}", peer_id, topic);
                Ok(())
            }
            GossipsubEvent::GossipsubNotSupported { peer_id } => {
                // TODO: should not be possible with mintlayer, disconnect?
                log::info!("peer {:?} does not support gossipsub", peer_id);
                Ok(())
            }
            GossipsubEvent::Message {
                propagation_source,
                message_id,
                message,
            } => {
                log::trace!(
                    "gossipsub message received, message id {:?}, propagation source {:?}",
                    message_id,
                    propagation_source
                );

                let message = match Message::decode(&mut &message.data[..]) {
                    Ok(data) => data,
                    Err(_) => {
                        log::warn!(
                            "received invalid message, propagation source: {:?}",
                            propagation_source
                        );

                        if self.swarm.is_connected(&propagation_source) {
                            log::info!("notify swarm manager about invalid message");

                            // TODO: implement peer profiling
                            self.conn_tx
                                .send(types::ConnectivityEvent::Misbehaved {
                                    peer_id: propagation_source,
                                    behaviour: 0,
                                })
                                .await?;
                        }

                        return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
                    }
                };

                self.gossip_tx
                    .send(types::PubSubEvent::MessageReceived {
                        peer_id: propagation_source,
                        message,
                        message_id,
                    })
                    .await
                    .map_err(P2pError::from)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{
        self,
        libp2p::{proto::util, Libp2pService},
        NetworkService,
    };
    use common::chain::block::{consensus_data::ConsensusData, Block};
    use futures::{FutureExt, StreamExt};
    use libp2p::{
        gossipsub::{
            Gossipsub, GossipsubConfigBuilder, GossipsubEvent, GossipsubMessage,
            IdentTopic as Topic, MessageAuthenticity, MessageId, TopicHash, ValidationMode,
        },
        swarm::SwarmEvent,
        Multiaddr, PeerId,
    };
    use serialization::Encode;
    use std::{collections::HashSet, sync::Arc};

    impl PartialEq for types::PubSubEvent {
        fn eq(&self, other: &Self) -> bool {
            let types::PubSubEvent::MessageReceived {
                peer_id: p1,
                message_id: m1,
                message: msg1,
            } = self;
            let types::PubSubEvent::MessageReceived {
                peer_id: p2,
                message_id: m2,
                message: msg2,
            } = other;

            (p1 == p2) && (m1 == m2) && (msg1 == msg2)
        }
    }

    impl PartialEq for types::ConnectivityEvent {
        fn eq(&self, other: &Self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn test_valid_message() {
        let config = common::chain::config::create_mainnet();
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend, _, _, mut gossip_rx, _) =
            util::make_libp2p(config, addr, &[net::PubSubTopic::Blocks]).await;

        let peer_id = PeerId::random();
        let message_id = MessageId::new(&[123]);
        let message = Message {
            magic: [0, 1, 2, 3],
            msg: MessageType::PubSub(PubSubMessage::Block(
                Block::new(vec![], None, 1337u32, ConsensusData::None).unwrap(),
            )),
        };

        assert_eq!(
            backend
                .on_gossipsub_event(GossipsubEvent::Message {
                    propagation_source: peer_id,
                    message_id: message_id.clone(),
                    message: GossipsubMessage {
                        source: Some(peer_id),
                        data: message.encode(),
                        sequence_number: None,
                        topic: TopicHash::from_raw("test"),
                    }
                })
                .await,
            Ok(())
        );

        assert_eq!(
            gossip_rx.recv().await.unwrap(),
            types::PubSubEvent::MessageReceived {
                peer_id,
                message,
                message_id,
            }
        );
    }

    #[tokio::test]
    async fn test_invalid_message_unknown_peer() {
        let config = common::chain::config::create_mainnet();
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend, _, _, mut gossip_rx, _) =
            util::make_libp2p(config, addr, &[net::PubSubTopic::Blocks]).await;

        let peer_id = PeerId::random();
        let message_id = MessageId::new(&[123]);

        assert_eq!(
            backend
                .on_gossipsub_event(GossipsubEvent::Message {
                    propagation_source: peer_id,
                    message_id: message_id.clone(),
                    message: GossipsubMessage {
                        source: Some(peer_id),
                        data: vec![999].encode(),
                        sequence_number: None,
                        topic: TopicHash::from_raw("test"),
                    }
                })
                .await,
            Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
        );

        assert_eq!(
            gossip_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        );
    }

    #[tokio::test]
    async fn test_invalid_message_known_peer() {
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend1, _, mut conn_rx, mut gossip_rx, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            addr.clone(),
            &[net::PubSubTopic::Blocks],
        )
        .await;

        let (mut backend2, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[net::PubSubTopic::Blocks],
        )
        .await;

        util::connect_swarms::<types::ComposedBehaviour, types::ComposedBehaviour>(
            addr,
            &mut backend1.swarm,
            &mut backend2.swarm,
        )
        .await;

        let peer_id = backend2.swarm.local_peer_id();
        let message_id = MessageId::new(&[123]);
        assert_eq!(
            backend1
                .on_gossipsub_event(GossipsubEvent::Message {
                    propagation_source: *peer_id,
                    message_id: message_id.clone(),
                    message: GossipsubMessage {
                        source: Some(*peer_id),
                        data: vec![999].encode(),
                        sequence_number: None,
                        topic: TopicHash::from_raw("test"),
                    }
                })
                .await,
            Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
        );

        assert_eq!(
            gossip_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        );
        assert_eq!(
            conn_rx.try_recv(),
            Ok(types::ConnectivityEvent::Misbehaved {
                peer_id: *backend2.swarm.local_peer_id(),
                behaviour: 0u32,
            })
        );
    }

    #[tokio::test]
    async fn test_subscribed() {
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend1, _, mut conn_rx, mut gossip_rx, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            addr.clone(),
            &[net::PubSubTopic::Blocks],
        )
        .await;

        let addr2: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend2, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            addr2.clone(),
            &[net::PubSubTopic::Blocks],
        )
        .await;

        util::connect_swarms::<types::ComposedBehaviour, types::ComposedBehaviour>(
            addr,
            &mut backend1.swarm,
            &mut backend2.swarm,
        )
        .await;

        let addr3: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend3, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            addr3,
            &[net::PubSubTopic::Blocks],
        )
        .await;

        // discard all unhandled events for backend2
        while backend2.swarm.next().now_or_never().is_some() {}

        // util::connect_swarms(addr2, &mut backend2.swarm, &mut backend3.swarm).await;
        util::connect_swarms::<types::ComposedBehaviour, types::ComposedBehaviour>(
            addr2,
            &mut backend2.swarm,
            &mut backend3.swarm,
        )
        .await;

        let mut needed_subscriptions: i32 = 4;

        loop {
            tokio::select! {
                event = backend1.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::ComposedEvent::GossipsubEvent(
                        GossipsubEvent::Subscribed { peer_id, .. })))
                    => {
                        assert_eq!(peer_id, *backend2.swarm.local_peer_id());
                        needed_subscriptions -= 1;
                    }
                    Some(_) => {},
                    None => panic!("got None"),
                },
                event = backend2.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::ComposedEvent::GossipsubEvent(
                        GossipsubEvent::Subscribed { peer_id, .. })))
                    => {
                        if peer_id != *backend3.swarm.local_peer_id() {
                            assert_eq!(peer_id, *backend1.swarm.local_peer_id());
                        }
                        needed_subscriptions -= 1;
                    }
                    Some(_) => {},
                    None => panic!("got None"),
                },
                event = backend3.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::ComposedEvent::GossipsubEvent(
                        GossipsubEvent::Subscribed { peer_id, .. })))
                    => {
                        assert_eq!(peer_id, *backend2.swarm.local_peer_id());
                        needed_subscriptions -= 1;
                    }
                    Some(_) => {},
                    None => panic!("got None"),
                },
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                    panic!("didn't receive subscriptions in time");
                }
            }

            if needed_subscriptions == 0 {
                break;
            }
        }
    }

    #[tokio::test]
    async fn test_unsubscribed() {
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend1, _, mut conn_rx, mut gossip_rx, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            addr.clone(),
            &[net::PubSubTopic::Blocks],
        )
        .await;

        let addr2: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend2, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            addr2.clone(),
            &[net::PubSubTopic::Blocks],
        )
        .await;

        util::connect_swarms::<types::ComposedBehaviour, types::ComposedBehaviour>(
            addr.clone(),
            &mut backend1.swarm,
            &mut backend2.swarm,
        )
        .await;

        let addr3: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend3, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            addr3,
            &[net::PubSubTopic::Blocks],
        )
        .await;

        // discard all unhandled events for backend2
        while backend2.swarm.next().now_or_never().is_some() {}
        util::connect_swarms::<types::ComposedBehaviour, types::ComposedBehaviour>(
            addr2,
            &mut backend2.swarm,
            &mut backend3.swarm,
        )
        .await;
        let mut needed_subscriptions: i32 = 4;

        loop {
            tokio::select! {
                event = backend1.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::ComposedEvent::GossipsubEvent(
                        GossipsubEvent::Subscribed { peer_id, .. })))
                    => {
                        assert_eq!(peer_id, *backend2.swarm.local_peer_id());
                        needed_subscriptions -= 1;
                    }
                    Some(_) => {},
                    None => panic!("got None"),
                },
                event = backend2.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::ComposedEvent::GossipsubEvent(
                        GossipsubEvent::Subscribed { peer_id, .. })))
                    => {
                        if peer_id != *backend3.swarm.local_peer_id() {
                            assert_eq!(peer_id, *backend1.swarm.local_peer_id());
                        }
                        needed_subscriptions -= 1;
                    }
                    Some(_) => {},
                    None => panic!("got None"),
                },
                event = backend3.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::ComposedEvent::GossipsubEvent(
                        GossipsubEvent::Subscribed { peer_id, .. })))
                    => {
                        assert_eq!(peer_id, *backend2.swarm.local_peer_id());
                        needed_subscriptions -= 1;
                    }
                    Some(_) => {},
                    None => panic!("got None"),
                },
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                    panic!("didn't receive subscriptions in time");
                }
            }

            if needed_subscriptions == 0 {
                break;
            }
        }

        backend2
            .swarm
            .behaviour_mut()
            .gossipsub
            .unsubscribe(&Topic::new("mintlayer-gossipsub-blocks"));
        let mut needed_unsubscriptions: i32 = 2;

        loop {
            tokio::select! {
                event = backend1.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::ComposedEvent::GossipsubEvent(
                        GossipsubEvent::Unsubscribed { peer_id, .. })))
                    => {
                        assert_eq!(peer_id, *backend2.swarm.local_peer_id());
                        needed_unsubscriptions -= 1;
                    }
                    Some(_) => {}
                    None => panic!("got None"),
                },
                event = backend2.swarm.next() => match event {
                    Some(_) => {},
                    None => panic!("got None"),
                },
                event = backend3.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::ComposedEvent::GossipsubEvent(
                        GossipsubEvent::Unsubscribed { peer_id, .. })))
                    => {
                        assert_eq!(peer_id, *backend2.swarm.local_peer_id());
                        needed_unsubscriptions -= 1;
                    }
                    Some(_) => {},
                    None => panic!("got None"),
                },
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                    panic!("didn't receive subscriptions in time");
                }
            }

            if needed_unsubscriptions == 0 {
                break;
            }
        }
    }

    #[tokio::test]
    async fn test_gossipsub_not_supported() {
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let config = common::chain::config::create_mainnet();
        let (mut backend1, _, mut conn_rx, mut gossip_rx, _) =
            util::make_libp2p(config.clone(), addr.clone(), &[net::PubSubTopic::Blocks]).await;

        let (transport, peer_id, id_keys) = util::make_transport_and_keys();
        let mut swarm =
            SwarmBuilder::new(transport, util::make_identify(config, id_keys), peer_id).build();

        util::connect_swarms::<types::ComposedBehaviour, Identify>(
            addr,
            &mut backend1.swarm,
            &mut swarm,
        )
        .await;

        loop {
            tokio::select! {
                event = backend1.swarm.next() => match event {
                    Some(SwarmEvent::Behaviour(types::ComposedEvent::GossipsubEvent(
                        GossipsubEvent::GossipsubNotSupported { peer_id })))
                    => {
                        assert_eq!(peer_id, *swarm.local_peer_id());
                        break;
                    }
                    Some(_) => {},
                    None => panic!("got None"),
                },
                event = swarm.next() => {},
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                    panic!("didn't receive subscriptions in time");
                }
            }
        }
    }
}
