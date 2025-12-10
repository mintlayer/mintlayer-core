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

use std::sync::Arc;

use common::{chain::config, primitives::user_agent::mintlayer_core_user_agent};
use networking::transport::TcpTransportSocket;
use p2p_types::{
    services::{Service, Services},
    PeerId,
};
use test_utils::BasicTestTimeGetter;

use crate::{
    config::{NodeType, P2pConfig},
    error::{ConnectionValidationError, P2pError},
    net::{
        default_backend::{ConnectivityHandle, DefaultNetworkingService},
        types::{PeerInfo, PeerRole},
    },
    peer_manager::PeerManager,
    test_helpers::{peerdb_inmemory_store, TEST_PROTOCOL_VERSION},
    PeerManagerEvent,
};

#[tracing::instrument]
#[test]
fn validate_services() {
    type TestNetworkingService = DefaultNetworkingService<TcpTransportSocket>;

    for node_type in [NodeType::Full, NodeType::BlocksOnly] {
        let chain_config = Arc::new(config::create_unit_test_config());
        let p2p_config = Arc::new(P2pConfig {
            node_type: node_type.into(),

            bind_addresses: Default::default(),
            socks5_proxy: Default::default(),
            disable_noise: Default::default(),
            boot_nodes: Default::default(),
            reserved_nodes: Default::default(),
            whitelisted_addresses: Default::default(),
            ban_config: Default::default(),
            outbound_connection_timeout: Default::default(),
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            peer_handshake_timeout: Default::default(),
            max_clock_diff: Default::default(),
            allow_discover_private_ips: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            sync_stalling_timeout: Default::default(),
            peer_manager_config: Default::default(),
            protocol_config: Default::default(),
            custom_disconnection_reason_for_banning: Default::default(),
        });

        let (cmd_sender, _cmd_receiver) = tokio::sync::mpsc::unbounded_channel();
        let (_conn_event_sender, conn_event_receiver) = tokio::sync::mpsc::unbounded_channel();
        let (_peer_mgr_event_sender, peer_mgr_event_receiver) =
            tokio::sync::mpsc::unbounded_channel::<PeerManagerEvent>();
        let time_getter = BasicTestTimeGetter::new();
        let connectivity_handle = ConnectivityHandle::<TestNetworkingService>::new(
            vec![],
            cmd_sender,
            conn_event_receiver,
        );

        let mut pm = PeerManager::<TestNetworkingService, _>::new(
            true,
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            connectivity_handle,
            peer_mgr_event_receiver,
            time_getter.get_time_getter(),
            peerdb_inmemory_store(),
        )
        .unwrap();

        // Make sure that all services are powers of two (it's required below)
        for (index, service) in Service::ALL.into_iter().enumerate() {
            assert_eq!(service as u64, 2u64.pow(index as u32));
        }

        // List all service combinations
        for services in 0..2u64.pow(Service::ALL.len() as u32) {
            let services = Services::from_u64(services);

            // List all peer roles
            for peer_role in enum_iterator::all::<PeerRole>() {
                let peer_id_1 = PeerId::new();
                let peer_info = PeerInfo {
                    peer_id: peer_id_1,
                    protocol_version: TEST_PROTOCOL_VERSION,
                    network: *chain_config.magic_bytes(),
                    software_version: *chain_config.software_version(),
                    user_agent: mintlayer_core_user_agent(),
                    common_services: services,
                };

                let res = pm.validate_connection(
                    &"127.0.0.1:1234".parse().unwrap(),
                    peer_role,
                    &peer_info,
                );

                if services.is_empty() {
                    assert_eq!(
                        res,
                        Err(P2pError::ConnectionValidationFailed(
                            ConnectionValidationError::NoCommonServices
                        ))
                    );
                } else {
                    let expected_services: Option<Services> = match peer_role {
                        PeerRole::Inbound
                        | PeerRole::OutboundReserved
                        | PeerRole::OutboundManual
                        | PeerRole::Feeler => {
                            // Inbound, OutboundReserved, OutboundManual and Feeler connections
                            // are allowed to nodes with any combination of services.
                            None
                        }
                        PeerRole::OutboundFullRelay => match node_type {
                            NodeType::Full => Some(
                                [Service::Blocks, Service::Transactions, Service::PeerAddresses]
                                    .as_slice()
                                    .into(),
                            ),
                            NodeType::BlocksOnly => {
                                Some([Service::Blocks, Service::PeerAddresses].as_slice().into())
                            }
                            NodeType::DnsServer => unimplemented!(),
                            NodeType::Inactive => unimplemented!(),
                        },
                        PeerRole::OutboundBlockRelay => Some([Service::Blocks].as_slice().into()),
                    };

                    if let Some(expected_services) = expected_services {
                        if services == expected_services {
                            assert_eq!(res, Ok(()));
                        } else {
                            assert_eq!(
                                res,
                                Err(P2pError::ConnectionValidationFailed(
                                    ConnectionValidationError::InsufficientServices {
                                        needed_services: expected_services,
                                        available_services: services
                                    }
                                ))
                            );
                        }
                    } else {
                        assert_eq!(res, Ok(()));
                    }
                }
            }
        }
    }
}
