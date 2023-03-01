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

use clap::Parser;
use config::DnsServerConfig;
use crawler_p2p::crawler_manager::{
    storage_impl::DnsServerStorageImpl, CrawlerManager, CrawlerManagerConfig,
};
use p2p::{
    config::{NodeType, P2pConfig},
    net::NetworkingService,
};
use tokio::sync::mpsc;

mod config;
mod crawler_p2p;
mod dns_server;
mod error;

async fn run(config: Arc<DnsServerConfig>) -> Result<void::Void, error::DnsServerError> {
    let (dns_server_cmd_tx, dns_server_cmd_rx) = mpsc::unbounded_channel();

    let chain_config = match config.network {
        config::Network::Mainnet => Arc::new(common::chain::config::create_mainnet()),
        config::Network::Testnet => Arc::new(common::chain::config::create_testnet()),
    };

    let p2p_config = Arc::new(P2pConfig {
        bind_addresses: Vec::new(),
        reserved_nodes: Vec::new(),
        max_inbound_connections: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        node_type: NodeType::DnsServer.into(),
        allow_discover_private_ips: Default::default(),
        msg_header_count_limit: Default::default(),
        msg_max_locator_count: Default::default(),
        max_request_blocks_count: Default::default(),
    });

    let transport = p2p::make_p2p_transport();

    let (conn, sync) = p2p::P2pNetworkingService::start(
        transport,
        vec![],
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
    )
    .await?;

    let storage = DnsServerStorageImpl::new(storage_lmdb::Lmdb::new(
        config.datadir.clone().into(),
        Default::default(),
        Default::default(),
        Default::default(),
    ))?;

    let crawler_config = CrawlerManagerConfig {
        reserved_nodes: config.reserved_node.clone(),
        default_p2p_port: chain_config.p2p_port(),
    };

    let mut crawler_manager = CrawlerManager::<p2p::P2pNetworkingService, _>::new(
        crawler_config,
        chain_config,
        conn,
        sync,
        storage,
        dns_server_cmd_tx,
    )?;

    let server = dns_server::DnsServer::new(config, dns_server_cmd_rx).await?;

    // Spawn for better parallelism
    let crawler_manager_task = tokio::spawn(async move { crawler_manager.run().await });
    let server_task = tokio::spawn(server.run());

    tokio::select! {
        res = crawler_manager_task => {
            res.expect("crawler should not panic")
        },
        res = server_task => {
            res.expect("server should not panic")
        },
    }
}

#[tokio::main]
async fn main() {
    let config = Arc::new(DnsServerConfig::parse());

    let result = run(config).await;

    if let Err(err) = result {
        eprintln!("DnsServer failed: {err:?}");
        std::process::exit(1)
    }
}
