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
use futures::never::Never;
use logging::log;
use tokio::sync::{mpsc, oneshot};

use common::{primitives::user_agent::UserAgent, time_getter::TimeGetter};
use config::DnsServerConfig;
use crawler_p2p::crawler_manager::{CrawlerManager, CrawlerManagerConfig};
use p2p::{
    config::{NodeType, P2pConfig},
    net::NetworkingService,
};
use utils::atomics::SeqCstAtomicBool;
use utils::default_data_dir::{default_data_dir_for_chain, prepare_data_dir};

use crate::{
    crawler_p2p::{crawler::CrawlerConfig, crawler_manager::storage::open_storage},
    error::DnsServerError,
};

mod config;
mod crawler_p2p;
mod dns_server;
mod error;

const DNS_SERVER_USER_AGENT: &str = "MintlayerDnsSeedServer";
const DNS_SERVER_DB_NAME: &str = "dns_server";

pub type Result<T> = core::result::Result<T, error::DnsServerError>;

async fn run(config: Arc<DnsServerConfig>) -> Result<Never> {
    let (dns_server_cmd_tx, dns_server_cmd_rx) = mpsc::unbounded_channel();

    let chain_type = match config.network {
        config::Network::Mainnet => common::chain::config::ChainType::Mainnet,
        config::Network::Testnet => common::chain::config::ChainType::Testnet,
    };
    let user_agent = UserAgent::try_from(DNS_SERVER_USER_AGENT).expect("expected valid user agent");
    let chain_config = Arc::new(common::chain::config::Builder::new(chain_type).build());

    let p2p_config = Arc::new(P2pConfig {
        bind_addresses: Vec::new(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Vec::new(),
        reserved_nodes: Vec::new(),
        whitelisted_addresses: Default::default(),
        // Note: this ban config (as well as any other settings related to the peer or sync manager)
        // won't have any effect on the dns server.
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: NodeType::DnsServer.into(),
        allow_discover_private_ips: Default::default(),
        user_agent,
        sync_stalling_timeout: Default::default(),
        peer_manager_config: Default::default(),
        protocol_config: Default::default(),
    });

    let transport = p2p::make_p2p_transport();
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();

    let time_getter = TimeGetter::default();

    let (conn, _messaging_handle, sync, _) = p2p::P2pNetworkingService::start(
        true,
        transport,
        vec![],
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        time_getter.clone(),
        shutdown,
        shutdown_receiver,
        subscribers_receiver,
    )
    .await?;

    let data_dir = prepare_data_dir(
        || default_data_dir_for_chain(chain_type.name()),
        &config.datadir,
    )
    .expect("Failed to prepare data directory");

    let storage = {
        let storage_data_dir = data_dir.join(DNS_SERVER_DB_NAME);
        let open_storage_backend = |data_dir| {
            storage_lmdb::Lmdb::new(
                data_dir,
                Default::default(),
                Default::default(),
                Default::default(),
            )
        };

        match open_storage(open_storage_backend(storage_data_dir.clone())) {
            Ok(storage) => Ok(storage),
            Err(err) => match err {
                DnsServerError::StorageVersionMismatch {
                    expected_version,
                    actual_version,
                } => {
                    log::warn!(
                        "Storage version mismatch, expected {}, got {}; removing the db.",
                        expected_version,
                        actual_version
                    );
                    std::fs::remove_dir_all(&storage_data_dir)?;
                    open_storage(open_storage_backend(storage_data_dir))
                }
                DnsServerError::ProtoError(_)
                | DnsServerError::AddrParseError(_)
                | DnsServerError::IoError(_)
                | DnsServerError::P2pError(_)
                | DnsServerError::StorageError(_)
                | DnsServerError::InvalidStorageState(_)
                | DnsServerError::Other(_) => Err(err),
            },
        }
    }?;

    let crawler_mgr_config = CrawlerManagerConfig {
        reserved_nodes: config.reserved_nodes.clone(),
        default_p2p_port: chain_config.p2p_port(),
    };

    let mut crawler_manager = CrawlerManager::<p2p::P2pNetworkingService, _>::new(
        time_getter,
        crawler_mgr_config,
        CrawlerConfig::default(),
        chain_config.clone(),
        conn,
        sync,
        storage,
        dns_server_cmd_tx,
    )?;

    let server = dns_server::DnsServer::new(config, chain_config, dns_server_cmd_rx).await?;

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
    utils::rust_backtrace::enable();

    logging::init_logging();

    let config = Arc::new(DnsServerConfig::parse());

    let result = run(config).await;

    if let Err(err) = result {
        eprintln!("DnsServer failed: {err:?}");
        std::process::exit(1)
    }
}
