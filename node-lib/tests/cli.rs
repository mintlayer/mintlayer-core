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

use std::{net::SocketAddr, num::NonZeroU64, path::Path, str::FromStr};

use common::chain::config::create_testnet;
use tempfile::TempDir;

use node_lib::{NodeConfigFile, NodeTypeConfigFile, RunOptions, StorageBackendConfigFile};
use utils_networking::IpOrSocketAddress;

const CONFIG_NAME: &str = "config.toml";

fn create_empty_file(path: impl AsRef<Path>) {
    let path = path.as_ref();
    let _file = std::fs::File::create(path).unwrap();
}

#[test]
fn create_default_config() {
    let data_dir = TempDir::new().unwrap();

    create_empty_file(data_dir.path().join(CONFIG_NAME));

    let config_path = data_dir.path().join(CONFIG_NAME);
    assert!(config_path.is_file());

    let chain_config = create_testnet();

    let options = RunOptions::default();
    let config = NodeConfigFile::read(&chain_config, &config_path, &options).unwrap();

    assert_eq!(
        config
            .chainstate
            .clone()
            .unwrap_or_default()
            .chainstate_config
            .max_db_commit_attempts,
        None
    );
    assert_eq!(
        config.chainstate.unwrap_or_default().chainstate_config.max_orphan_blocks,
        None
    );

    assert!(config
        .p2p
        .clone()
        .unwrap_or_default()
        .bind_addresses
        .unwrap_or_default()
        .is_empty());
    assert_eq!(
        config.p2p.clone().unwrap_or_default().discouragement_threshold,
        None
    );
    assert_eq!(
        config.p2p.clone().unwrap_or_default().discouragement_duration,
        None
    );
    assert_eq!(
        config.p2p.clone().unwrap_or_default().outbound_connection_timeout,
        None
    );

    assert_eq!(
        config.rpc.unwrap_or_default().bind_address,
        Some(SocketAddr::from_str("127.0.0.1:13030").unwrap())
    );
}

// Check that the config fields are overwritten by the run options.
#[test]
fn read_config_override_values() {
    let data_dir = TempDir::new().unwrap();

    create_empty_file(data_dir.path().join(CONFIG_NAME));

    let config_path = data_dir.path().join(CONFIG_NAME);
    assert!(config_path.is_file());

    let chain_config = create_testnet();

    let blockprod_min_peers_to_produce_blocks = 10;
    let blockprod_skip_ibd_check = true;
    let blockprod_use_current_time_if_non_pos = true;
    let max_db_commit_attempts = 1;
    let max_orphan_blocks = 2;
    let p2p_networking_enabled = false;
    let p2p_bind_addr = "127.0.0.1:44444".parse::<SocketAddr>().unwrap();
    let p2p_socks5_proxy = "socks5_proxy";
    let p2p_disable_noise = false;
    let p2p_boot_node: IpOrSocketAddress = "127.0.0.1".parse().unwrap();
    let p2p_reserved_node: IpOrSocketAddress = "127.0.0.1".parse().unwrap();
    let p2p_max_inbound_connections = 123;
    let p2p_discouragement_threshold = 3;
    let p2p_discouragement_duration = 234;
    let p2p_timeout = NonZeroU64::new(10000).unwrap();
    let p2p_ping_check_period = 30;
    let p2p_ping_timeout = NonZeroU64::new(60).unwrap();
    let p2p_sync_stalling_timeout = NonZeroU64::new(37).unwrap();
    let p2p_max_clock_diff = 15;
    let p2p_force_dns_query_if_no_global_addresses_known = true;
    let rpc_bind_address = "127.0.0.1:5432".parse().unwrap();
    let backend_type = StorageBackendConfigFile::InMemory;
    let node_type = NodeTypeConfigFile::FullNode;
    let max_tip_age = 1000;
    let rpc_username = "username";
    let rpc_password = "password";
    let rpc_cookie_file = "cookie_file";
    let min_tx_relay_fee_rate = 321;
    let enable_chainstate_heavy_checks = true;
    let allow_checkpoints_mismatch = true;

    let options = RunOptions {
        blockprod_min_peers_to_produce_blocks: Some(blockprod_min_peers_to_produce_blocks),
        blockprod_skip_ibd_check: Some(blockprod_skip_ibd_check),
        blockprod_use_current_time_if_non_pos: Some(blockprod_use_current_time_if_non_pos),
        storage_backend: Some(backend_type.clone()),
        node_type: Some(node_type),
        mock_time: None,
        max_db_commit_attempts: Some(max_db_commit_attempts),
        max_orphan_blocks: Some(max_orphan_blocks),
        p2p_networking_enabled: Some(p2p_networking_enabled),
        p2p_bind_addresses: Some(vec![p2p_bind_addr]),
        p2p_socks5_proxy: Some(p2p_socks5_proxy.to_owned()),
        p2p_disable_noise: Some(p2p_disable_noise),
        p2p_boot_nodes: Some(vec![p2p_boot_node.clone()]),
        p2p_reserved_nodes: Some(vec![p2p_reserved_node.clone()]),
        p2p_max_inbound_connections: Some(p2p_max_inbound_connections),
        p2p_discouragement_threshold: Some(p2p_discouragement_threshold),
        p2p_discouragement_duration: Some(p2p_discouragement_duration),
        p2p_outbound_connection_timeout: Some(p2p_timeout),
        p2p_ping_check_period: Some(p2p_ping_check_period),
        p2p_ping_timeout: Some(p2p_ping_timeout),
        p2p_sync_stalling_timeout: Some(p2p_sync_stalling_timeout),
        p2p_max_clock_diff: Some(p2p_max_clock_diff),
        p2p_whitelist_addr: None,
        p2p_force_dns_query_if_no_global_addresses_known: Some(
            p2p_force_dns_query_if_no_global_addresses_known,
        ),
        max_tip_age: Some(max_tip_age),
        rpc_bind_address: Some(rpc_bind_address),
        rpc_enabled: Some(true),
        rpc_username: Some(rpc_username.to_owned()),
        rpc_password: Some(rpc_password.to_owned()),
        rpc_cookie_file: Some(rpc_cookie_file.to_owned()),
        clean_data: Some(false),
        min_tx_relay_fee_rate: Some(min_tx_relay_fee_rate),
        force_allow_run_as_root_outer: Default::default(),
        enable_chainstate_heavy_checks: Some(enable_chainstate_heavy_checks),
        allow_checkpoints_mismatch: Some(allow_checkpoints_mismatch),
        // Note: there is no correspondence to this option inside NodeConfigFile;
        // the contents of the csv file will become part of ChainConfig.
        custom_checkpoints_csv_file: Some("foo.csv".to_owned().into()),
    };
    let config = NodeConfigFile::read(&chain_config, &config_path, &options).unwrap();

    assert_eq!(
        config.blockprod.as_ref().unwrap().min_peers_to_produce_blocks,
        Some(blockprod_min_peers_to_produce_blocks),
    );

    assert_eq!(
        config.blockprod.as_ref().unwrap().skip_ibd_check,
        Some(blockprod_skip_ibd_check)
    );

    assert_eq!(
        config.blockprod.as_ref().unwrap().use_current_time_if_non_pos,
        Some(blockprod_use_current_time_if_non_pos)
    );

    assert_eq!(
        config.chainstate.as_ref().unwrap().chainstate_config.max_db_commit_attempts,
        Some(max_db_commit_attempts)
    );
    assert_eq!(
        config.chainstate.as_ref().unwrap().chainstate_config.max_orphan_blocks,
        Some(max_orphan_blocks)
    );
    assert_eq!(
        config.chainstate.as_ref().unwrap().chainstate_config.max_tip_age,
        Some(max_tip_age)
    );

    assert_eq!(
        config.mempool.unwrap().min_tx_relay_fee_rate,
        Some(min_tx_relay_fee_rate)
    );

    assert_eq!(
        config.chainstate.as_ref().unwrap().chainstate_config.enable_heavy_checks,
        Some(enable_chainstate_heavy_checks)
    );

    assert_eq!(
        config.chainstate.as_ref().unwrap().chainstate_config.allow_checkpoints_mismatch,
        Some(allow_checkpoints_mismatch)
    );

    assert_eq!(
        config.p2p.as_ref().unwrap().networking_enabled,
        Some(p2p_networking_enabled)
    );
    assert_eq!(
        config.p2p.as_ref().unwrap().bind_addresses,
        Some(vec!(p2p_bind_addr))
    );
    assert_eq!(
        config.p2p.as_ref().unwrap().socks5_proxy,
        Some(p2p_socks5_proxy.to_owned())
    );
    assert_eq!(
        config.p2p.as_ref().unwrap().disable_noise,
        Some(p2p_disable_noise)
    );
    assert_eq!(
        config.p2p.as_ref().unwrap().boot_nodes,
        Some(vec!(p2p_boot_node))
    );
    assert_eq!(
        config.p2p.as_ref().unwrap().reserved_nodes,
        Some(vec!(p2p_reserved_node))
    );
    assert_eq!(
        config.p2p.as_ref().unwrap().max_inbound_connections,
        Some(p2p_max_inbound_connections)
    );
    assert_eq!(
        config.p2p.as_ref().unwrap().discouragement_threshold,
        Some(p2p_discouragement_threshold)
    );
    assert_eq!(
        config.p2p.as_ref().unwrap().discouragement_duration,
        Some(p2p_discouragement_duration)
    );
    assert_eq!(
        config.p2p.as_ref().unwrap().outbound_connection_timeout,
        Some(p2p_timeout)
    );
    assert_eq!(
        config.p2p.as_ref().unwrap().ping_check_period,
        Some(p2p_ping_check_period)
    );
    assert_eq!(
        config.p2p.as_ref().unwrap().ping_timeout,
        Some(p2p_ping_timeout)
    );
    assert_eq!(
        config.p2p.as_ref().unwrap().sync_stalling_timeout,
        Some(p2p_sync_stalling_timeout)
    );
    assert_eq!(
        config.p2p.as_ref().unwrap().max_clock_diff,
        Some(p2p_max_clock_diff)
    );
    assert_eq!(config.p2p.as_ref().unwrap().node_type, Some(node_type));
    assert_eq!(
        config.p2p.as_ref().unwrap().force_dns_query_if_no_global_addresses_known,
        Some(p2p_force_dns_query_if_no_global_addresses_known)
    );

    assert_eq!(
        config.rpc.clone().unwrap().bind_address,
        Some(rpc_bind_address)
    );
    assert!(config.rpc.clone().unwrap().rpc_enabled.unwrap());

    assert_eq!(
        config.rpc.as_ref().unwrap().username.as_deref(),
        Some(rpc_username)
    );
    assert_eq!(
        config.rpc.as_ref().unwrap().password.as_deref(),
        Some(rpc_password)
    );
    assert_eq!(
        config.rpc.as_ref().unwrap().cookie_file.as_deref(),
        Some(rpc_cookie_file)
    );

    assert_eq!(config.chainstate.unwrap().storage_backend, backend_type);
}
