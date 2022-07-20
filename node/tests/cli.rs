// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{net::SocketAddr, path::Path, str::FromStr};

use assert_cmd::Command;
use directories::UserDirs;
use tempdir::TempDir;

use common::chain::config::ChainType;
use node::{NodeConfig, RunOptions};

const BIN_NAME: &str = env!("CARGO_BIN_EXE_node");
const CONFIG_NAME: &str = "config.toml";

// This test is only needed because the node name ix hardcoded here, so if the name is changed we
// get an error that is easy to understand.
#[test]
fn node_path_is_correct() {
    assert!(Path::new(BIN_NAME).is_file());
}

#[test]
fn no_args() {
    Command::new(BIN_NAME).assert().failure();
}

#[test]
fn create_default_config() {
    let data_dir = TempDir::new("").unwrap();

    Command::new(BIN_NAME)
        .arg("--datadir")
        .arg(data_dir.path().to_str().unwrap())
        .arg("create-config")
        .assert()
        .success();
    let config_path = data_dir.path().join(CONFIG_NAME);
    assert!(config_path.is_file());

    let options = default_run_options();
    let config = NodeConfig::read(&config_path, &options).unwrap();

    assert_eq!(config.datadir, data_dir.path());

    assert_eq!(config.chainstate.max_db_commit_attempts, 10);
    assert_eq!(config.chainstate.max_orphan_blocks, 512);

    assert_eq!(config.p2p.bind_address, "/ip6/::1/tcp/3031");
    assert_eq!(config.p2p.ban_threshold, 100);
    assert_eq!(config.p2p.outbound_connection_timeout, 10);

    assert_eq!(
        config.rpc.bind_address,
        SocketAddr::from_str("127.0.0.1:3030").unwrap()
    );
}

// Check that the config fields are overwritten by the run options.
#[test]
fn read_config_override_values() {
    let data_dir = TempDir::new("").unwrap();

    Command::new(BIN_NAME)
        .arg("--datadir")
        .arg(data_dir.path().to_str().unwrap())
        .arg("create-config")
        .assert()
        .success();
    let config_path = data_dir.path().join(CONFIG_NAME);
    assert!(config_path.is_file());

    let max_db_commit_attempts = 1;
    let max_orphan_blocks = 2;
    let p2p_addr = "address";
    let p2p_ban_threshold = 3;
    let p2p_timeout = 10000;
    let rpc_addr = SocketAddr::from_str("127.0.0.1:5432").unwrap();
    let enable_mdns = false;

    let options = RunOptions {
        net: ChainType::Mainnet,
        max_db_commit_attempts: Some(max_db_commit_attempts),
        max_orphan_blocks: Some(max_orphan_blocks),
        p2p_addr: Some(p2p_addr.into()),
        p2p_ban_threshold: Some(p2p_ban_threshold),
        p2p_outbound_connection_timeout: Some(p2p_timeout),
        enable_mdns: Some(enable_mdns),
        mdns_query_interval: None,
        mdns_enable_ipv6: None,
        rpc_addr: Some(rpc_addr),
    };
    let config = NodeConfig::read(&config_path, &options).unwrap();

    assert_eq!(config.datadir, data_dir.path());

    assert_eq!(
        config.chainstate.max_db_commit_attempts,
        max_db_commit_attempts
    );
    assert_eq!(config.chainstate.max_orphan_blocks, max_orphan_blocks);

    assert_eq!(config.p2p.bind_address, p2p_addr);
    assert_eq!(config.p2p.ban_threshold, p2p_ban_threshold);
    assert_eq!(config.p2p.outbound_connection_timeout, p2p_timeout);

    assert_eq!(config.rpc.bind_address, rpc_addr);
}

// Check that the `--conf` option has the precedence over the default data directory value.
#[test]
fn custom_config_path() {
    let temp_dir = TempDir::new("").unwrap();
    let config_path = temp_dir.path().join(CONFIG_NAME);

    Command::new(BIN_NAME)
        .arg("--conf")
        .arg(config_path.to_str().unwrap())
        .arg("create-config")
        .assert()
        .success();
    let data_dir = UserDirs::new().unwrap().home_dir().join(".mintlayer");
    assert!(data_dir.is_dir());
    assert!(config_path.is_file());

    let options = default_run_options();
    let config = NodeConfig::read(&config_path, &options).unwrap();

    assert_eq!(config.datadir, data_dir);
}

// Check that the `--conf` option has the precedence over the `--datadir` option.
#[test]
fn custom_config_path_and_data_dir() {
    let data_dir = TempDir::new("").unwrap();
    let temp_dir = TempDir::new("").unwrap();
    let config_path = temp_dir.path().join(CONFIG_NAME);

    Command::new(BIN_NAME)
        .arg("--datadir")
        .arg(data_dir.path().to_str().unwrap())
        .arg("--conf")
        .arg(config_path.to_str().unwrap())
        .arg("create-config")
        .assert()
        .success();
    assert!(config_path.is_file());

    let options = default_run_options();
    let config = NodeConfig::read(&config_path, &options).unwrap();

    assert_eq!(config.datadir, data_dir.path());
}

fn default_run_options() -> RunOptions {
    RunOptions {
        net: ChainType::Mainnet,
        max_db_commit_attempts: None,
        max_orphan_blocks: None,
        p2p_addr: None,
        p2p_ban_threshold: None,
        p2p_outbound_connection_timeout: None,
        enable_mdns: None,
        mdns_query_interval: None,
        mdns_enable_ipv6: None,
        rpc_addr: None,
    }
}
