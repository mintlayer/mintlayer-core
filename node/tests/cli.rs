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

use common::chain::config::ChainType;
use node::{NodeConfig, RunOptions};

const BIN_NAME: &str = env!("CARGO_BIN_EXE_node");
const CONFIG_PATH: &str = concat!(env!("CARGO_TARGET_TMPDIR"), "/test_mintlayer.toml");

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
    Command::new(BIN_NAME)
        .arg("create-config")
        .arg("--path")
        .arg(CONFIG_PATH)
        .assert()
        .success();
    let options = RunOptions {
        config_path: CONFIG_PATH.into(),
        net: ChainType::Mainnet,
        max_db_commit_attempts: None,
        max_orphan_blocks: None,
        p2p_addr: None,
        p2p_ban_threshold: None,
        p2p_outbound_connection_timeout: None,
        rpc_addr: None,
    };
    let config = NodeConfig::read(&options).unwrap();

    assert_eq!(config.chainstate.max_db_commit_attempts, 10);
    assert_eq!(config.chainstate.max_orphan_blocks, 512);

    assert_eq!(config.p2p.bind_address, "/ip6/::1/tcp/3031");
    assert_eq!(config.p2p.ban_threshold, 100);
    assert_eq!(config.p2p.outbound_connection_timeout, 10);

    assert_eq!(
        config.rpc.address,
        SocketAddr::from_str("127.0.0.1:3030").unwrap()
    );
}

// Check that the config fields are overwritten by the run options.
#[test]
fn read_config_override_values() {
    Command::new(BIN_NAME)
        .arg("create-config")
        .arg("--path")
        .arg(CONFIG_PATH)
        .assert()
        .success();

    let max_db_commit_attempts = 1;
    let max_orphan_blocks = 2;
    let p2p_addr = "address";
    let p2p_ban_threshold = 3;
    let p2p_timeout = 10000;
    let rpc_addr = SocketAddr::from_str("127.0.0.1:5432").unwrap();

    let options = RunOptions {
        config_path: CONFIG_PATH.into(),
        net: ChainType::Mainnet,
        max_db_commit_attempts: Some(max_db_commit_attempts),
        max_orphan_blocks: Some(max_orphan_blocks),
        p2p_addr: Some(p2p_addr.into()),
        p2p_ban_threshold: Some(p2p_ban_threshold),
        p2p_outbound_connection_timeout: Some(p2p_timeout),
        rpc_addr: Some(rpc_addr),
    };
    let config = NodeConfig::read(&options).unwrap();

    assert_eq!(
        config.chainstate.max_db_commit_attempts,
        max_db_commit_attempts
    );
    assert_eq!(config.chainstate.max_orphan_blocks, max_orphan_blocks);

    assert_eq!(config.p2p.bind_address, p2p_addr);
    assert_eq!(config.p2p.ban_threshold, p2p_ban_threshold);
    assert_eq!(config.p2p.outbound_connection_timeout, p2p_timeout);

    assert_eq!(config.rpc.address, rpc_addr);
}
