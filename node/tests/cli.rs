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

use std::path::Path;

use assert_cmd::Command;

use node::{NodeConfig, RunOptions};

const BIN_NAME: &str = env!("CARGO_BIN_EXE_node");

// This test is only needed because the node name ix hardcoded here, so if the name is changed we
// get an error that is easy to understand.
#[test]
fn path_is_correct() {
    assert!(Path::new(BIN_NAME).is_file());
}

#[test]
fn no_args() {
    Command::new(BIN_NAME).assert().failure();
}

#[test]
fn create_config() {
    let config_path = concat!(env!("CARGO_TARGET_TMPDIR"), "/test_mintlayer.toml");
    let max_block_header_size = 100;
    let max_block_size_from_txs = 200;
    let max_block_size_from_smart_contracts = 300;

    Command::new(BIN_NAME)
        .arg("create-config")
        .arg("--path")
        .arg(config_path)
        .assert()
        .success();
    // let run_options = RunOptions {
    //     config_path: config_path.into(),
    //     max_block_header_size: Some(max_block_header_size),
    //     max_block_size_from_txs: Some(max_block_size_from_txs),
    //     max_block_size_from_smart_contracts: Some(max_block_size_from_smart_contracts),
    //     p2p_addr: None,
    //     rpc_addr: None,
    // };
    // let config = NodeConfig::read(run_options).unwrap();
    todo!();
    todo!();
    // assert_eq!(
    //     config.chainstate.max_block_header_size,
    //     max_block_header_size
    // );
    // assert_eq!(
    //     config.chainstate.max_block_size_from_txs,
    //     max_block_size_from_txs
    // );
    // assert_eq!(
    //     config.chainstate.max_block_size_from_smart_contracts,
    //     max_block_size_from_smart_contracts
    // );
}
