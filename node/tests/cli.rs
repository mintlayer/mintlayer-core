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

const BIN_NAME: &str = env!("CARGO_BIN_EXE_node");

// This test is only needed because the node name ix hardcoded here, so if the name is changed we
// get an error that is easy to understand.
#[test]
fn path_is_correct() {
    assert!(Path::new(BIN_NAME).is_file());
}

#[test]
fn no_args() {
    Command::new(BIN_NAME).assert().success();
    // TODO: Check predicates?..
    todo!();
    todo!();
}

#[test]
fn create_config() {
    Command::new(BIN_NAME).arg("--create-config").assert().success();
    // TODO: FIXME: Check the config after creation.
    todo!();
    todo!();
}

// TODO: Create config with args?
