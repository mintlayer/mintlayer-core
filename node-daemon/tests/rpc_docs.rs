// Copyright (c) 2024 RBB S.r.l
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

use expect_test::expect_file;

use rpc_description::RpcDocs;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[test]
fn user() {
    let interface = node_lib::rpc::interface_description();
    let docs = RpcDocs {
        title: "Mintlayer node",
        version: VERSION,
        description: "",
        interface: &interface,
    };
    expect_file!["../docs/RPC.md"].assert_eq(&docs.to_string());
}

#[test]
fn developer() {
    let interface = node_lib::rpc::dev_interface_description();
    let docs = RpcDocs {
        title: "Mintlayer node developer functions",
        version: VERSION,
        description: "These functions are used for testing and only enabled in regtest.",
        interface: &interface,
    };
    expect_file!["../docs/RPC_DEV.md"].assert_eq(&docs.to_string());
}
