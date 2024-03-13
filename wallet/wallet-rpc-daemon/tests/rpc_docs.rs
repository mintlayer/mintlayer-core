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

#[test]
fn docs() {
    let interface = wallet_rpc_lib::rpc_interface_description();
    let docs = rpc_description::RpcDocs {
        title: "Mintlayer node wallet",
        version: env!("CARGO_PKG_VERSION"),
        description: "",
        interface: &interface,
    };
    expect_test::expect_file!["../docs/RPC.md"].assert_eq(&docs.to_string());
}
