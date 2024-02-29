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

use rpc::description::{Described, Interface};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let include_dev = std::env::args().any(|a| a == "--dev");

    let main_interface = vec![
        node_lib::rpc::NodeRpcDescription::DESCRIPTION,
        chainstate::rpc::ChainstateRpcDescription::DESCRIPTION,
        mempool::rpc::MempoolRpcDescription::DESCRIPTION,
        p2p::rpc::P2pRpcDescription::DESCRIPTION,
        blockprod::rpc::BlockProductionRpcDescription::DESCRIPTION,
    ];

    let dev_interface =
        include_dev.then_some(test_rpc_functions::rpc::RpcTestFunctionsRpcDescription::DESCRIPTION);

    let interface = Interface::from_iter(main_interface.into_iter().chain(dev_interface));

    println!("# RPC documentation for Mintlayer node\n");
    println!("Version `{VERSION}`.\n");
    print!("{interface}");
}
