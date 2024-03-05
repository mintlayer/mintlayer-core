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

use rpc_description::{Described, Interface};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(clap::Parser)]
pub enum CommandLine {
    /// Generate node docs
    Node {
        /// Include developer/testing functionality
        #[arg(long)]
        dev: bool,
    },

    /// Generate wallet docs
    Wallet,
}

struct RpcDocs {
    title: &'static str,
    modules: Vec<rpc_description::Module>,
}

fn main() {
    let args = <CommandLine as clap::Parser>::parse();

    let docs = match args {
        CommandLine::Node { dev } => {
            let title = "Mintlayer node";

            let mut modules = vec![
                node_lib::rpc::NodeRpcDescription::DESCRIPTION,
                chainstate::rpc::ChainstateRpcDescription::DESCRIPTION,
                mempool::rpc::MempoolRpcDescription::DESCRIPTION,
                p2p::rpc::P2pRpcDescription::DESCRIPTION,
                blockprod::rpc::BlockProductionRpcDescription::DESCRIPTION,
            ];

            if dev {
                modules.push(test_rpc_functions::rpc::RpcTestFunctionsRpcDescription::DESCRIPTION);
            }

            RpcDocs { title, modules }
        }

        CommandLine::Wallet => {
            let title = "Mintlayer node wallet";

            let modules = vec![wallet_rpc_lib::WalletRpcDescription::DESCRIPTION];

            RpcDocs { title, modules }
        }
    };

    let RpcDocs { title, modules } = docs;
    let interface = Interface::from_iter(modules);

    println!("# RPC documentation for {title}\n");
    println!("Version `{VERSION}`.\n");
    print!("{interface}");
}
