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

use std::env;

#[tokio::main]
async fn main() -> Result<(), node_lib::Error> {
    let opts = node_lib::Options::from_args(env::args_os());
    node_lib::init_logging(&opts);
    let setup_result = node_lib::setup(opts).await?;
    let node = match setup_result {
        node_lib::NodeSetupResult::Node(node) => node,
        node_lib::NodeSetupResult::DataDirCleanedUp => {
            panic!(
                "Data directory is now clean. Please restart the node without `--clean-data` flag"
            );
        }
    };
    node.main().await;
    Ok(())
}
