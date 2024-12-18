// Copyright (c) 2023 RBB S.r.l
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

pub async fn run() -> anyhow::Result<()> {
    let opts = node_lib::Options::from_args(std::env::args_os());
    logging::init_logging();
    logging::log::info!("Command line options: {opts:?}");
    let setup_result = node_lib::setup(opts).await?;
    match setup_result {
        node_lib::NodeSetupResult::Node(node) => {
            node.main().await;
        }
        node_lib::NodeSetupResult::DataDirCleanedUp => {
            logging::log::info!(
                "Data directory is now clean. Please restart the node without `--clean-data` flag"
            );
        }
    };

    Ok(())
}

#[tokio::main]
async fn main() {
    utils::rust_backtrace::enable();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    run().await.unwrap_or_else(|err| {
        eprintln!("Mintlayer node launch failed: {err:?}");
        std::process::exit(1)
    })
}
