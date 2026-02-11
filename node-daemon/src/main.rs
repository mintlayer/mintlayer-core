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
    let setup_result = node_lib::setup(opts.with_resolved_command()).await?;
    match setup_result {
        node_lib::NodeSetupResult::Node(node) => {
            node.main().await;
        }
        node_lib::NodeSetupResult::DataDirCleanedUp => {
            logging::log::info!(
                "Data directory is now clean. Please restart the node without the `--{}` flag",
                node_lib::CLEAN_DATA_OPTION_LONG_NAME
            );
        }
        node_lib::NodeSetupResult::BootstrapFileImported(bootstrap_result) => {
            match bootstrap_result {
                Ok(()) => {
                    logging::log::info!(
                        "Node was bootstrapped successfully. Please restart the node without the `--{}` flag",
                        node_lib::IMPORT_BOOTSTRAP_FILE_OPTION_LONG_NAME
                    );
                }
                Err(err) => {
                    logging::log::error!("Node bootstrapping failed: {err}");
                    std::process::exit(1)
                }
            }
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
