// Copyright (c) 2021-2026 RBB S.r.l
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

use anyhow::Result;

use chainstate::{import_bootstrap_file, BootstrapError, ChainstateError};
use utils::{shallow_clone::ShallowClone as _, tokio_spawn};

use crate::{
    setup, NodeSetupResult, NodeType, Options, CLEAN_DATA_OPTION_LONG_NAME,
    IMPORT_BOOTSTRAP_FILE_OPTION_LONG_NAME,
};

pub struct ExitCode(pub i32);

pub async fn run_node_daemon() -> anyhow::Result<ExitCode> {
    let opts = Options::from_args(std::env::args_os(), NodeType::NodeDaemon);
    let setup_result = setup(opts.with_resolved_command()).await?;
    match setup_result {
        NodeSetupResult::RunNode(node) => {
            node.main().await;
        }
        NodeSetupResult::Bootstrap(node, bootstrap_file) => {
            let chainstate_handle = node.controller().chainstate.shallow_clone();
            let shutdown_trigger = node.controller().shutdown_trigger.clone();
            let node_main_join_handle = tokio_spawn(node.main(), "Node main");

            let bootstrap_result = chainstate_handle
                .call_mut(move |cs| import_bootstrap_file(cs, &bootstrap_file))
                .await;

            shutdown_trigger.initiate();
            node_main_join_handle.await?;

            match extract_bootstrap_error(bootstrap_result?)? {
                Ok(()) => {
                    logging::log::info!(
                        "Node was bootstrapped successfully. Please restart the node without the `--{}` flag",
                        IMPORT_BOOTSTRAP_FILE_OPTION_LONG_NAME
                    );
                }
                Err(err) => {
                    // Note: we don't return an error here, because bootstrapping will likely fail
                    // due to a user mistake rather than node malfunction, so we don't want for
                    // e.g. the stack trace to be printed in this case (anyhow::Error does this
                    // when backtrace is enabled).
                    logging::log::error!("Node bootstrapping failed: {err}");
                    return Ok(ExitCode(1));
                }
            }
        }
        NodeSetupResult::DataDirCleanedUp => {
            logging::log::info!(
                "Data directory is now clean. Please restart the node without the `--{}` flag",
                CLEAN_DATA_OPTION_LONG_NAME
            );
        }
    };

    Ok(ExitCode(0))
}

fn extract_bootstrap_error(
    bootstrap_result: Result<(), ChainstateError>,
) -> Result<Result<(), BootstrapError>, ChainstateError> {
    match bootstrap_result {
        Ok(()) => Ok(Ok(())),
        Err(err) => match err {
            ChainstateError::BootstrapError(err) => Ok(Err(err)),
            err @ (ChainstateError::StorageError(_)
            | ChainstateError::FailedToInitializeChainstate(_)
            | ChainstateError::ProcessBlockError(_)
            | ChainstateError::FailedToReadProperty(_)
            | ChainstateError::BlockInvalidatorError(_)
            | ChainstateError::IoError(_)) => Err(err),
        },
    }
}
