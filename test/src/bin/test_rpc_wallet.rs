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

use logging::log;
use wallet_rpc_lib::{cmdline, error::RunError};

async fn run() -> Result<(), RunError> {
    let (ws_config, rpc_config) =
        <cmdline::WalletRpcDaemonArgs as clap::Parser>::parse().into_config()?;

    wallet_rpc_lib::run(ws_config, rpc_config).await?;

    Ok(())
}

#[tokio::main]
async fn main() {
    utils::rust_backtrace::enable();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    logging::init_logging();

    let run_result = run().await;

    if let Err(err) = run_result {
        log::error!("{err}");
        std::process::exit(1);
    }
}
