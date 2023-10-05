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

//! Top-level node runner as a library

mod config_files;
mod mock_time;
pub mod node_controller;
mod options;
pub mod rpc;
mod runner;

pub type Error = anyhow::Error;

pub use config_files::{
    NodeConfigFile, NodeTypeConfigFile, RpcConfigFile, StorageBackendConfigFile,
};
pub use options::{Command, Options, RunOptions};
pub use runner::setup;

pub fn default_rpc_config() -> RpcConfigFile {
    RpcConfigFile::with_run_options(RpcConfigFile::default(), &options::RunOptions::default())
}

pub fn init_logging(_opts: &Options) {
    logging::init_logging()
}
