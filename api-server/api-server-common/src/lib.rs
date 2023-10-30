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

pub mod storage;

use clap::Parser;
use common::chain::config::ChainType;

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
    Signet,
}

impl From<Network> for ChainType {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => ChainType::Mainnet,
            Network::Testnet => ChainType::Testnet,
            Network::Regtest => ChainType::Regtest,
            Network::Signet => ChainType::Signet,
        }
    }
}

#[derive(Parser, Debug)]
pub struct PostgresConfig {
    /// Postgres host
    #[clap(long, default_value = "localhost")]
    pub postgres_host: String,

    /// Postgres port
    #[clap(long, default_value = "5432")]
    pub postgres_port: u16,

    /// Postgres user
    #[clap(long, default_value = "postgres")]
    pub postgres_user: String,

    /// Postgres password
    #[clap(long)]
    pub postgres_password: Option<String>,

    /// Postgres database
    #[clap(long)]
    pub postgres_database: Option<String>,

    /// Postgres max connections
    #[clap(long, default_value = "10")]
    pub postgres_max_connections: u32,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self::parse()
    }
}
