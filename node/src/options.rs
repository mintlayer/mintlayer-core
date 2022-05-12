//! Node configuration options

use std::net::SocketAddr;
use std::path::PathBuf;
use strum::VariantNames;

use common::chain::config::ChainType;

/// Mintlayer node executable
#[derive(clap::Parser, Debug)]
#[clap(author, version, about)]
pub struct Options {
    /// Where to write logs
    #[clap(long, value_name = "PATH")]
    pub log_path: Option<PathBuf>,

    /// Address to bind RPC to
    #[clap(long, value_name = "ADDR", default_value = "127.0.0.1:3030")]
    pub rpc_addr: SocketAddr,

    /// Blockchain type
    #[clap(long, value_name = "NET", possible_values = ChainType::VARIANTS)]
    pub net: ChainType,
}

impl Options {
    pub fn from_args() -> Self {
        clap::Parser::parse()
    }
}
