//! Node configuration options

use std::net::SocketAddr;
use std::path::PathBuf;

/// Mintlayer node binary
#[derive(clap::Parser, Debug)]
#[structopt(name = "mintlayer-node")]
pub struct Options {
    /// Where to write logs
    #[clap(long, name = "PATH")]
    pub log_path: Option<PathBuf>,

    /// Address to bind RPC to
    #[clap(long, name = "ADDR", default_value = "127.0.0.1:3030")]
    pub rpc_addr: SocketAddr,
}

impl Options {
    pub fn from_args() -> Self {
        clap::Parser::parse()
    }
}
