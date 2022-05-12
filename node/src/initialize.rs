//! Node initialisation routine.

use crate::options::Options;
use common::chain::config::ChainType;
use consensus::rpc::ConsensusRpcServer;
use std::sync::Arc;
use p2p::rpc::P2pRpcServer;

#[derive(Debug, Ord, PartialOrd, PartialEq, Eq, Clone, Copy, thiserror::Error)]
enum Error {
    #[error("Chain type '{0}' not yet supported")]
    UnsupportedChain(ChainType),
}

pub async fn initialize(opts: Options) -> anyhow::Result<subsystem::Manager> {
    // Initialize storage and chain configuration
    let storage = blockchain_storage::Store::new_empty()?;

    // Chain configuration
    let chain_config = match opts.net {
        ChainType::Mainnet => Arc::new(common::chain::config::create_mainnet()),
        chain_ty => return Err(Error::UnsupportedChain(chain_ty).into()),
    };

    // INITIALIZE SUBSYSTEMS

    let mut manager = subsystem::Manager::new("mintlayer");
    manager.install_signal_handlers();

    // Consensus subsystem
    let consensus = manager.add_subsystem(
        "consensus",
        consensus::make_consensus(chain_config, storage.clone())?,
    );

    // P2P subsystem
    let p2p = manager.add_subsystem(
        "p2p",
        p2p::make_p2p::<p2p::net::libp2p::Libp2pService>(
            Arc::clone(&chain_config),
            consensus.clone(),
            opts.p2p_addr,
        )
        .await
        .unwrap(),
    );

    // RPC subsystem
    let _rpc = manager.add_subsystem(
        "rpc",
        rpc::Builder::new(opts.rpc_addr)
            .register(consensus.into_rpc())
            .register(p2p.clone().into_rpc())
            .build()
            .await?,
    );

    Ok(manager)
}
