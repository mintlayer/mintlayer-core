//! Node initialisation routine.

use crate::options::Options;
use consensus::rpc::ConsensusRpcServer;

pub async fn initialize(opts: Options) -> anyhow::Result<subsystem::Manager> {
    // Initialize storage and chain configuration
    let storage = blockchain_storage::Store::new_empty()?;
    let chain_config = common::chain::config::create_mainnet();

    // INITIALIZE SUBSYSTEMS

    let mut manager = subsystem::Manager::new("mintlayer");
    manager.install_signal_handlers();

    // Consensus subsystem
    let consensus = manager.add_subsystem(
        "consensus",
        consensus::make_consensus(chain_config, storage.clone())?,
    );

    // RPC subsystem
    let _rpc = manager.add_subsystem(
        "rpc",
        rpc::Builder::new(opts.rpc_addr)
            .register(consensus.clone().into_rpc())
            .build()
            .await?,
    );

    Ok(manager)
}
