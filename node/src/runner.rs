//! Node initialisation routine.

use crate::options::Options;
use chainstate::rpc::ChainstateRpcServer;
use common::chain::config::ChainType;
use p2p::rpc::P2pRpcServer;
use std::sync::Arc;

#[derive(Debug, Ord, PartialOrd, PartialEq, Eq, Clone, Copy, thiserror::Error)]
enum Error {
    #[error("Chain type '{0}' not yet supported")]
    UnsupportedChain(ChainType),
}

/// Initialize the node, giving caller the opportunity to add more subsystems before start.
pub async fn initialize(opts: Options) -> anyhow::Result<subsystem::Manager> {
    // Initialize storage and chain configuration
    let storage = blockchain_storage::Store::new_empty()?;

    // Chain configuration
    let chain_config = match opts.net {
        ChainType::Mainnet => Arc::new(common::chain::config::create_mainnet()),
        ChainType::Regtest => Arc::new(common::chain::config::create_regtest()),
        chain_ty => return Err(Error::UnsupportedChain(chain_ty).into()),
    };

    // INITIALIZE SUBSYSTEMS

    let mut manager = subsystem::Manager::new("mintlayer");
    manager.install_signal_handlers();

    // Chainstate subsystem
    let chainstate = manager.add_subsystem(
        "chainstate",
        chainstate::make_chainstate(Arc::clone(&chain_config), storage.clone(), None)?,
    );

    // P2P subsystem
    let p2p = manager.add_subsystem(
        "p2p",
        p2p::make_p2p::<p2p::net::libp2p::Libp2pService>(
            Arc::clone(&chain_config),
            chainstate.clone(),
            opts.p2p_addr,
        )
        .await
        .expect("The p2p subsystem initialization failed"),
    );

    // RPC subsystem
    let _rpc = manager.add_subsystem(
        "rpc",
        rpc::Builder::new(opts.rpc_addr)
            .register(chainstate.clone().into_rpc())
            .register(NodeRpc::new(manager.make_shutdown_trigger()).into_rpc())
            .register(p2p.clone().into_rpc())
            .build()
            .await?,
    );

    Ok(manager)
}

/// Initialize and run the node
pub async fn run(opts: Options) -> anyhow::Result<()> {
    let manager = initialize(opts).await?;

    #[allow(clippy::unit_arg)]
    Ok(manager.main().await)
}

#[rpc::rpc(server, namespace = "node")]
trait NodeRpc {
    /// Order the node to shutdown
    #[method(name = "shutdown")]
    fn shutdown(&self) -> rpc::Result<()>;

    /// Get node software version
    #[method(name = "version")]
    fn version(&self) -> rpc::Result<String>;
}

struct NodeRpc {
    shutdown_trigger: subsystem::manager::ShutdownTrigger,
}

impl NodeRpc {
    fn new(shutdown_trigger: subsystem::manager::ShutdownTrigger) -> Self {
        Self { shutdown_trigger }
    }
}

impl NodeRpcServer for NodeRpc {
    fn shutdown(&self) -> rpc::Result<()> {
        self.shutdown_trigger.initiate();
        Ok(())
    }

    fn version(&self) -> rpc::Result<String> {
        Ok(env!("CARGO_PKG_VERSION").into())
    }
}
