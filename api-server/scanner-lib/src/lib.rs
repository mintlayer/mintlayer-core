use std::sync::Arc;

use common::chain::ChainConfig;
use node_comm::rpc_client::NodeRpcClient;

pub mod sync;

pub async fn run(_chain_config: &Arc<ChainConfig>, _rpc_client: &NodeRpcClient) {}
