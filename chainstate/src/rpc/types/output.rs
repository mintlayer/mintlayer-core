use common::chain::{ChainConfig, TxOutput};

#[derive(Debug, Clone, serde::Serialize)]
pub struct RpcOutput {}

impl RpcOutput {
    pub fn new(chain_config: &ChainConfig, output: &TxOutput) -> Self {
        Self {}
    }
}
