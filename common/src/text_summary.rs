use crate::chain::ChainConfig;

pub trait TextSummary {
    fn text_summary(&self, chain_config: &ChainConfig) -> String;
}
