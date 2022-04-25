use common::chain::PoWChainConfig;
use common::Uint256;
use std::time::Duration;

mod helpers;
mod temp;
pub mod work;

#[derive(Debug)]
pub enum Error {
    ConversionError(String),
}

pub struct PoW(PoWChainConfig);

impl PoW {
    pub fn difficulty_limit(&self) -> Uint256 {
        self.0.limit()
    }

    pub fn no_retargeting(&self) -> bool {
        self.0.no_retargeting()
    }

    pub fn allow_min_difficulty_blocks(&self) -> bool {
        self.0.allow_min_difficulty_blocks()
    }

    pub fn target_spacing(&self) -> Duration {
        self.0.target_spacing()
    }

    pub fn max_retarget_factor(&self) -> u64 {
        self.0.max_retarget_factor()
    }

    pub fn target_timespan_in_secs(&self) -> u64 {
        self.0.target_timespan().as_secs()
    }

    /// Follows the upper bound of the target timespan (2 weeks * 4) of Bitcoin.
    /// See Bitcoin's Protocol rules on [Difficulty change](https://en.bitcoin.it/wiki/Protocol_rules)
    pub fn max_target_timespan_in_secs(&self) -> u64 {
        self.target_timespan_in_secs() * self.max_retarget_factor()
    }

    /// Follows the lower bound of the target timespan  (2 weeks / 4) of Bitcoin.
    /// See Bitcoin's Protocol rules on [Difficulty change](https://en.bitcoin.it/wiki/Protocol_rules)
    pub fn min_target_timespan_in_secs(&self) -> u64 {
        self.target_timespan_in_secs() / self.max_retarget_factor()
    }

    pub fn difficulty_adjustment_interval(&self) -> u64 {
        // or a total of 2016 blocks
        self.target_timespan_in_secs() / self.target_spacing().as_secs()
    }
}
