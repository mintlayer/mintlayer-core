use crate::pow::temp::BlockIndex;
use crate::pow::Error;
use common::primitives::{BlockHeight, Compact};
use common::Uint256;

/// checks if retargeting is due for the provided block_height
pub fn due_for_retarget(difficulty_adjustment_interval: u64, block_height: BlockHeight) -> bool {
    let height: u64 = block_height.into();
    height % difficulty_adjustment_interval == 0
}

/// The block time of the first block, based on the difficulty adjustment interval,
/// where first block = height of given block - difficulty adjustment interval - 1 (off by one)
pub fn get_starting_block_time(
    difficulty_adjustment_interval: u64,
    block_index: &BlockIndex,
) -> u32 {
    let retarget_height = {
        let height: u64 = block_index.height.into();
        // Go back by what we want to be 14 days worth of blocks (the last 2015 blocks)
        let old_block_height = height - (difficulty_adjustment_interval - 1);
        BlockHeight::new(old_block_height)
    };

    let retarget_block_index = block_index.get_ancestor(retarget_height);

    retarget_block_index.get_block_time()
}

/// Returns a calculated new target as Compact datatype.
/// See Bitcoin's Protocol rules of [Difficulty change](https://en.bitcoin.it/wiki/Protocol_rules)
/// # Arguments
/// `actual_timespan_of_last_interval` - the actual timespan or the difference between the current block
/// and the 2016th block before it. This should be in seconds.
/// `target_timespan` - found in the `PoWChainConfig`. This should be in seconds.
/// `old_target` - Coming from the last block, this is the `bits` of the PoWData.
/// `difficulty_limit` - found in the PoWChainConfig, as `limit`
pub fn calculate_new_target(
    actual_timespan_of_last_interval: u64,
    target_timespan: u64,
    old_target: Compact,
    difficulty_limit: Uint256,
) -> Result<Compact, Error> {
    let actual_timespan = Uint256::from_u64(actual_timespan_of_last_interval).ok_or_else(|| {
        Error::ConversionError(format!(
            "conversion of actual timespan {:?} to Uint256 type failed.",
            actual_timespan_of_last_interval
        ))
    })?;

    let target_timespan = Uint256::from_u64(target_timespan).ok_or_else(|| {
        Error::ConversionError(format!(
            "conversion of target timespan {:?} to Uint256 type failed.",
            target_timespan
        ))
    })?;

    let old_target = Uint256::try_from(old_target).map_err(|e| {
        Error::ConversionError(format!(
            "conversion of bits {:?} to Uint256 type: {:?}",
            old_target, e
        ))
    })?;

    // new target is computed by  multiplying the old target by ratio of the actual timespan / target timespan.
    // see Bitcoin's Protocol rules of Difficulty change: https://en.bitcoin.it/wiki/Protocol_rules
    let mut new_target = old_target * actual_timespan;
    new_target = new_target / target_timespan;

    new_target = if new_target > difficulty_limit {
        difficulty_limit
    } else {
        new_target
    };

    Ok(Compact::from(new_target))
}

pub mod special_rules {
    use super::*;

    /// Checks if it took > 20 minutes to find a block
    pub fn block_production_stalled(
        target_spacing_in_secs: u64,
        new_block_time: u32,
        prev_block_time: u32,
    ) -> bool {
        new_block_time as u64 > (prev_block_time as u64 + (target_spacing_in_secs * 2))
    }

    pub fn last_non_special_min_difficulty(_block_index: &BlockIndex) -> Compact {
        // Return the last non-special-min-difficulty-rules-block
        // let mut ctr_index = block_index.clone();
        // loop {
        //     let block_bits = ctr_index.data.bits();
        //     if ctr_index.height == BlockHeight::zero() {
        //         return block_bits;
        //     }
        //
        //     if due_for_retarget(pow_cfg, ctr_index.height) && block_bits == pow_cfg.limit() {
        //         match ctr_index.prev() {
        //             None => { return block_bits; }
        //             Some(id) => {   }
        //         }
        //     }
        // }
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::pow::helpers::due_for_retarget;
    use common::primitives::BlockHeight;

    #[test]
    fn due_for_retarget_test() {
        let interval = 2016;
        let test = |h: BlockHeight| due_for_retarget(interval, h);

        assert!(test(BlockHeight::zero()));
        assert!(!test(BlockHeight::one()));
        assert!(test(BlockHeight::new(interval)));
        assert!(!test(BlockHeight::new(interval + 1)));
        assert!(test(BlockHeight::new(interval * 2)));
        assert!(test(BlockHeight::new(interval * 5)));
        assert!(test(BlockHeight::new(interval * 10)));
        assert!(!test(BlockHeight::new((interval * 10) + 1)));
        assert!(!test(BlockHeight::new((interval * 10) - 1)));
    }
}
