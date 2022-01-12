pub const TARGET_TIMESPAN_SECS: u32 = 14 * 24 * 60 * 60; // 2 weeks

pub const TARGET_SPACING: u32 = 10 * 60;
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u32 = TARGET_TIMESPAN_SECS / TARGET_SPACING;

/// taken from: https://github.com/bitcoin/bitcoin/blob/master/src/pow.cpp#L56
pub const TIMESPAN_ADJUSTMENT_FACTOR: u32 = 4;

pub const UPPER_TARGET_TIMESPAN_SECS: u32 = TARGET_TIMESPAN_SECS * TIMESPAN_ADJUSTMENT_FACTOR;
pub const LOWER_TARGET_TIMESPAN_SECS: u32 = TARGET_TIMESPAN_SECS / TIMESPAN_ADJUSTMENT_FACTOR;
