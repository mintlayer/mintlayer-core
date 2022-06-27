use parity_scale_codec::{Decode, Encode};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Encode, Decode, PartialOrd, Ord)]
pub struct BlockTimestamp {
    #[codec(compact)]
    timestamp: u32,
}

impl std::fmt::Display for BlockTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.timestamp.fmt(f)
    }
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum TimestampError {
    #[error("Duration cannot fit in a u32: {0:?}")]
    DurationTooLargeForU32(Duration),
}

impl BlockTimestamp {
    pub fn from_int_seconds(timestamp: u32) -> Self {
        Self { timestamp }
    }

    pub fn from_duration_since_epoch(duration: Duration) -> Result<Self, TimestampError> {
        let result = Self {
            timestamp: duration
                .as_secs()
                .try_into()
                .map_err(|_| TimestampError::DurationTooLargeForU32(duration))?,
        };
        Ok(result)
    }

    pub fn as_duration_since_epoch(&self) -> Duration {
        Duration::from_secs(self.timestamp as u64)
    }

    pub fn as_int_seconds(&self) -> u32 {
        self.timestamp
    }
}
