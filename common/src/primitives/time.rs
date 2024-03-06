// Copyright (c) 2021-2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    fmt::{Debug, Display},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime},
};

use chrono::TimeZone;
use serde::{Deserialize, Serialize};

use rpc_description::HasValueHint;

pub fn duration_to_int(d: &Duration) -> Result<u64, std::num::TryFromIntError> {
    let r = d.as_millis().try_into()?;
    Ok(r)
}

pub fn duration_from_int(v: u64) -> Duration {
    Duration::from_millis(v)
}

/// Will be used in functional tests
static TIME_SOURCE: AtomicU64 = AtomicU64::new(0);

/// Return mocked time if set, otherwise return `None`
fn get_mocked_time() -> Option<Time> {
    let value = TIME_SOURCE.load(Ordering::SeqCst);
    if value != 0 {
        Some(Time::from_duration_since_epoch(duration_from_int(value)))
    } else {
        None
    }
}

/// Reset time source to use `SystemTime::UNIX_EPOCH`
pub fn reset() {
    TIME_SOURCE.store(0, Ordering::SeqCst);
}

/// Set current time as a Duration since SystemTime::UNIX_EPOCH
pub fn set(now: Duration) -> Result<(), std::num::TryFromIntError> {
    TIME_SOURCE.store(duration_to_int(&now)?, Ordering::SeqCst);
    Ok(())
}

/// Either gets the current time or panics
pub fn get_time() -> Time {
    match get_mocked_time() {
        Some(mocked_time) => mocked_time,
        None => Time::from_duration_since_epoch(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Time went backwards"),
        ),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, HasValueHint)]
pub struct Time {
    /// Time, stored as duration since SystemTime::UNIX_EPOCH
    time: Duration,
}

impl Time {
    pub const fn as_duration_since_epoch(&self) -> Duration {
        self.time
    }

    pub const fn as_secs_since_epoch(&self) -> u64 {
        self.time.as_secs()
    }

    pub const fn from_duration_since_epoch(duration: Duration) -> Self {
        Self { time: duration }
    }

    pub const fn from_secs_since_epoch(seconds: u64) -> Self {
        Self {
            time: Duration::from_secs(seconds),
        }
    }

    pub const fn saturating_duration_add(&self, duration: Duration) -> Self {
        Self {
            time: self.time.saturating_add(duration),
        }
    }

    pub const fn saturating_duration_sub(&self, t: Duration) -> Self {
        Self {
            time: self.time.saturating_sub(t),
        }
    }

    pub const fn saturating_sub(&self, t: Self) -> Duration {
        self.time.saturating_sub(t.time)
    }

    pub fn as_absolute_time(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        TryInto::<i64>::try_into(self.time.as_secs()).ok().and_then(|secs| {
            // Note: chrono::DateTime supports time values up to about 262,000 years away
            // from the common era, which is still way below i64::MAX; i.e. timestamp_opt
            // may still return None here.
            chrono::Utc.timestamp_opt(secs, self.time.subsec_nanos()).single()
        })
    }
}

impl std::ops::Add<Duration> for Time {
    type Output = Option<Self>;

    fn add(self, other: Duration) -> Option<Self> {
        self.time.checked_add(other).map(|time| Self { time })
    }
}

impl std::ops::Sub<Duration> for Time {
    type Output = Option<Self>;

    fn sub(self, other: Duration) -> Option<Self> {
        self.time.checked_sub(other).map(|time| Self { time })
    }
}

impl std::ops::Sub<Time> for Time {
    type Output = Option<Duration>;

    fn sub(self, other: Time) -> Option<Duration> {
        self.time.checked_sub(other.as_duration_since_epoch())
    }
}

impl Debug for Time {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let utc_time = self.as_absolute_time();

        if let Some(time) = utc_time {
            write!(f, "{time:?}")
        } else {
            write!(f, "Time({:?})", self.time)
        }
    }
}

impl Display for Time {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let utc_time = self.as_absolute_time();

        if let Some(time) = utc_time {
            write!(f, "{time}")
        } else {
            // Note: we could use humantime::format_duration here, but the output won't be
            // very nice, e.g. for Duration::MAX it'll be:
            // "584542046090years 7months 15days 17h 5m 3s 999ms 999us 999ns"
            write!(f, "{:?} since Unix epoch", self.time)
        }
    }
}

#[cfg(test)]
mod tests {
    use logging::log;

    use super::*;

    #[test]
    #[serial_test::serial]
    fn test_time() {
        logging::init_logging();
        set(Duration::from_secs(1337)).unwrap();

        log::info!("p2p time: {}", get_time().as_secs_since_epoch());
        std::thread::sleep(Duration::from_secs(1));

        log::info!("p2p time: {}", get_time().as_secs_since_epoch());
        assert_eq!(get_time().as_secs_since_epoch(), 1337);
        std::thread::sleep(Duration::from_secs(1));

        log::info!("rpc time: {}", get_time().as_secs_since_epoch());
        std::thread::sleep(Duration::from_millis(500));

        assert_eq!(get_time().as_secs_since_epoch(), 1337);
        log::info!("rpc time: {}", get_time().as_secs_since_epoch());
        std::thread::sleep(Duration::from_millis(500));

        reset();
        assert_ne!(get_time().as_secs_since_epoch(), 1337);
        log::info!("rpc time: {}", get_time().as_secs_since_epoch());
    }

    #[test]
    #[serial_test::serial]
    fn test_mocked() {
        assert_eq!(get_mocked_time(), None);

        set(Duration::from_secs(1337)).unwrap();
        assert_eq!(get_time().as_secs_since_epoch(), 1337);
        assert_eq!(get_mocked_time(), Some(Time::from_secs_since_epoch(1337)));

        reset();
        assert_eq!(get_mocked_time(), None);
    }

    #[test]
    fn test_conversion() {
        let val = 1234567;
        let d = duration_from_int(val);
        let val_again = duration_to_int(&d).unwrap();
        assert_eq!(val, val_again);
    }

    #[test]
    fn debug_display() {
        let t = Time::from_secs_since_epoch(1705064092);
        let s = format!("{t:?}");
        assert_eq!(s, "2024-01-12T12:54:52Z");
        let s = format!("{t}");
        assert_eq!(s, "2024-01-12 12:54:52 UTC");

        let t = Time::from_duration_since_epoch(Duration::from_millis(1705064092123));
        let s = format!("{t:?}");
        assert_eq!(s, "2024-01-12T12:54:52.123Z");
        let s = format!("{t}");
        assert_eq!(s, "2024-01-12 12:54:52.123 UTC");

        let t = Time::from_duration_since_epoch(Duration::MAX);
        let s = format!("{t:?}");
        assert_eq!(s, "Time(18446744073709551615.999999999s)");
        let s = format!("{t}");
        assert_eq!(s, "18446744073709551615.999999999s since Unix epoch");
    }
}
