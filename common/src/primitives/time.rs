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

    /// Convert this `Time` instance to a `jiff::Timestamp`.
    ///
    /// This may fail if the time is too far into the future: `jiff::Timestamp`
    /// supports dates up to the end of year 9999.
    pub fn as_absolute_time(&self) -> Option<jiff::Timestamp> {
        TryInto::<i64>::try_into(self.time.as_secs())
            .ok()
            .and_then(|secs| jiff::Timestamp::new(secs, self.time.subsec_nanos() as i32).ok())
    }

    /// Create a new `Time` instance from a `jiff::Timestamp`.
    ///
    /// This will fail if the date-time is before the Unix epoch or if it doesn't represent
    /// a whole number of seconds.
    pub fn from_absolute_time(time: &jiff::Timestamp) -> Option<Self> {
        if time.subsec_nanosecond() != 0 {
            return None;
        }

        let seconds: u64 = time.as_second().try_into().ok()?;
        Some(Self::from_secs_since_epoch(seconds))
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
            // `jiff::Timestamp`'s Display renders RFC 3339 (e.g. "2024-01-12T12:54:52Z"),
            // which is what the Debug output looked like with `chrono`.
            write!(f, "{time}")
        } else {
            write!(f, "Time({:?})", self.time)
        }
    }
}

impl Display for Time {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let utc_time = self.as_absolute_time();

        if let Some(time) = utc_time {
            // Same format that `chrono`'s Display used to produce, e.g.
            // "2024-01-12 12:54:52 UTC" / "2024-01-12 12:54:52.123 UTC"; the subsecond
            // part uses chrono's grouping (3, 6 or 9 digits, no trailing-zero trimming).
            let subsec_nanos = time.subsec_nanosecond();
            let base =
                time.to_zoned_datetime(jiff::tz::TimeZone::UTC).strftime("%Y-%m-%d %H:%M:%S");
            if subsec_nanos == 0 {
                write!(f, "{base} UTC")
            } else if subsec_nanos % 1_000_000 == 0 {
                write!(f, "{base}.{:03} UTC", subsec_nanos / 1_000_000)
            } else if subsec_nanos % 1_000 == 0 {
                write!(f, "{base}.{:06} UTC", subsec_nanos / 1_000)
            } else {
                write!(f, "{base}.{:09} UTC", subsec_nanos)
            }
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
    use rstest::rstest;

    use logging::log;
    use randomness::RngExt as _;
    use test_utils::random::{Seed, make_seedable_rng};

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

        // Subsecond digits use chrono's 3/6/9 grouping (no trailing-zero trimming).
        let t = Time::from_duration_since_epoch(Duration::from_millis(1705064092100));
        assert_eq!(format!("{t}"), "2024-01-12 12:54:52.100 UTC");
        let t = Time::from_duration_since_epoch(Duration::from_micros(1705064092001100));
        assert_eq!(format!("{t}"), "2024-01-12 12:54:52.001100 UTC");
        let t = Time::from_duration_since_epoch(Duration::from_nanos(1705064092_000000001));
        assert_eq!(format!("{t}"), "2024-01-12 12:54:52.000000001 UTC");

        let t = Time::from_duration_since_epoch(Duration::MAX);
        let s = format!("{t:?}");
        assert_eq!(s, "Time(18446744073709551615.999999999s)");
        let s = format!("{t}");
        assert_eq!(s, "18446744073709551615.999999999s since Unix epoch");
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn from_to_absolute_time(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        for _ in 0..10 {
            let year = rng.random_range(1970..=3000);
            let month = rng.random_range(1..=12);
            let days_in_month =
                jiff::civil::date(year, month.try_into().unwrap(), 1).days_in_month();
            let day = rng.random_range(1..=days_in_month);
            let hour = rng.random_range(0..24);
            let min = rng.random_range(0..60);
            let sec = rng.random_range(0..60);
            let abs_time = jiff::tz::TimeZone::UTC
                .to_zoned_datetime(
                    jiff::civil::date(year, month.try_into().unwrap(), day.try_into().unwrap())
                        .at(hour, min, sec, 0),
                )
                .unwrap()
                .timestamp();

            let time = Time::from_absolute_time(&abs_time).unwrap();
            let abs_time_from_conversion = time.as_absolute_time().unwrap();
            assert_eq!(abs_time_from_conversion, abs_time);

            // Only a whole number of seconds should be allowed.
            let millis = rng.random_range(1..1000);
            let abs_time_with_millis =
                abs_time.checked_add(jiff::SignedDuration::from_millis(millis)).unwrap();
            assert!(Time::from_absolute_time(&abs_time_with_millis).is_none());
        }
    }
}
