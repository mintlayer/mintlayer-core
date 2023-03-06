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

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use once_cell::sync::Lazy;

pub fn duration_to_int(d: &Duration) -> Result<u64, std::num::TryFromIntError> {
    let r = d.as_millis().try_into()?;
    Ok(r)
}

pub fn duration_from_int(v: u64) -> Duration {
    Duration::from_millis(v)
}

/// Will be used in functional tests
static TIME_SOURCE: AtomicU64 = AtomicU64::new(0);

/// Instant can only be constructed from the `Instant::now' call.
/// Store a lazily initialized constant that can be used later with the mocked time.
static BASE_MOCK_INSTANT: Lazy<Instant> = Lazy::new(Instant::now);

/// Return mocked time if set, otherwise return `None`
fn get_mocked_system_time() -> Option<Duration> {
    let value = TIME_SOURCE.load(Ordering::SeqCst);
    if value != 0 {
        Some(duration_from_int(value))
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
pub fn get_system_time() -> Duration {
    match get_mocked_system_time() {
        Some(mocked_time) => mocked_time,
        None => SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time went backwards"),
    }
}

/// Return instant (monotonic) time
pub fn get_instant_time() -> Instant {
    match get_mocked_system_time() {
        Some(mocked_time) => *BASE_MOCK_INSTANT + mocked_time,
        None => Instant::now(),
    }
}

#[cfg(test)]
mod tests {
    use logging::log;

    use super::*;

    #[test]
    #[serial_test::serial]
    fn test_time() {
        logging::init_logging::<&std::path::Path>(None);
        set(Duration::from_secs(1337)).unwrap();

        log::info!("p2p time: {}", get_system_time().as_secs());
        std::thread::sleep(Duration::from_secs(1));

        log::info!("p2p time: {}", get_system_time().as_secs());
        assert_eq!(get_system_time().as_secs(), 1337);
        std::thread::sleep(Duration::from_secs(1));

        log::info!("rpc time: {}", get_system_time().as_secs());
        std::thread::sleep(Duration::from_millis(500));

        assert_eq!(get_system_time().as_secs(), 1337);
        log::info!("rpc time: {}", get_system_time().as_secs());
        std::thread::sleep(Duration::from_millis(500));

        reset();
        assert_ne!(get_system_time().as_secs(), 1337);
        log::info!("rpc time: {}", get_system_time().as_secs());
    }

    #[test]
    #[serial_test::serial]
    fn test_mocked() {
        assert_eq!(get_mocked_system_time(), None);

        set(Duration::from_secs(1337)).unwrap();
        assert_eq!(get_system_time().as_secs(), 1337);
        assert_eq!(get_mocked_system_time(), Some(Duration::from_secs(1337)));

        let time = get_instant_time();
        set(Duration::from_secs(1338)).unwrap();
        assert_eq!(
            get_instant_time().duration_since(time),
            Duration::from_secs(1)
        );

        reset();
        assert_eq!(get_mocked_system_time(), None);
    }

    #[test]
    fn test_conversion() {
        let val = 1234567;
        let d = duration_from_int(val);
        let val_again = duration_to_int(&d).unwrap();
        assert_eq!(val, val_again);
    }
}
