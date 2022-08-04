// Copyright (c) 2021 RBB S.r.l
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
//
// Author(s): A. Altonen
#![allow(unused, dead_code)]
use lazy_static::lazy_static;
use logging::log;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

fn duration_to_int(d: &Duration) -> Result<u64, Box<dyn std::error::Error>> {
    let r = d.as_millis().try_into()?;
    Ok(r)
}

fn duration_from_int(v: u64) -> Duration {
    Duration::from_millis(v)
}

lazy_static! {
    static ref TIME_SOURCE: AtomicU64 = Default::default();
}

/// Either gets the current time or panics
pub fn get() -> Duration {
    let value = TIME_SOURCE.load(Ordering::SeqCst);
    if value == 0 {
        return SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time went backwards");
    }

    duration_from_int(value)
}

/// Return mocked time if set, otherwise return `None`
pub fn get_mocked() -> Option<Duration> {
    let value = TIME_SOURCE.load(Ordering::SeqCst);
    if value == 0 {
        return None;
    }

    Some(duration_from_int(value))
}

/// Reset time source to use `SystemTime::UNIX_EPOCH`
pub fn reset() {
    TIME_SOURCE.store(0, Ordering::SeqCst);
}

/// Set current time as a Duration since SystemTime::UNIX_EPOCH
pub fn set(now: Duration) -> Result<(), Box<dyn std::error::Error>> {
    TIME_SOURCE.store(duration_to_int(&now)?, Ordering::SeqCst);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[serial_test::serial]
    fn test_time() {
        logging::init_logging::<&std::path::Path>(None);
        set(Duration::from_secs(1337));

        log::info!("p2p time: {}", get().as_secs());
        std::thread::sleep(Duration::from_secs(1));

        log::info!("p2p time: {}", get().as_secs());
        assert_eq!(get().as_secs(), 1337);
        std::thread::sleep(Duration::from_secs(1));

        log::info!("rpc time: {}", get().as_secs());
        std::thread::sleep(Duration::from_millis(500));

        assert_eq!(get().as_secs(), 1337);
        log::info!("rpc time: {}", get().as_secs());
        std::thread::sleep(Duration::from_millis(500));

        reset();
        assert_ne!(get().as_secs(), 1337);
        log::info!("rpc time: {}", get().as_secs());
    }

    #[test]
    #[serial_test::serial]
    fn test_mocked() {
        assert_eq!(get_mocked(), None);

        set(Duration::from_secs(1337)).unwrap();
        assert_eq!(get().as_secs(), 1337);
        assert_eq!(get_mocked(), Some(Duration::from_secs(1337)));

        reset();
        assert_eq!(get_mocked(), None);
    }

    #[test]
    fn test_conversion() {
        let val = 1234567;
        let d = duration_from_int(val);
        let val_again = duration_to_int(&d).unwrap();
        assert_eq!(val, val_again);
    }
}
