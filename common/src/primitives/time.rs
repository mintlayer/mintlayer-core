// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
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
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::SystemTime;

lazy_static! {
    static ref TIME_SOURCE: AtomicI64 = Default::default();
}

/// Either gets the current time or panics
pub fn get() -> i64 {
    let value = TIME_SOURCE.load(Ordering::SeqCst);
    if value == 0 {
        return SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as i64;
    }

    value
}

/// Return mocked time if set, otherwise return `None`
pub fn get_mocked() -> Option<i64> {
    let value = TIME_SOURCE.load(Ordering::SeqCst);
    if value == 0 {
        return None;
    }

    Some(value)
}

/// Reset time source to use `SystemTime::UNIX_EPOCH`
pub fn reset() {
    TIME_SOURCE.store(0i64, Ordering::SeqCst);
}

/// Set current time
pub fn set(now: i64) -> Result<(), &'static str> {
    if now <= 0 {
        return Err("Invalid time given");
    }

    TIME_SOURCE.store(now, Ordering::SeqCst);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time() {
        logging::init_logging::<&std::path::Path>(None);

        let handle = std::thread::spawn(move || {
            log::info!("p2p time: {}", get());
            std::thread::sleep(std::time::Duration::from_secs(1));

            log::info!("p2p time: {}", get());
            assert_eq!(get(), 1337);
            std::thread::sleep(std::time::Duration::from_secs(1));

            log::info!("p2p time: {}", get());
            assert_ne!(get(), 1337);
        });

        std::thread::spawn(move || {
            log::info!("rpc time: {}", get());
            std::thread::sleep(std::time::Duration::from_millis(500));

            set(1337);
            assert_eq!(get(), 1337);
            log::info!("rpc time: {}", get());
            std::thread::sleep(std::time::Duration::from_millis(500));

            reset();
            assert_ne!(get(), 1337);
            log::info!("rpc time: {}", get());
        });

        handle.join();
    }

    #[test]
    fn test_mocked() {
        assert_eq!(get_mocked(), None);

        assert_eq!(set(1337), Ok(()));
        assert_eq!(get(), 1337);
        assert_eq!(get_mocked(), Some(1337));

        reset();
        assert_eq!(get_mocked(), None);

        assert_eq!(set(0), Err("Invalid time given"));
        assert_eq!(set(-17), Err("Invalid time given"));
    }
}
