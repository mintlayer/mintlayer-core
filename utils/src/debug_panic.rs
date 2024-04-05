// Copyright (c) 2021-2024 RBB S.r.l
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

/// Panic in debug builds or log the message in release builds.
/// Note that unlike the standard `panic` macro this one requires at least one argument.
#[macro_export]
macro_rules! debug_panic_or_log {
    ($($arg:tt)+) => {
        if cfg!(debug_assertions) {
            panic!($($arg)*);
        } else {
            logging::log::error!("CRITICAL: debug build would panic: {}", format!($($arg)*));
        }
    }
}

/// If the passed condition is false, panic in debug builds or log the corresponding message in release builds.
/// Note that unlike the standard `assert` macro this one requires at least one extra argument.
#[macro_export]
macro_rules! debug_assert_or_log {
    ($cond:expr, $($arg:tt)+)=> {
        if !($cond) {
            $crate::debug_panic_or_log!("assertion failed: {}, {}", stringify!($cond), format!($($arg)*));
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(debug_assertions)]
    mod debug {
        #[test]
        #[should_panic(expected = "Test message")]
        fn test_panic() {
            debug_panic_or_log!("Test message");
        }

        #[test]
        #[should_panic(expected = "Test message")]
        fn test_assert_false() {
            debug_assert_or_log!(false, "Test message");
        }
    }

    #[cfg(not(debug_assertions))]
    mod release {
        #[should_panic(expected = "Some other message")]
        #[test]
        fn test_panic() {
            debug_panic_or_log!("Test message");
            panic!("Some other message");
        }

        #[should_panic(expected = "Some other message")]
        #[test]
        fn test_assert_false() {
            debug_assert_or_log!(false, "Test message");
            panic!("Some other message");
        }
    }

    #[should_panic(expected = "Some other message")]
    #[test]
    fn test_assert_true() {
        debug_assert_or_log!(true, "Test message");
        panic!("Some other message");
    }
}
