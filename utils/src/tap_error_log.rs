// Copyright (c) 2022 RBB S.r.l
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

use std::{fmt::Display, panic::Location};

use logging::log;

use crate::workspace_path::relative_src_file_path;

pub trait LogError
where
    Self: Sized,
{
    fn log_err(self) -> Self;
    fn log_err_pfx(self, prefix: &str) -> Self;
    fn log_warn(self) -> Self;
    fn log_warn_pfx(self, prefix: &str) -> Self;
    fn log_err_with_level(self, log_level: log::Level) -> Self;
    fn log_err_with_level_pfx(self, log_level: log::Level, prefix: &str) -> Self;
}

fn log_error<E: Display>(err: &E, log_level: log::Level, location: &Location) {
    log::log!(
        // Note: the default target will be the module name, i.e. "utils::tap_error_log";
        // replace it with a shorter string that is still informative enough.
        target: "LogError",
        log_level,
        "{err} ({}:{}:{})",
        relative_src_file_path(location.file()),
        location.line(),
        location.column()
    );
}

fn log_error_pfx<E: Display>(err: &E, prefix: &str, log_level: log::Level, location: &Location) {
    log::log!(
        target: "LogError",
        log_level,
        "{prefix}: {err} ({}:{}:{})",
        relative_src_file_path(location.file()),
        location.line(),
        location.column()
    );
}

impl<T, E: Display> LogError for Result<T, E> {
    #[inline(always)]
    #[track_caller]
    fn log_err(self) -> Self {
        if let Err(ref err) = self {
            log_error(err, log::Level::Error, Location::caller());
        }
        self
    }

    #[inline(always)]
    #[track_caller]
    fn log_warn(self) -> Self {
        if let Err(ref err) = self {
            log_error(err, log::Level::Warn, Location::caller());
        }
        self
    }

    #[inline(always)]
    #[track_caller]
    fn log_err_with_level(self, log_level: log::Level) -> Self {
        if let Err(ref err) = self {
            log_error(err, log_level, Location::caller());
        }
        self
    }

    #[inline(always)]
    #[track_caller]
    fn log_err_pfx(self, prefix: &str) -> Self {
        if let Err(ref err) = self {
            log_error_pfx(err, prefix, log::Level::Error, Location::caller());
        }
        self
    }

    #[inline(always)]
    #[track_caller]
    fn log_warn_pfx(self, prefix: &str) -> Self {
        if let Err(ref err) = self {
            log_error_pfx(err, prefix, log::Level::Warn, Location::caller());
        }
        self
    }

    #[inline(always)]
    #[track_caller]
    fn log_err_with_level_pfx(self, log_level: log::Level, prefix: &str) -> Self {
        if let Err(ref err) = self {
            log_error_pfx(err, prefix, log_level, Location::caller());
        }
        self
    }
}
