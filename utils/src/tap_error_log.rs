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

use std::fmt::Display;

pub trait LogError
where
    Self: Sized,
{
    fn log_err(self) -> Self;
    fn log_err_pfx(self, prefix: &str) -> Self;
    fn log_warn(self) -> Self;
    fn log_warn_pfx(self, prefix: &str) -> Self;
}

impl<T, E: Display> LogError for Result<T, E> {
    #[inline(always)]
    fn log_err(self) -> Self {
        if let Err(ref err) = self {
            logging::log::error!("{}", err);
        }
        self
    }

    #[inline(always)]
    fn log_warn(self) -> Self {
        if let Err(ref err) = self {
            logging::log::warn!("{}", err);
        }
        self
    }

    #[inline(always)]
    fn log_err_pfx(self, prefix: &str) -> Self {
        if let Err(ref err) = self {
            logging::log::error!("{}: {}", prefix, err);
        }
        self
    }

    #[inline(always)]
    fn log_warn_pfx(self, prefix: &str) -> Self {
        if let Err(ref err) = self {
            logging::log::warn!("{}: {}", prefix, err);
        }
        self
    }
}
