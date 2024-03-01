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

use std::{fmt::Display, panic::Location};

use logging::log;

use crate::workspace_path::relative_src_file_path;

pub fn log<T: Display>(obj: &T, target: &str, log_level: log::Level, location: &Location) {
    log::log!(
        target: target,
        log_level,
        "{obj} ({}:{}:{})",
        relative_src_file_path(location.file()),
        location.line(),
        location.column()
    );
}

pub fn log_pfx<T: Display>(
    obj: &T,
    prefix: &str,
    target: &str,
    log_level: log::Level,
    location: &Location,
) {
    log::log!(
        target: target,
        log_level,
        "{prefix}: {obj} ({}:{}:{})",
        relative_src_file_path(location.file()),
        location.line(),
        location.column()
    );
}
