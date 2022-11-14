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

//! Support for memory map reallocation

use logging::log;
use utils::{sync, tap_error_log::LogError};

use crate::map_resize::resize_info::MapResizeInfo;

use self::memsize::MemSize;

pub mod memsize;
pub mod resize_info;

/// Token representing acquisition of the memory map resource
#[derive(Debug)]
pub struct MemMapController();

impl MemMapController {
    pub fn new() -> Self {
        Self()
    }
}

/// A proof of having acquired the memory map resource exclusively
pub type ExclusiveMemMapController<'a> = sync::RwLockWriteGuard<'a, MemMapController>;

/// Memory remapping procedure. Ensure at least `headroom` free space is available
pub fn remap(
    env: &lmdb::Environment,
    _map_token: ExclusiveMemMapController<'_>,
    headroom: MemSize,
) -> storage_core::Result<()> {
    let resize_info = MapResizeInfo::from_resize_headroom(env, headroom, true)?;

    if resize_info.should_resize_map() {
        // Remap with double of the required size
        let new_size = 2 * resize_info.required_size();
        log::info!(
            "Resizing LMDB memory map from {} to {}",
            resize_info.current_size(),
            new_size,
        );
        env.set_map_size(new_size.as_bytes())
            .or_else(crate::error::process_with_err)
            .log_err()?;
    }

    debug_assert!(
        MemSize::from_bytes(env.info().expect("Map size query").map_size() as u64)
            >= resize_info.required_size(),
        "Memory map still not big enough",
    );

    Ok(())
}
