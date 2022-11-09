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

/// Represents LMDB memory map size
#[derive(Eq, PartialEq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct MemSize(u64);

impl MemSize {
    /// Specify in the number of bytes
    pub const fn from_bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    /// Specify in the number of kilobytes
    pub const fn from_kilobytes(kilobytes: u64) -> Self {
        Self::from_bytes(1024 * kilobytes)
    }

    /// Specify in the number of megabytes
    pub const fn from_megabytes(megabytes: u64) -> Self {
        Self::from_kilobytes(1024 * megabytes)
    }

    /// Get raw byte count as u64
    pub fn as_bytes_u64(self) -> u64 {
        self.0
    }

    /// Get raw byte count in native representation
    pub fn as_bytes(self) -> usize {
        self.0.try_into().expect("Ran out of address space")
    }

    /// Division, rounding up
    pub fn div_ceil(self, rhs: Self) -> u64 {
        // TODO: Use u64::div_ceil once stable
        self.0 / rhs.0 + (self.0 % rhs.0 > 0) as u64
    }
}

impl std::fmt::Display for MemSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}B", self.0)
    }
}

impl std::ops::Add for MemSize {
    type Output = MemSize;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::Mul<MemSize> for u64 {
    type Output = MemSize;

    fn mul(self, rhs: MemSize) -> Self::Output {
        MemSize(self * rhs.0)
    }
}

/// Token representing acquisition of the memory map resource
#[derive(Debug)]
pub struct MemMapToken();

impl MemMapToken {
    pub fn new() -> Self {
        Self()
    }
}

/// A proof of having acquired the memory map resource exclusively
pub type ExclusiveMemMapToken<'a> = sync::RwLockWriteGuard<'a, MemMapToken>;

/// Memory remapping procedure. Ensure at least `headroom` free space is available
pub fn remap(
    env: &lmdb::Environment,
    _map_token: ExclusiveMemMapToken<'_>,
    headroom: MemSize,
) -> storage_core::Result<()> {
    // Get page size
    let page_size = {
        let stat = env.stat().or_else(crate::error::process_with_err)?;
        MemSize::from_bytes(stat.page_size() as u64)
    };

    // Get current occupancy info
    let info = env.info().or_else(crate::error::process_with_err)?;
    let current_size = MemSize::from_bytes(info.map_size() as u64);
    let current_pages = current_size.div_ceil(page_size);
    let used_pages = (info.last_pgno() + 1) as u64;
    let freelist_pages = env.freelist().or_else(crate::error::process_with_err)? as u64;
    let free_pages = (current_pages - used_pages) + freelist_pages;

    // Get map size requirements
    let required_free_pages = headroom.div_ceil(page_size);
    let required_pages = used_pages + required_free_pages;
    let required_size = required_pages * page_size;

    log::trace!(
        "LMDB memory: occupied = {} - {}, reserved = {}, free = {}, required = {}",
        used_pages * page_size,
        freelist_pages * page_size,
        current_size,
        free_pages * page_size,
        required_size,
    );

    // Ensure there is enough space
    if required_size > current_size {
        // Remap with double the size but or the required size, whichever is larger
        let new_size = std::cmp::max(2 * current_size, required_size);
        log::info!(
            "Resizing LMDB memory map from {} to {}",
            current_size,
            new_size,
        );
        env.set_map_size(new_size.as_bytes())
            .or_else(crate::error::process_with_err)
            .log_err()?;
    }

    Ok(())
}
