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

/// Represents LMDB memory map size
#[derive(Eq, PartialEq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct MemSize(u64);

impl MemSize {
    pub const ZERO: Self = MemSize(0);

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
    pub fn as_bytes(self) -> u64 {
        self.0
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
