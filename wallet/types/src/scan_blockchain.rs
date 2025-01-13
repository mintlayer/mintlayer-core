// Copyright (c) 2025 RBB S.r.l
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

#[derive(Debug, Clone, Copy)]
pub enum ScanBlockchain {
    /// Skips the scanning of the blockchain, used when creating a wallet from a brand new seed
    /// phrase never used before
    SkipScanning,
    /// Scans the blockchain and waits for the scanning to complete before returning
    ScanAndWait,
    /// Scans the blockchain in the background
    ScanNoWait,
}

impl ScanBlockchain {
    pub fn skip_scanning_the_blockchain(&self) -> bool {
        match self {
            Self::SkipScanning => true,
            Self::ScanNoWait | Self::ScanAndWait => false,
        }
    }

    pub fn should_wait_for_blockchain_scanning(&self) -> bool {
        match self {
            Self::ScanAndWait => true,
            Self::SkipScanning | Self::ScanNoWait => false,
        }
    }
}
