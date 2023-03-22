// Copyright (c) 2023 RBB S.r.l
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

use serialization::{Decode, Encode};

#[derive(Eq, PartialEq, Clone, Copy, Debug, Encode, Decode, Default)]
pub struct Service(u32);

impl Service {
    /// Transactions
    pub const TRANSACTIONS: Service = Service(1 << 0);

    /// Blocks
    pub const BLOCKS: Service = Service(1 << 1);

    /// Peer address announcements from new nodes joining the network
    pub const PEER_ADDRESSES: Service = Service(1 << 2);
}

#[derive(Eq, PartialEq, Clone, Copy, Debug, Encode, Decode, Default)]
pub struct Services(u32);

impl Services {
    pub fn has_service(&self, service: Service) -> bool {
        self.0 & service.0 != 0
    }
}

impl From<&[Service]> for Services {
    fn from(services: &[Service]) -> Self {
        let mut result = 0;
        for service in services {
            result |= service.0
        }
        Services(result)
    }
}
