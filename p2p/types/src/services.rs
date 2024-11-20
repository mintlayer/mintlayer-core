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

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[repr(u64)]
pub enum Service {
    Transactions = 1 << 0,
    Blocks = 1 << 1,
    PeerAddresses = 1 << 2,
}

impl Service {
    pub const ALL: [Service; 3] = [Service::Transactions, Service::Blocks, Service::PeerAddresses];
}

#[derive(Eq, PartialEq, Clone, Copy, Debug, Encode, Decode, serde::Serialize)]
pub struct Services(u64);

impl Services {
    pub fn from_u64(val: u64) -> Self {
        Self(val)
    }

    pub fn has_service(&self, flag: Service) -> bool {
        self.0 & flag as u64 != 0
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

impl From<&[Service]> for Services {
    fn from(services: &[Service]) -> Self {
        let result = services.iter().fold(0, |so_far, current| so_far | *current as u64);
        Services(result)
    }
}

impl std::ops::BitAnd for Services {
    type Output = Services;

    fn bitand(self, rhs: Self) -> Self::Output {
        Services(self.0 & rhs.0)
    }
}

impl std::ops::BitOr for Services {
    type Output = Services;

    fn bitor(self, rhs: Self) -> Self::Output {
        Services(self.0 | rhs.0)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn test_service_flags() {
        let all_flags = vec![Service::Transactions, Service::Blocks, Service::PeerAddresses];
        let services: Services = all_flags.as_slice().into();
        for flag in all_flags {
            assert!(services.has_service(flag));
        }
    }
}
