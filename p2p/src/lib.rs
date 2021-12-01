// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
pub mod error;
pub mod net;
pub mod peer;

#[allow(unused)]
struct NetworkManager {}

#[allow(unused)]
impl NetworkManager {
    pub fn new() -> Self {
        Self {}
    }
}

#[allow(unused)]
struct P2P {
    mgr: NetworkManager,
}

#[allow(unused)]
impl P2P {
    pub fn new() -> Self {
        Self {
            mgr: NetworkManager::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let _p2p = P2P::new();
    }
}
