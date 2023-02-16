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

use crate::BlockProductionError;

pub trait BlockProductionInterface: Send {
    /// When called, the Block Builder will start creating blocks at the next tip in chainstate
    fn start(&self) -> Result<(), BlockProductionError>;

    /// When called, the Block Builder will cancel all current attempts to create blocks
    /// and won't attempt to do it again for new tips in chainstate or mempool
    /// Call start() to enable again
    fn stop(&self) -> Result<(), BlockProductionError>;

    /// Check if the Block Builder is currently connected
    fn is_connected(&self) -> bool;
}
