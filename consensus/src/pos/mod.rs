// Copyright (c) 2021 RBB S.r.l
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

use common::{chain::ChainConfig, primitives::BlockHeight};

pub fn is_due_for_epoch_data_calculation(chain_config: &ChainConfig, height: BlockHeight) -> bool {
    let height: u64 = height.into();
    let epoch_length: i64 = chain_config.epoch_length().into();
    let epoch_length: u64 =
        epoch_length.try_into().expect("Epoch length negative. Invariant broken.");
    height % epoch_length == 0
}
