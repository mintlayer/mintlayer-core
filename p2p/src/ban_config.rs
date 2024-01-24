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

use std::time::Duration;

use utils::make_config_setting;

make_config_setting!(DiscouragementThreshold, u32, 100);
make_config_setting!(
    DiscouragementDuration,
    Duration,
    Duration::from_secs(60 * 60 * 24)
);

/// Settings related to banning in the general sense (i.e. to the handling of BanScore and
/// potentially to manual banning as well).
#[derive(Default, Debug, Clone)]
pub struct BanConfig {
    /// The ban score threshold after which a peer becomes discouraged.
    pub discouragement_threshold: DiscouragementThreshold,
    /// The duration of discouragement.
    pub discouragement_duration: DiscouragementDuration,
}
