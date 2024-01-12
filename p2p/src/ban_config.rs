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

make_config_setting!(BanThreshold, u32, 100);
// TODO: initially, the ban duration was 24h, but later it was changed to 30 min because automatic
// banning can be dangerous. E.g. it's possible for an attacker to force the node to use malicious
// Tor exit nodes by making it ban all honest ones. Using a smaller interval seemed less dangerous,
// so we chose 30 min. But even automatic disconnection of seemingly misbehaving peers may lead
// to network splitting; e.g. if in a future version some previously incorrect behavior becomes
// valid, the network may be split between old and new nodes, because the old ones would ban peers
// that exhibit such behavior. Also, 30 min doesn't make much sense for manual banning. So, we
// should probably get rid of automatic banning and return the old duration for the manual banning.
// But if we decide to keep the auto-ban functionality:
// a) the config names should be changed to AutoBanDuration, AutoBanThreshold;
// b) manual banning should have a separate ManualBanDuration; or event better, the ban duration
// should be specified by the user via RPC and the config should become ManualBanDefaultDuration.
// c) there should be the ability to turn auto-banning off, e.g. by setting the threshold to 0;
// by default, auto banning should be turned off.
make_config_setting!(BanDuration, Duration, Duration::from_secs(60 * 30));
make_config_setting!(DiscouragementThreshold, u32, 100);
make_config_setting!(
    DiscouragementDuration,
    Duration,
    Duration::from_secs(60 * 60 * 24)
);

/// Settings related to banning and discouragement.
#[derive(Default, Debug, Clone)]
pub struct BanConfig {
    /// The score threshold after which a peer is banned.
    pub ban_threshold: BanThreshold,
    /// The duration of a ban.
    pub ban_duration: BanDuration,
    /// The score threshold after which a peer becomes discouraged.
    pub discouragement_threshold: DiscouragementThreshold,
    /// The duration of discouragement.
    pub discouragement_duration: DiscouragementDuration,
}
