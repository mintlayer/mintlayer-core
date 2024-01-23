// Copyright (c) 2021-2023 RBB S.r.l
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

use utils::make_config_setting;

use super::salt::Salt;

// TODO: do we need the tables to be this big?
make_config_setting!(NewAddrTableBucketCount, usize, 1024);
make_config_setting!(TriedAddrTableBucketCount, usize, 256);
make_config_setting!(AddrTablesBucketSize, usize, 64);

#[derive(Default, Debug, Clone)]
pub struct PeerDbConfig {
    /// Bucket count for the "new" address table.
    pub new_addr_table_bucket_count: NewAddrTableBucketCount,
    /// Bucket count for the "tried" address table.
    pub tried_addr_table_bucket_count: TriedAddrTableBucketCount,
    /// Address table bucket size.
    pub addr_tables_bucket_size: AddrTablesBucketSize,
    /// The initial value for the peer db's salt.
    pub salt: Option<Salt>,
}
