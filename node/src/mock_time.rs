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

use std::time::Duration;

use common::chain::config::ChainType;

/// Sets mock time (seconds since UNIX epoch)
pub fn set_mock_time(chain_type: ChainType, time: u64) -> Result<(), crate::Error> {
    anyhow::ensure!(
        chain_type == ChainType::Regtest,
        "Mock time allowed on regtest chain only"
    );
    common::primitives::time::set(Duration::from_secs(time))?;
    Ok(())
}
