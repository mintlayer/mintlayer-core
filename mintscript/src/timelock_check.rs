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

use common::{
    chain::{block::timestamp::BlockTimestamp, timelock::OutputTimeLock},
    primitives::{BlockDistance, BlockHeight},
};
use utils::ensure;

use crate::script::error::Error;

pub fn check_timelock(
    source_block_height: &BlockHeight,
    source_block_time: &BlockTimestamp,
    timelock: &OutputTimeLock,
    spend_height: &BlockHeight,
    spending_time: &BlockTimestamp,
) -> Result<(), Error> {
    let past_lock = match timelock {
        OutputTimeLock::UntilHeight(h) => spend_height >= h,
        OutputTimeLock::UntilTime(t) => spending_time >= t,
        OutputTimeLock::ForBlockCount(d) => {
            let dist: i64 = (*d).try_into().map_err(|_| Error::BlockDistanceInvalid(*d))?;
            let dist = BlockDistance::from(dist);
            *spend_height
                >= (*source_block_height + dist).ok_or(Error::BlockHeightArithmeticError(
                    source_block_height.into_int(),
                    *d,
                ))?
        }
        OutputTimeLock::ForSeconds(dt) => {
            *spending_time
                >= source_block_time.add_int_seconds(*dt).ok_or(
                    Error::BlockTimestampArithmeticError(source_block_time.as_int_seconds(), *dt),
                )?
        }
    };

    ensure!(past_lock, Error::TimelockNotSatisfied);

    Ok(())
}
