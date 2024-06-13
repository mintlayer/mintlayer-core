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
    chain::{block::timestamp::BlockTimestamp, timelock::OutputTimeLock, UtxoOutPoint},
    primitives::{BlockCount, BlockHeight},
};
use mintscript::checker::TimelockChecker as _;
use thiserror::Error;
use utils::ensure;

pub type TimelockError = mintscript::checker::TimelockError<std::convert::Infallible>;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum OutputMaturityError {
    #[error("Maturity setting type for the output {0:?} is invalid")]
    InvalidOutputMaturitySettingType(UtxoOutPoint),
    #[error("Maturity setting for the output {0:?} is too short: {1:?} < {2:?}")]
    InvalidOutputMaturityDistance(UtxoOutPoint, BlockCount, BlockCount),
}

struct TimelockData {
    spending_height: BlockHeight,
    spending_time: BlockTimestamp,
    source_height: BlockHeight,
    source_time: BlockTimestamp,
}

impl mintscript::checker::TimelockContext for TimelockData {
    type Error = std::convert::Infallible;

    fn spending_height(&self) -> BlockHeight {
        self.spending_height
    }
    fn spending_time(&self) -> BlockTimestamp {
        self.spending_time
    }
    fn source_height(&self) -> Result<BlockHeight, Self::Error> {
        Ok(self.source_height)
    }
    fn source_time(&self) -> Result<BlockTimestamp, Self::Error> {
        Ok(self.source_time)
    }
}

pub fn check_timelock(
    source_block_height: &BlockHeight,
    source_block_time: &BlockTimestamp,
    timelock: &OutputTimeLock,
    spend_height: &BlockHeight,
    spending_time: &BlockTimestamp,
    _outpoint: &UtxoOutPoint,
) -> Result<(), TimelockError> {
    let mut data = TimelockData {
        spending_height: *spend_height,
        spending_time: *spending_time,
        source_height: *source_block_height,
        source_time: *source_block_time,
    };
    mintscript::checker::StandardTimelockChecker.check_timelock(&mut data, timelock)
}

pub fn check_output_maturity_setting(
    timelock: &OutputTimeLock,
    required: BlockCount,
    outpoint: UtxoOutPoint,
) -> Result<(), OutputMaturityError> {
    match timelock {
        OutputTimeLock::ForBlockCount(c) => {
            let given = BlockCount::new(*c);
            ensure!(
                given >= required,
                OutputMaturityError::InvalidOutputMaturityDistance(outpoint, given, required)
            );
            Ok(())
        }
        OutputTimeLock::UntilHeight(_)
        | OutputTimeLock::UntilTime(_)
        | OutputTimeLock::ForSeconds(_) => Err(
            OutputMaturityError::InvalidOutputMaturitySettingType(outpoint),
        ),
    }
}
