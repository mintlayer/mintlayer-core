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
    primitives::{BlockCount, BlockDistance, BlockHeight},
};
use thiserror::Error;
use utils::ensure;

use super::error::ConnectTransactionError;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum OutputMaturityError {
    #[error("Maturity setting type for the output {0:?} is invalid")]
    InvalidOutputMaturitySettingType(UtxoOutPoint),
    #[error("Maturity setting for the output {0:?} is too short: {1:?} < {2:?}")]
    InvalidOutputMaturityDistance(UtxoOutPoint, BlockCount, BlockCount),
}

pub fn check_timelock(
    source_block_height: &BlockHeight,
    source_block_time: &BlockTimestamp,
    timelock: &OutputTimeLock,
    spend_height: &BlockHeight,
    spending_time: &BlockTimestamp,
    outpoint: &UtxoOutPoint,
) -> Result<(), ConnectTransactionError> {
    let past_lock = match timelock {
        OutputTimeLock::UntilHeight(h) => spend_height >= h,
        OutputTimeLock::UntilTime(t) => spending_time >= t,
        OutputTimeLock::ForBlockCount(d) => {
            let d: i64 = (*d)
                .try_into()
                .map_err(|_| ConnectTransactionError::BlockHeightArithmeticError)?;
            let d = BlockDistance::from(d);
            *spend_height
                >= (*source_block_height + d)
                    .ok_or(ConnectTransactionError::BlockHeightArithmeticError)?
        }
        OutputTimeLock::ForSeconds(dt) => {
            *spending_time
                >= source_block_time
                    .add_int_seconds(*dt)
                    .ok_or(ConnectTransactionError::BlockTimestampArithmeticError)?
        }
    };

    ensure!(
        past_lock,
        ConnectTransactionError::TimeLockViolation(outpoint.clone())
    );

    Ok(())
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
