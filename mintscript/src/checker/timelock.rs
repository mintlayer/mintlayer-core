// Copyright (c) 2024 RBB S.r.l
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

pub trait TimelockChecker<C> {
    type Error: std::error::Error;

    /// Check timelock
    fn check_timelock(&mut self, ctx: &mut C, lock: &OutputTimeLock) -> Result<(), Self::Error>;
}

/// Blockchain state information needed to verify timelocks
pub trait TimelockContext {
    type Error: std::error::Error;

    /// Height at which the UTXO is being spent
    fn spending_height(&self) -> BlockHeight;

    /// Time at which the UTXO is being spent
    fn spending_time(&self) -> BlockTimestamp;

    /// Height at which the UTXO was confirmed
    fn source_height(&self) -> Result<BlockHeight, Self::Error>;

    /// Time at which the UTXO was confirmed
    fn source_time(&self) -> Result<BlockTimestamp, Self::Error>;
}

pub struct StandardTimelockChecker;

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum TimelockError<CE> {
    #[error(transparent)]
    Context(#[from] CE),

    #[error("Block height arithmetic error")]
    HeightArith,

    #[error("Timestamp arithmetic error")]
    TimestampArith,

    #[error("Spending at height {0}, locked until height {1}")]
    HeightLocked(BlockHeight, BlockHeight),

    #[error("Spending at timestamp {0}, locked until timestamp {1}")]
    TimestampLocked(BlockTimestamp, BlockTimestamp),
}

fn check_at_least<T: Ord, E>(cur: T, req: T, err_f: impl FnOnce(T, T) -> E) -> Result<(), E> {
    (cur >= req).then_some(()).ok_or_else(|| err_f(cur, req))
}

impl<C: TimelockContext> TimelockChecker<C> for StandardTimelockChecker {
    type Error = TimelockError<C::Error>;

    fn check_timelock(&mut self, ctx: &mut C, lock: &OutputTimeLock) -> Result<(), Self::Error> {
        use TimelockError as E;

        match lock {
            OutputTimeLock::UntilHeight(required) => {
                check_at_least(ctx.spending_height(), *required, E::HeightLocked)
            }
            OutputTimeLock::UntilTime(required) => {
                check_at_least(ctx.spending_time(), *required, E::TimestampLocked)
            }
            OutputTimeLock::ForBlockCount(d) => {
                let distance = BlockDistance::new((*d).try_into().map_err(|_| E::HeightArith)?);
                let required = (ctx.source_height()? + distance).ok_or(E::HeightArith)?;
                check_at_least(ctx.spending_height(), required, E::HeightLocked)
            }
            OutputTimeLock::ForSeconds(dt) => {
                let required = ctx.source_time()?.add_int_seconds(*dt).ok_or(E::TimestampArith)?;
                check_at_least(ctx.spending_time(), required, E::TimestampLocked)
            }
        }
    }
}

pub struct NoOpTimelockChecker;

impl<C> TimelockChecker<C> for NoOpTimelockChecker {
    type Error = std::convert::Infallible;

    fn check_timelock(&mut self, _ctx: &mut C, _lock: &OutputTimeLock) -> Result<(), Self::Error> {
        Ok(())
    }
}
