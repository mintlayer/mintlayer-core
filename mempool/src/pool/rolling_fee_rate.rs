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

use common::primitives::Amount;
use logging::log;

use super::feerate::FeeRate;
use crate::config::Time;

#[derive(Clone, Copy, Debug)]
pub struct RollingFeeRate {
    block_since_last_rolling_fee_bump: bool,
    rolling_minimum_fee_rate: FeeRate,
    last_rolling_fee_update: Time,
}

impl RollingFeeRate {
    pub fn new(creation_time: Time) -> Self {
        Self {
            block_since_last_rolling_fee_bump: false,
            rolling_minimum_fee_rate: FeeRate::new(Amount::from_atoms(0)),
            last_rolling_fee_update: creation_time,
        }
    }

    #[allow(clippy::float_arithmetic)]
    pub fn decay_fee(mut self, halflife: Time, current_time: Time) -> Self {
        log::debug!(
            "decay_fee: old fee rate:  {:?}\nCurrent time: {:?}\nLast Rolling Fee Update: {:?}\nHalflife: {:?}",
            self.rolling_minimum_fee_rate,
            self.last_rolling_fee_update,
            current_time,
            halflife,
        );

        let divisor = ((current_time.as_secs() - self.last_rolling_fee_update.as_secs()) as f64
            / (halflife.as_secs() as f64))
            .exp2();
        self.rolling_minimum_fee_rate = FeeRate::new(Amount::from_atoms(
            (self.rolling_minimum_fee_rate.atoms_per_kb() as f64 / divisor) as u128,
        ));

        log::debug!(
            "decay_fee: new fee rate:  {:?}",
            self.rolling_minimum_fee_rate
        );
        self.last_rolling_fee_update = current_time;
        self
    }

    pub fn rolling_minimum_fee_rate(&self) -> FeeRate {
        self.rolling_minimum_fee_rate
    }

    pub fn set_rolling_minimum_fee_rate(&mut self, rolling_minimum_fee_rate: FeeRate) {
        self.rolling_minimum_fee_rate = rolling_minimum_fee_rate
    }

    pub fn set_block_since_last_rolling_fee_bump(
        &mut self,
        block_since_last_rolling_fee_bump: bool,
    ) {
        self.block_since_last_rolling_fee_bump = block_since_last_rolling_fee_bump
    }

    pub fn block_since_last_rolling_fee_bump(&self) -> bool {
        self.block_since_last_rolling_fee_bump
    }

    pub fn last_rolling_fee_update(&self) -> Time {
        self.last_rolling_fee_update
    }
}
