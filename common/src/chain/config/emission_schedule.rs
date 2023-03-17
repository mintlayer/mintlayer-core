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

pub use crate::chain::mlt::Mlt;
use crate::primitives::BlockHeight;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

/// Internal emission schedule representation
pub type EmissionScheduleFn = dyn Fn(BlockHeight) -> Mlt + Sync + Send + 'static;

/// Emission schedule, characterized by function from block height to total supply at that point.
///
/// The function has to be a monotonic non-decreasing function.
#[derive(Clone)]
pub struct EmissionSchedule(std::sync::Arc<EmissionScheduleFn>);

impl EmissionSchedule {
    /// Construct an emission schedule from a function.
    ///
    /// Be careful to maintain invariants as specified in [EmissionSchedule] docs
    pub fn from_fn(f: impl 'static + Fn(BlockHeight) -> Mlt + Sync + Send) -> Self {
        Self(std::sync::Arc::new(f))
    }

    /// Construct an emission schedule from a function. See also [Self::from_fn]
    pub fn from_arc_fn(f: std::sync::Arc<EmissionScheduleFn>) -> Self {
        Self(f)
    }

    /// Get total MLT amount issued up to given block height.
    ///
    /// This includes all coins ever created up to given block height, including premine and any
    /// coins that have been burnt or made irrecoverable.
    pub fn amount_at(&self, ht: BlockHeight) -> Mlt {
        self.0(ht)
    }

    /// Get initial supply (premine)
    pub fn initial_supply(&self) -> Mlt {
        self.amount_at(BlockHeight::zero())
    }

    /// Get subsidy for block at given height
    pub fn subsidy(&self, ht: BlockHeight) -> Mlt {
        let prev_ht = ht.prev_height().expect("Genesis has no subsidy");
        (self.amount_at(ht) - self.amount_at(prev_ht)).expect("Supply not monotonic")
    }
}

impl std::fmt::Debug for EmissionSchedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EmissionSchedule(<function>)")
    }
}

/// Emission schedule where supply is a piecewise linear function, represented as a table.
///
/// The table has a string representation, described in [Self::from_str].
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct EmissionScheduleTabular {
    /// The initial supply, in MLTs
    initial_supply: Mlt,
    /// The initial per-block subsidy, before the first period kicks in.
    initial_subsidy: Mlt,
    /// Subsidy periods. Specified by block height and the block subsidy starting at that height.
    periods: BTreeMap<BlockHeight, Mlt>,
}

impl EmissionScheduleTabular {
    /// Create a new piecewise-linear supply schedule
    ///
    /// This constructor takes:
    ///  * The initial supply (premine amount)
    ///  * The initial per-block subsidy, before the first explicitly specified period (below).
    ///  * Subsidy periods. These are mappings from block heights to per-block subsidy from that
    ///    point onwards, until the next period. The periods are implicitly sorted by BTreeMap.
    pub fn new(
        initial_supply: Mlt,
        initial_subsidy: Mlt,
        periods: BTreeMap<BlockHeight, Mlt>,
    ) -> Self {
        Self {
            initial_supply,
            initial_subsidy,
            periods,
        }
    }

    /// All subsidy periods, starting at block height 0
    pub fn subsidy_periods(&self) -> impl Iterator<Item = (BlockHeight, Mlt)> + '_ {
        std::iter::once((BlockHeight::zero(), self.initial_subsidy))
            .chain(self.periods.iter().map(|(ht, mlt)| (*ht, *mlt)))
    }

    /// Get the initial supply
    pub fn initial_supply(&self) -> Mlt {
        self.initial_supply
    }

    /// Get tail emission block height and per-block amount
    pub fn tail_emission(&self) -> (BlockHeight, Mlt) {
        let empty_tail = || (BlockHeight::zero(), self.initial_subsidy);
        self.periods.iter().next_back().map_or_else(empty_tail, |(ht, mlt)| (*ht, *mlt))
    }

    /// Final supply. `None` if the supply increases indefinitely
    pub fn final_supply(&self) -> Option<Mlt> {
        let (tail_block, tail_subsidy) = self.tail_emission();
        (tail_subsidy == Mlt::ZERO).then(|| self.schedule().amount_at(tail_block))
    }

    /// Get the final emission schedule
    pub fn schedule(&self) -> EmissionSchedule {
        let table_seed = (
            self.initial_supply,
            self.initial_subsidy,
            BlockHeight::zero(),
        );

        // Pre-calculate a table with starting supply and per-block rewards for each reward period.
        let table: BTreeMap<BlockHeight, (Mlt, Mlt)> = self
            .periods
            .iter()
            .scan(
                table_seed,
                |(supply, old_subsidy, start_block), (end_block, new_subsidy)| {
                    let n_blocks = u64::from(*end_block) - u64::from(*start_block);
                    let cur_period = (*old_subsidy * n_blocks as u128).expect("Subsidy overflow");
                    *supply = (*supply + cur_period).expect("Subsidy overflow");
                    *old_subsidy = *new_subsidy;
                    *start_block = *end_block;
                    Some((*end_block, (*supply, *new_subsidy)))
                },
            )
            .collect();

        // Take copies of values to be moved into the closure.
        let initial_entry = (self.initial_supply, self.initial_subsidy);

        EmissionSchedule::from_fn(move |height: BlockHeight| {
            let initial = (&BlockHeight::zero(), &initial_entry);
            let (start, (start_supply, subsidy)) =
                table.range(BlockHeight::zero()..height).next_back().unwrap_or(initial);
            assert!(
                start <= &height,
                "Block heights incorrect, start={start}, ht={height}"
            );
            let n_blocks = u64::from(height) - u64::from(*start);
            let period_subsidy = (*subsidy * n_blocks as u128).expect("Subsidy overflow");
            (*start_supply + period_subsidy).expect("Subsidy overflow")
        })
    }
}

impl std::fmt::Display for EmissionScheduleTabular {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}+{}", self.initial_supply, self.initial_subsidy)?;
        for (ht, mlt) in &self.periods {
            write!(f, ",{ht}:+{mlt}")?;
        }
        Ok(())
    }
}

#[derive(Eq, PartialEq, Debug, thiserror::Error)]
pub enum ParseEmissionTableError {
    #[error("Emission table cannot be an empty string")]
    Empty,
    #[error("Initial supply amount malformed: {0}")]
    InitialSupply(<Mlt as FromStr>::Err),
    #[error("Subsidy for period {0} not specified")]
    NoSubsidy(usize),
    #[error("Block subsidy for period {0} malformed: {1}")]
    Subsidy(usize, <Mlt as FromStr>::Err),
    #[error("Block height for period {0} malformed: {1}")]
    BlockHeight(usize, <BlockHeight as FromStr>::Err),
}

impl FromStr for EmissionScheduleTabular {
    type Err = ParseEmissionTableError;

    /// Load a piecewise linear supply schedule from a string
    ///
    /// The string format is as follows:
    ///
    /// * The initial supply a MLT amount
    /// * Followed by the "`+`" sign
    /// * Followed by the initial block subsidy in MLT
    /// * Optionally a comma followed by comma-separated subsidy period entries, consisting of:
    ///   * The block height at which the period starts
    ///   * Followed by "`:+`"
    ///   * Followed by the per-block MLT subsidy in this period
    ///
    /// All MLT amounts are allowed to contain fractions, up to the precision of 1 atom.
    ///
    /// ## Examples
    ///
    /// Start with 100 MLTs, no additional emission:
    /// ```
    /// # use common::chain::config::emission_schedule::*;
    /// let es: EmissionScheduleTabular = "100+0".parse().unwrap();
    /// assert_eq!(es.final_supply(), Some(Mlt::from_mlt(100)));
    /// ```
    ///
    /// Start with 1000 MLTs, add 0.1 MLT each block forever:
    /// ```
    /// # use common::chain::config::emission_schedule::*;
    /// let es: EmissionScheduleTabular = "1000+0.1".parse().unwrap();
    /// assert_eq!(es.final_supply(), None);
    /// ```
    ///
    /// Start with 1000 MLTs, add 1 MLT each block up to block 500, no subsidy afterwards:
    /// ```
    /// # use common::chain::config::emission_schedule::*;
    /// let es: EmissionScheduleTabular = "1000+1,500:+0".parse().unwrap();
    /// ```
    ///
    /// A more complicated schedule with multiple subsidy periods:
    /// ```
    /// # use common::chain::config::emission_schedule::*;
    /// let es: EmissionScheduleTabular =
    ///     "1000+1,10000:+0.5,20000:+0.25,30000:+0.125,40000:+0".parse().unwrap();
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(',');

        let (initial_supply, initial_subsidy) = parts
            .next()
            .ok_or(Self::Err::Empty)?
            .trim()
            .split_once('+')
            .ok_or(Self::Err::NoSubsidy(0))?;
        let initial_supply = initial_supply.trim().parse().map_err(Self::Err::InitialSupply)?;
        let initial_subsidy = initial_subsidy.parse().map_err(|e| Self::Err::Subsidy(0, e))?;

        let periods: Result<BTreeMap<BlockHeight, Mlt>, Self::Err> = parts
            .zip(1..)
            .map(|(s, n)| {
                let (ht, mlt) = s.trim().split_once(":+").ok_or(Self::Err::NoSubsidy(n))?;
                let ht: BlockHeight = ht.parse().map_err(|e| Self::Err::BlockHeight(n, e))?;
                let mlt: Mlt = mlt.parse().map_err(|e| Self::Err::Subsidy(n, e))?;
                Ok((ht, mlt))
            })
            .collect();

        Ok(Self {
            initial_supply,
            initial_subsidy,
            periods: periods?,
        })
    }
}

// Emission schedule for mainnet

pub const MAINNET_COIN_PREMINE: Mlt = Mlt::from_mlt(400_000_000);

pub fn mainnet_schedule_table(block_interval: Duration) -> EmissionScheduleTabular {
    // Check block interval is in whole seconds
    assert_eq!(
        (block_interval.as_nanos() % 1_000_000_000),
        0,
        "Block interval supported up to the resolution of 1 sec"
    );

    // Number of blocks emitted per year
    let blocks_per_year: u64 = (365 * 24 * 60 * 60) / block_interval.as_secs();
    let years = (1..).map(|x| BlockHeight::new(blocks_per_year * x));
    let initial_subsidy = Mlt::from_mlt(202);
    let subsequent_subsidies =
        [151, 113, 85, 64, 48, 36, 27, 20, 15, 0].iter().map(|x| Mlt::from_mlt(*x));
    let rewards = years.zip(subsequent_subsidies).collect();
    EmissionScheduleTabular::new(MAINNET_COIN_PREMINE, initial_subsidy, rewards)
}

#[cfg(test)]
mod tests {
    use crate::primitives::Amount;

    use super::*;
    use proptest::prelude::*;

    const MAINNET_TOTAL_SUPPLY: Mlt = Mlt::from_mlt(599_990_800);
    const BLOCKS_PER_YEAR: u64 = 262800;

    fn mainnet_default_table() -> EmissionScheduleTabular {
        mainnet_schedule_table(crate::chain::config::DEFAULT_TARGET_BLOCK_SPACING)
    }

    fn mainnet_default_schedule() -> EmissionSchedule {
        mainnet_default_table().schedule()
    }

    const MAINNET_TABLE_STRING: &str = concat!(
        "400000000+202,",
        "262800:+151,525600:+113,788400:+85,1051200:+64,1314000:+48,",
        "1576800:+36,1839600:+27,2102400:+20,2365200:+15,2628000:+0",
    );

    #[test]
    fn mainnet_schedule_display() {
        assert_eq!(
            &format!("{}", mainnet_default_table()),
            MAINNET_TABLE_STRING
        )
    }

    #[test]
    fn mainnet_schedule_from_str() {
        assert_eq!(
            EmissionScheduleTabular::from_str(MAINNET_TABLE_STRING),
            Ok(mainnet_default_table()),
        );
    }

    proptest! {
        #[test]
        fn table_parser_nocrash(input: String) {
            let _: Result<EmissionScheduleTabular, _> = input.parse();
        }

        #[test]
        fn table_parser_roundtrip(
            input in r"[0-9]{1,9} *\+[0-9]{1,4}( *, *[0-9]{1,6}:\+[0-9]{1,4}){0,20}"
        ) {
            let es = match EmissionScheduleTabular::from_str(&input) {
                Ok(es) => es,
                Err(e) => panic!("Invalid table string {input:?}: {e}"),
            };
            let formatted = format!("{es}");
            let reconstructed: EmissionScheduleTabular = formatted.parse().unwrap();
            assert_eq!(es, reconstructed);
            assert_eq!(formatted, format!("{reconstructed}"));
        }
    }

    #[test]
    fn mainnet_subsidy_schedule() {
        let config = crate::chain::config::create_mainnet();

        assert_eq!(config.coin_decimals(), Mlt::DECIMALS);

        // first year
        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(1)),
            Amount::from_fixedpoint_str("202", Mlt::DECIMALS).unwrap()
        );
        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(2)),
            Amount::from_fixedpoint_str("202", Mlt::DECIMALS).unwrap()
        );
        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(5)),
            Amount::from_fixedpoint_str("202", Mlt::DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(10000)),
            Amount::from_fixedpoint_str("202", Mlt::DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(BLOCKS_PER_YEAR)),
            Amount::from_fixedpoint_str("202", Mlt::DECIMALS).unwrap()
        );

        // second year
        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(BLOCKS_PER_YEAR + 1)),
            Amount::from_fixedpoint_str("151", Mlt::DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(BLOCKS_PER_YEAR + 2)),
            Amount::from_fixedpoint_str("151", Mlt::DECIMALS).unwrap()
        );

        assert_eq!(
            config
                .block_subsidy_at_height(&BlockHeight::new(BLOCKS_PER_YEAR + BLOCKS_PER_YEAR / 2)),
            Amount::from_fixedpoint_str("151", Mlt::DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(2 * BLOCKS_PER_YEAR)),
            Amount::from_fixedpoint_str("151", Mlt::DECIMALS).unwrap()
        );

        // third year
        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(2 * BLOCKS_PER_YEAR + 1)),
            Amount::from_fixedpoint_str("113", Mlt::DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(2 * BLOCKS_PER_YEAR + 2)),
            Amount::from_fixedpoint_str("113", Mlt::DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(
                2 * BLOCKS_PER_YEAR + BLOCKS_PER_YEAR / 2
            )),
            Amount::from_fixedpoint_str("113", Mlt::DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(3 * BLOCKS_PER_YEAR)),
            Amount::from_fixedpoint_str("113", Mlt::DECIMALS).unwrap()
        );

        // forth year
        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(3 * BLOCKS_PER_YEAR + 1)),
            Amount::from_fixedpoint_str("85", Mlt::DECIMALS).unwrap()
        );

        // towards the end
        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(10 * BLOCKS_PER_YEAR)),
            Amount::from_fixedpoint_str("15", Mlt::DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(10 * BLOCKS_PER_YEAR + 1)),
            Amount::from_fixedpoint_str("0", Mlt::DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(10 * BLOCKS_PER_YEAR + 2)),
            Amount::from_fixedpoint_str("0", Mlt::DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(11 * BLOCKS_PER_YEAR + 2)),
            Amount::from_fixedpoint_str("0", Mlt::DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(u64::MAX)),
            Amount::from_fixedpoint_str("0", Mlt::DECIMALS).unwrap()
        );
    }

    #[test]
    fn subsidy_calculation_nonnegative() {
        // Note: The es.subsidy() method contains an assertion that fires if the MLT amount < 0.
        let es = mainnet_default_schedule();

        // Check heights up to 2 million exhaustively
        for ht in (1u64..2_000_000).map(BlockHeight::from) {
            let _ = es.subsidy(ht);
        }

        // Check year transition heights + 5 block neighborhood
        let year_transition_block_heights = (1..20).flat_map(|year| {
            (0..=10).map(move |offset| BlockHeight::from(year * BLOCKS_PER_YEAR + offset - 5))
        });
        for ht in year_transition_block_heights {
            let _ = es.subsidy(ht);
        }
    }

    #[test]
    fn total_emission_0() {
        let schedule = EmissionScheduleTabular::new(Mlt::ZERO, Mlt::ZERO, BTreeMap::new());
        assert_eq!(schedule.final_supply(), Some(Mlt::ZERO));
    }

    #[test]
    fn total_emission_1() {
        let schedule = [
            (BlockHeight::new(1), Mlt::from_atoms(20)),
            (BlockHeight::new(11), Mlt::from_atoms(0)),
        ];
        let schedule =
            EmissionScheduleTabular::new(Mlt::ZERO, Mlt::ZERO, schedule.into_iter().collect());
        assert_eq!(schedule.final_supply(), Some(Mlt::from_atoms(200)));
    }

    #[test]
    fn total_emission_2() {
        let schedule = [
            (BlockHeight::new(1), Mlt::from_atoms(20)),
            (BlockHeight::new(11), Mlt::from_atoms(10)),
            (BlockHeight::new(51), Mlt::from_atoms(0)),
        ];
        let schedule =
            EmissionScheduleTabular::new(Mlt::ZERO, Mlt::ZERO, schedule.into_iter().collect());
        assert_eq!(schedule.final_supply(), Some(Mlt::from_atoms(200 + 400)));
    }

    #[test]
    fn total_emission_3() {
        let schedule = [
            (BlockHeight::new(1), Mlt::from_atoms(20)),
            (BlockHeight::new(11), Mlt::from_atoms(10)),
            (BlockHeight::new(51), Mlt::from_atoms(5)),
            (BlockHeight::new(101), Mlt::from_atoms(0)),
        ];
        let schedule =
            EmissionScheduleTabular::new(Mlt::ZERO, Mlt::ZERO, schedule.into_iter().collect());
        assert_eq!(
            schedule.final_supply(),
            Some(Mlt::from_atoms(200 + 400 + 250))
        );
    }

    #[test]
    fn total_emission_4() {
        let schedule = EmissionScheduleTabular::new(Mlt::ZERO, Mlt::from_atoms(1), BTreeMap::new());
        assert_eq!(schedule.final_supply(), None);
    }

    #[test]
    fn total_emission_5() {
        let schedule = [
            (BlockHeight::new(1), Mlt::from_atoms(20)),
            (BlockHeight::new(11), Mlt::from_atoms(10)),
            (BlockHeight::new(51), Mlt::from_atoms(5)),
            (BlockHeight::new(101), Mlt::from_atoms(1)),
        ];
        let schedule =
            EmissionScheduleTabular::new(Mlt::ZERO, Mlt::ZERO, schedule.into_iter().collect());
        assert_eq!(schedule.final_supply(), None);
    }

    #[test]
    fn initial_supply_mainnet() {
        assert_eq!(
            mainnet_default_schedule().initial_supply(),
            MAINNET_COIN_PREMINE
        );
    }

    #[test]
    fn total_supply_mainnet() {
        let es = mainnet_schedule_table(crate::chain::config::DEFAULT_TARGET_BLOCK_SPACING);
        assert_eq!(es.final_supply(), Some(MAINNET_TOTAL_SUPPLY));
    }
}
