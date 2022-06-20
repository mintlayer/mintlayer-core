use super::DEFAULT_TARGET_BLOCK_SPACING;
use crate::primitives::{Amount, BlockHeight};
use std::time::Duration;

// TODO Move to a separate module
/// Represents a certain amount of MLT.
#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Debug)]
pub struct Mlt(Amount);

impl Mlt {
    /// Number of decimal digits used to represent MLT
    pub const DECIMALS: u8 = 11;
    /// Number of atoms in 1 MLT
    pub const ATOMS_PER_MLT: u128 = 10u128.pow(Self::DECIMALS as u32);
    /// Zero MLTs
    pub const ZERO: Self = Self(Amount::from_atoms(0));
    /// Maximum representable amount of MLTs
    pub const MAX: Self = Self(Amount::MAX);

    /// Construct from the number atomic units
    pub const fn from_atoms(n: u128) -> Self {
        Self(Amount::from_atoms(n))
    }

    /// Construct from the number of MLTs
    pub const fn from_mlt(n: u64) -> Self {
        // Since the argument is u64 and number of atoms in 1 MLT is <= u64::MAX,
        // the result is guaranteed to fit into the internal representation of Amount (u128)
        static_assertions::const_assert!(Mlt::ATOMS_PER_MLT <= u64::MAX as u128);
        Self(Amount::from_atoms(n as u128 * Mlt::ATOMS_PER_MLT))
    }

    /// Convert the number of atoms to Amount
    pub const fn to_amount_atoms(self) -> Amount {
        self.0
    }
}

impl std::ops::Add for Mlt {
    type Output = Option<Self>;
    fn add(self, rhs: Self) -> Option<Self> {
        (self.0 + rhs.0).map(Self)
    }
}

impl std::ops::Sub for Mlt {
    type Output = Option<Self>;
    fn sub(self, rhs: Self) -> Option<Self> {
        (self.0 - rhs.0).map(Self)
    }
}

impl std::ops::Mul<u128> for Mlt {
    type Output = Option<Self>;
    fn mul(self, rhs: u128) -> Option<Self> {
        (self.0 * rhs).map(Self)
    }
}

/// Internal emission schedule representation
pub type EmissionScheduleFn = dyn Fn(BlockHeight) -> Mlt + Sync + Send + 'static;

/// Emission schedule, characterized by function from block height to total supply at that point.
///
/// The function has to be a monotonic non-decreasing function. The function also has to
/// eventually flatten out to a constant function if [Self::final_supply] is required to make any
/// sense. The point at which the function becomes constant is where the block rewards run out.
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
    pub fn from_dyn_fn(f: Box<EmissionScheduleFn>) -> Self {
        Self(f.into())
    }

    /// Construct an emission schedule from yearly block award table
    ///
    /// This constructor takes:
    ///  * The initial supply (premine amount)
    ///  * Yearly per-block rewards, as a vector.
    ///    In years outside of the range of the vector, the reward is assumed to be zero.
    ///  * The target block interval. Only intervals in 1 second increments are valid.
    ///
    /// All calculations MLT amount are capped at [Mlt::MAX], which is [u128::MAX] atoms. The
    /// reward vector contains unsigned quantities and is finite in the number of years. Because of
    /// that, the resulting function is guaranteed to be monotonically increasing and to flatten out
    /// once the reward years pass.
    pub fn from_yearly_table(initial: Mlt, yearly: Vec<Mlt>, block_interval: Duration) -> Self {
        // Check block interval is in whole seconds
        assert!(
            (block_interval.as_nanos() % 1_000_000_000) == 0,
            "Block interval supported up to the resolution of 1 sec"
        );

        // Number of blocks emitted per year
        let blocks_per_year: u64 = (365 * 24 * 60 * 60) / block_interval.as_secs();
        // Total supply at start of each year in which rewards are emitted
        let mut yearly_cumulative = vec![initial];
        yearly_cumulative.extend(yearly.iter().scan(initial, |sum, &block_reward| {
            *sum = (block_reward * blocks_per_year as u128)
                .and_then(|year_reward| year_reward + *sum)
                .expect("MLT reward overflow");
            Some(*sum)
        }));
        // Total supply after the emission is finished
        let total = yearly_cumulative.last().copied().expect("Per-year supply empty");

        let supply_fn = move |ht: BlockHeight| {
            let ht: u64 = ht.into();
            let year = (ht / blocks_per_year) as usize;
            let blocks_this_year = (ht % blocks_per_year) as u128;
            let prev_years = yearly_cumulative.get(year).copied().unwrap_or(total);
            let per_block = yearly.get(year).copied().unwrap_or(Mlt::ZERO);
            (per_block * blocks_this_year)
                .and_then(|this_year| this_year + prev_years)
                .expect("MLT reward overflow")
        };

        Self::from_fn(supply_fn)
    }

    /// Get supply at given block height
    pub fn supply_at(&self, ht: BlockHeight) -> Mlt {
        self.0(ht)
    }

    /// Get initial supply (premine)
    pub fn initial_supply(&self) -> Mlt {
        self.supply_at(BlockHeight::zero())
    }

    /// Get final supply
    pub fn final_supply(&self) -> Mlt {
        self.supply_at(BlockHeight::max())
    }

    /// Total amount of MLT emitted as block rewards
    pub fn total_subsidy(&self) -> Mlt {
        (self.final_supply() - self.initial_supply()).expect("Supply not monotonic")
    }

    /// Get subsidy for block at given height
    pub fn subsidy(&self, ht: BlockHeight) -> Mlt {
        let prev_ht = ht.prev_height().expect("Genesis has no subsidy");
        (self.supply_at(ht) - self.supply_at(prev_ht)).expect("Supply not monotonic")
    }
}

impl std::fmt::Debug for EmissionSchedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EmissionSchedule(<function>)")
    }
}

// Emission schedule for mainnet

const MAINNET_COIN_PREMINE: Mlt = Mlt::from_mlt(400_000_000);

pub fn mainnet_schedule() -> EmissionSchedule {
    let yearly_block_rewards = [202, 151, 113, 85, 64, 48, 36, 27, 20, 15];
    let yearly_block_rewards = yearly_block_rewards.iter().copied().map(Mlt::from_mlt).collect();

    EmissionSchedule::from_yearly_table(
        MAINNET_COIN_PREMINE,
        yearly_block_rewards,
        DEFAULT_TARGET_BLOCK_SPACING,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const MAINNET_TOTAL_SUPPLY: Mlt = Mlt::from_mlt(599_990_800);
    const BLOCKS_PER_YEAR: u64 = 262800;

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
        let es = mainnet_schedule();

        // Check heights up to 2 million exhaustively
        for ht in (1u64..2_000_000).map(BlockHeight::from) {
            let _ = es.subsidy(ht);
        }

        // Check year transition heights + 5 block neighbourhood
        let year_transition_block_heights = (1..20).flat_map(|year| {
            (0..=10)
                .into_iter()
                .map(move |offset| BlockHeight::from(year * BLOCKS_PER_YEAR + offset - 5))
        });
        for ht in year_transition_block_heights {
            let _ = es.subsidy(ht);
        }
    }

    #[test]
    fn total_emission_0() {
        let schedule =
            EmissionSchedule::from_yearly_table(Mlt::ZERO, vec![], DEFAULT_TARGET_BLOCK_SPACING);
        assert_eq!(schedule.final_supply(), Mlt::ZERO);
    }

    #[test]
    fn initial_supply_mainnet() {
        assert_eq!(mainnet_schedule().initial_supply(), MAINNET_COIN_PREMINE);
    }

    #[test]
    fn total_supply_mainnet() {
        assert_eq!(mainnet_schedule().final_supply(), MAINNET_TOTAL_SUPPLY);
    }
}
