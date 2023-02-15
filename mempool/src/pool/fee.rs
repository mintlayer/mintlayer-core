use std::{
    iter::Sum,
    ops::{Add, Sub},
};

use common::primitives::Amount;
use utils::newtype;

newtype! {
    #[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
    pub struct Fee(Amount);
}

impl Add for Fee {
    type Output = Option<Self>;

    fn add(self, rhs: Self) -> Self::Output {
        (self.0 + rhs.0).map(Self)
    }
}

impl Sub for Fee {
    type Output = Option<Self>;

    fn sub(self, rhs: Self) -> Self::Output {
        (self.0 - rhs.0).map(Self)
    }
}

impl Sum<Fee> for Option<Fee> {
    fn sum<I>(mut iter: I) -> Self
    where
        I: Iterator<Item = Fee>,
    {
        iter.try_fold(Fee(Amount::ZERO), std::ops::Add::add)
    }
}
