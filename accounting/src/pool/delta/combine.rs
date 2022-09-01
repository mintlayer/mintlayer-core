use common::primitives::{signed_amount::SignedAmount, Amount};

use crate::error::Error;

use super::{DelegationDataDelta, PoolDataDelta};

pub(super) fn combine_delegation_data(
    lhs: &DelegationDataDelta,
    rhs: DelegationDataDelta,
) -> Result<Option<DelegationDataDelta>, Error> {
    match (lhs, rhs) {
        (DelegationDataDelta::Add(_), DelegationDataDelta::Add(_)) => {
            Err(Error::DelegationDataCreatedMultipleTimes)
        }
        (DelegationDataDelta::Add(_), DelegationDataDelta::Remove) => {
            // if lhs had a creation, and we remove, this means nothing is left and there's a net zero left
            Ok(None)
        }
        (DelegationDataDelta::Remove, DelegationDataDelta::Add(d)) => {
            Ok(Some(DelegationDataDelta::Add(d)))
        }
        (DelegationDataDelta::Remove, DelegationDataDelta::Remove) => {
            Err(Error::DelegationDataDeletedMultipleTimes)
        }
    }
}

pub(super) fn combine_pool_data(
    lhs: &PoolDataDelta,
    rhs: PoolDataDelta,
) -> Result<Option<PoolDataDelta>, Error> {
    match (lhs, rhs) {
        (PoolDataDelta::CreatePool(_), PoolDataDelta::CreatePool(_)) => {
            Err(Error::PoolCreatedMultipleTimes)
        }
        (PoolDataDelta::CreatePool(_), PoolDataDelta::DecommissionPool) => {
            // if lhs had a creation, and we decommission, this means nothing is left and there's a net zero left
            Ok(None)
        }
        (PoolDataDelta::DecommissionPool, PoolDataDelta::CreatePool(d)) => {
            Ok(Some(PoolDataDelta::CreatePool(d)))
        }
        (PoolDataDelta::DecommissionPool, PoolDataDelta::DecommissionPool) => {
            Err(Error::PoolDecommissionedMultipleTimes)
        }
    }
}

/// add two numbers that can be Some or None, one unsigned and another signed
/// If both numbers are None, then the result is none (if key not found in both parent and local)
/// If only unsigned is present, then the unsigned is returned (only parent found)
/// If only signed is present, we convert it to unsigned and return it (only delta found)
/// If both found, we add them and return them as unsigned
/// Errors can happen when doing conversions; which can uncover inconsistency issues
pub(super) fn combine_amount_delta(
    lhs: &Option<Amount>,
    rhs: &Option<SignedAmount>,
) -> Result<Option<Amount>, Error> {
    match (lhs, rhs) {
        (None, None) => Ok(None),
        (None, Some(v)) => Ok(Some(
            (*v).into_unsigned().ok_or(Error::ArithmeticErrorToUnsignedFailed)?,
        )),
        (Some(v), None) => Ok(Some(*v)),
        (Some(v1), Some(v2)) => {
            let v1 = v1.into_signed().ok_or(Error::ArithmeticErrorToSignedFailed)?;
            let sum = (v1 + *v2).ok_or(Error::ArithmeticErrorDeltaAdditionFailed)?;
            let sum = sum.into_unsigned().ok_or(Error::ArithmeticErrorSumToUnsignedFailed)?;
            Ok(Some(sum))
        }
    }
}

pub(super) fn combine_signed_amount_delta(
    lhs: &Option<SignedAmount>,
    rhs: &Option<SignedAmount>,
) -> Result<Option<SignedAmount>, Error> {
    match (lhs, rhs) {
        (None, None) => Ok(None),
        (None, Some(v)) => Ok(Some(*v)),
        (Some(v), None) => Ok(Some(*v)),
        (Some(v1), Some(v2)) => {
            let v1 = v1;
            let sum = (*v1 + *v2).ok_or(Error::ArithmeticErrorDeltaAdditionFailed)?;
            Ok(Some(sum))
        }
    }
}
