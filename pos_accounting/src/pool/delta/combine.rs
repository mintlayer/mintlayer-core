use common::primitives::{signed_amount::SignedAmount, Amount};

use crate::error::Error;

use super::delta_data_collection::DataDelta;

pub(super) fn combine_data_with_delta<T: Clone>(
    parent_data: Option<T>,
    local_data: Option<&DataDelta<T>>,
) -> Result<Option<T>, Error> {
    match (parent_data, local_data) {
        (None, None) => Ok(None),
        (None, Some(d)) => match d {
            DataDelta::Create(d) => Ok(Some(*d.clone())),
            DataDelta::Modify(_) => Err(Error::ModifyNonexistingData),
            DataDelta::Delete => Err(Error::RemoveNonexistingData),
        },
        (Some(p), None) => Ok(Some(p)),
        (Some(_), Some(d)) => match d {
            DataDelta::Create(_) => Err(Error::DataCreatedMultipleTimes),
            DataDelta::Modify(d) => Ok(Some(*d.clone())),
            DataDelta::Delete => Ok(None),
        },
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
