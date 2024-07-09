// Copyright (c) 2021-2022 RBB S.r.l
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

use common::primitives::{amount::SignedAmount, Amount};

use crate::{error::Error, DataDelta};

/// Combine data with an element of `DeltaDataCollection`.
/// An element can be either a Delta or a result of delta undo.
pub fn combine_data_with_delta<T: Clone + Eq>(
    lhs: Option<T>,
    rhs: Option<DataDelta<T>>,
) -> Result<Option<T>, Error> {
    match (lhs, rhs) {
        (lhs, None) => Ok(lhs),
        (None, Some(d)) => {
            let (prev, next) = d.consume();
            match (prev, next) {
                (None, next) => Ok(next),
                (Some(_), None) => Err(Error::RemoveNonexistingData),
                (Some(_), Some(_)) => Err(Error::ModifyNonexistingData),
            }
        }
        (Some(data), Some(d)) => {
            let (prev, next) = d.consume();
            match (prev, next) {
                (None, None) => Err(Error::DeltaDataMismatch),
                (None, Some(_)) => Err(Error::DataCreatedMultipleTimes),
                (Some(old), new) => {
                    utils::ensure!(data == old, Error::DeltaDataMismatch);
                    Ok(new)
                }
            }
        }
    }
}

/// Apply a delta on top of a balance which is effectively combining unsigned amount with a signed.
/// Errors can happen when doing conversions; which can uncover inconsistency issues
pub fn combine_amount_delta(lhs: Amount, rhs: Option<SignedAmount>) -> Result<Amount, Error> {
    match (lhs, rhs) {
        (v, None) => Ok(v),
        (v1, Some(v2)) => {
            let v1 = v1.into_signed().ok_or(Error::ArithmeticErrorToSignedFailed)?;
            let sum = (v1 + v2).ok_or(Error::ArithmeticErrorDeltaAdditionFailed)?;
            let sum = sum.into_unsigned().ok_or(Error::ArithmeticErrorSumToUnsignedFailed)?;
            Ok(sum)
        }
    }
}

#[cfg(test)]
pub mod test {
    use crate::DataDelta;

    use super::*;
    use common::primitives::amount::{signed::SignedIntType, UnsignedIntType};

    use rstest::rstest;

    #[rstest]
    #[rustfmt::skip]
    #[case(None,      None,                                       Ok(None))]
    #[case(None,      Some(DataDelta::new(None, Some('a'))),      Ok(Some('a')))]
    #[case(None,      Some(DataDelta::new(Some('a'), None)),      Err(Error::RemoveNonexistingData))]
    #[case(None,      Some(DataDelta::new(Some('a'), Some('b'))), Err(Error::ModifyNonexistingData))]
    #[case(Some('a'), None,                                       Ok(Some('a')))]
    #[case(Some('a'), Some(DataDelta::new(None, None)),           Err(Error::DeltaDataMismatch))]
    #[case(Some('a'), Some(DataDelta::new(None, Some('a'))),      Err(Error::DataCreatedMultipleTimes))]
    #[case(Some('a'), Some(DataDelta::new(Some('a'), Some('a'))), Ok(Some('a')))]
    #[case(Some('a'), Some(DataDelta::new(Some('a'), Some('b'))), Ok(Some('b')))]
    #[case(Some('a'), Some(DataDelta::new(Some('b'), Some('c'))), Err(Error::DeltaDataMismatch))]
    #[case(Some('a'), Some(DataDelta::new(Some('a'), None)),      Ok(None))]
    #[case(Some('a'), Some(DataDelta::new(Some('b'), None)),      Err(Error::DeltaDataMismatch))]
    fn test_combine_data_with_delta(
        #[case] data: Option<char>,
        #[case] delta: Option<DataDelta<char>>,
        #[case] expected_result: Result<Option<char>, Error>,
    ) {
        assert_eq!(
            combine_data_with_delta(data, delta),
            expected_result
        );
    }

    #[rstest]
    #[rustfmt::skip]
    #[case(0, None,     Ok(Amount::from_atoms(0)))]
    #[case(0, Some(1),  Ok(Amount::from_atoms(1)))]
    #[case(1, None,     Ok(Amount::from_atoms(1)))]
    #[case(1, Some(-1), Ok(Amount::from_atoms(0)))]
    #[case(2, Some(1),  Ok(Amount::from_atoms(3)))]
    #[case(3, Some(-1), Ok(Amount::from_atoms(2)))]
    #[case(0,                    Some(-1),                 Err(Error::ArithmeticErrorSumToUnsignedFailed))]
    #[case(1,                    Some(SignedIntType::MIN), Err(Error::ArithmeticErrorSumToUnsignedFailed))]
    #[case(1,                    Some(SignedIntType::MAX), Err(Error::ArithmeticErrorDeltaAdditionFailed))]
    #[case(UnsignedIntType::MIN, Some(-1),                 Err(Error::ArithmeticErrorSumToUnsignedFailed))]
    #[case(UnsignedIntType::MAX, Some(1),                  Err(Error::ArithmeticErrorToSignedFailed))]
    #[case(1,                    Some(SignedIntType::MAX), Err(Error::ArithmeticErrorDeltaAdditionFailed))]
    #[case(SignedIntType::MAX.try_into().unwrap(), Some(1), Err(Error::ArithmeticErrorDeltaAdditionFailed))]
    fn test_combine_amount_delta(
        #[case] balance: UnsignedIntType,
        #[case] delta: Option<SignedIntType>,
        #[case] expected_result: Result<Amount, Error>,
    ) {
        assert_eq!(
            combine_amount_delta(
                Amount::from_atoms(balance),
                delta.map(SignedAmount::from_atoms)
            ),
            expected_result
        );
    }
}
