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

use common::primitives::{signed_amount::SignedAmount, Amount};

use crate::{
    delta::delta_data_collection::{DataDelta, DeltaMapElement},
    error::Error,
};

/// Combine data with an element of `DeltaDataCollection`.
/// An element can be either a Delta or a result of delta undo.
pub fn combine_data_with_delta<T: Clone + PartialEq>(
    lhs: Option<&T>,
    rhs: Option<&DeltaMapElement<T>>,
) -> Result<Option<T>, Error> {
    match (lhs, rhs) {
        (None, None) => Ok(None),
        (None, Some(d)) => match d.get_data_delta() {
            DataDelta::Mismatch => Err(Error::DeltaDataMismatch),
            DataDelta::Modify(prev, new) => match (prev, new) {
                (None, None) => Ok(None),
                (None, Some(d)) => Ok(Some(d.clone())),
                (Some(_), None) => Err(Error::DeltaDataMismatch),
                (Some(_), Some(_)) => Err(Error::DeltaDataMismatch),
            },
        },
        (Some(p), None) => Ok(Some(p.clone())),
        (Some(data), Some(delta)) => match delta.get_data_delta() {
            DataDelta::Mismatch => Err(Error::DeltaDataMismatch),
            DataDelta::Modify(prev, new) => match (prev, new) {
                (None, None) => Err(Error::DeltaDataMismatch),
                (None, Some(_)) => Err(Error::DeltaDataMismatch),
                (Some(old), None) => {
                    utils::ensure!(data == old, Error::DeltaDataMismatch);
                    Ok(None)
                }
                (Some(old), Some(new)) => {
                    utils::ensure!(data == old, Error::DeltaDataMismatch);
                    Ok(Some(new.clone()))
                }
            },
        },
    }
}

/// Add two numbers that can be Some or None, one unsigned and another signed
/// If both numbers are None, then the result is none (if key not found in both parent and local)
/// If only unsigned is present, then the unsigned is returned (only parent found)
/// If only signed is present, we convert it to unsigned and return it (only delta found)
/// If both found, we add them and return them as unsigned
/// Errors can happen when doing conversions; which can uncover inconsistency issues
pub fn combine_amount_delta(
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

#[cfg(test)]
pub mod test {
    use crate::{DataDelta::Modify, DataDeltaUndo};

    use super::*;
    use common::primitives::{amount::UnsignedIntType, signed_amount::SignedIntType};

    use rstest::rstest;

    #[rstest]
    #[rustfmt::skip]
    #[case(None,      None,                               Ok(None))]
    #[case(None,      Some(Modify(None, Some('a'))),      Ok(Some('a')))]
    #[case(None,      Some(Modify(Some('a'), None)),      Err(Error::DeltaDataMismatch))]
    #[case(None,      Some(Modify(Some('a'), Some('b'))), Err(Error::DeltaDataMismatch))]
    #[case(Some('a'), None,                               Ok(Some('a')))]
    #[case(Some('a'), Some(Modify(None, Some('a'))),      Err(Error::DeltaDataMismatch))]
    #[case(Some('a'), Some(Modify(Some('a'), Some('a'))), Ok(Some('a')))]
    #[case(Some('a'), Some(Modify(Some('a'), Some('b'))), Ok(Some('b')))]
    #[case(Some('a'), Some(Modify(Some('b'), Some('c'))), Err(Error::DeltaDataMismatch))]
    #[case(Some('a'), Some(Modify(Some('a'), None)),      Ok(None))]
    #[case(Some('a'), Some(Modify(Some('b'), None)),      Err(Error::DeltaDataMismatch))]
    fn test_combine_data_with_delta(
        #[case] data: Option<char>,
        #[case] delta: Option<DataDelta<char>>,
        #[case] expected_result: Result<Option<char>, Error>,
    ) {
        assert_eq!(
            combine_data_with_delta(
                data.as_ref(),
                delta.as_ref().map(|d| DeltaMapElement::Delta(d.clone())).as_ref()
            ),
            expected_result
        );

        assert_eq!(
            combine_data_with_delta(
                data.as_ref(),
                delta.map(|d| DeltaMapElement::DeltaUndo(DataDeltaUndo(d))).as_ref()
            ),
            expected_result
        );
    }

    #[rstest]
    #[rustfmt::skip]
    #[case(None,    None,     Ok(None))]
    #[case(None,    Some(1),  Ok(Some(Amount::from_atoms(1))))]
    #[case(Some(1), None,     Ok(Some(Amount::from_atoms(1))))]
    #[case(Some(2), Some(1),  Ok(Some(Amount::from_atoms(3))))]
    #[case(Some(3), Some(-1), Ok(Some(Amount::from_atoms(2))))]
    #[case(None,                       Some(-1),                 Err(Error::ArithmeticErrorToUnsignedFailed))]
    #[case(Some(1),                    Some(SignedIntType::MIN), Err(Error::ArithmeticErrorSumToUnsignedFailed))]
    #[case(Some(1),                    Some(SignedIntType::MAX), Err(Error::ArithmeticErrorDeltaAdditionFailed))]
    #[case(Some(UnsignedIntType::MIN), Some(-1),                 Err(Error::ArithmeticErrorSumToUnsignedFailed))]
    #[case(Some(UnsignedIntType::MAX), Some(1),                  Err(Error::ArithmeticErrorToSignedFailed))]
    #[case(Some(1),                    Some(SignedIntType::MAX), Err(Error::ArithmeticErrorDeltaAdditionFailed))]
    #[case(Some(SignedIntType::MAX.try_into().unwrap()), Some(1), Err(Error::ArithmeticErrorDeltaAdditionFailed))]
    fn test_combine_amount_delta(
        #[case] amount: Option<UnsignedIntType>,
        #[case] delta: Option<SignedIntType>,
        #[case] expected_result: Result<Option<Amount>, Error>,
    ) {
        assert_eq!(
            combine_amount_delta(
                &amount.map(Amount::from_atoms),
                &delta.map(SignedAmount::from_atoms)
            ),
            expected_result
        );
    }
}
