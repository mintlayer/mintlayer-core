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
pub fn combine_data_with_delta<T: Clone>(
    lhs: Option<&T>,
    rhs: Option<&DeltaMapElement<T>>,
) -> Result<Option<T>, Error> {
    match (lhs, rhs) {
        (None, None) => Ok(None),
        (None, Some(d)) => match d.get_data_delta() {
            DataDelta::Create(d) => Ok(Some(d.clone())),
            DataDelta::Modify(_, _) => Err(Error::ModifyNonexistingData),
            DataDelta::Delete(_) => Err(Error::RemoveNonexistingData),
        },
        (Some(p), None) => Ok(Some(p.clone())),
        (Some(_), Some(d)) => match d.get_data_delta() {
            DataDelta::Create(_) => Err(Error::DataCreatedMultipleTimes),
            DataDelta::Modify(_, d) => Ok(Some(d.clone())),
            DataDelta::Delete(_) => Ok(None),
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
    use crate::DataDeltaUndo;

    use super::*;
    use common::primitives::{amount::UnsignedIntType, signed_amount::SignedIntType};

    #[test]
    #[rustfmt::skip]
    fn test_combine_data_with_delta() {
        let delta_create = Some(DeltaMapElement::Delta(DataDelta::Create('b')));
        let delta_modify = Some(DeltaMapElement::Delta(DataDelta::Modify('a', 'b')));
        let delta_delete= Some(DeltaMapElement::Delta(DataDelta::Delete('b')));

        assert_eq!(combine_data_with_delta::<i32>(None, None),                  Ok(None));
        assert_eq!(combine_data_with_delta(None,        delta_create.as_ref()), Ok(Some('b')));
        assert_eq!(combine_data_with_delta(None,        delta_modify.as_ref()), Err(Error::ModifyNonexistingData));
        assert_eq!(combine_data_with_delta(None,        delta_delete.as_ref()), Err(Error::RemoveNonexistingData));
        assert_eq!(combine_data_with_delta(Some(&'a'),  None),                  Ok(Some('a')));
        assert_eq!(combine_data_with_delta(Some(&'a'),  delta_create.as_ref()), Err(Error::DataCreatedMultipleTimes));
        assert_eq!(combine_data_with_delta(Some(&'a'),  delta_modify.as_ref()), Ok(Some('b')));
        assert_eq!(combine_data_with_delta(Some(&'a'),  delta_delete.as_ref()), Ok(None));
    }

    #[test]
    #[rustfmt::skip]
    fn test_combine_data_with_undo() {
        let undo_delete = Some(DeltaMapElement::DeltaUndo(DataDeltaUndo(DataDelta::Create('b'))));
        let undo_modify = Some(DeltaMapElement::DeltaUndo(DataDeltaUndo(DataDelta::Modify('a', 'b'))));
        let undo_create= Some(DeltaMapElement::DeltaUndo(DataDeltaUndo(DataDelta::Delete('b'))));

        assert_eq!(combine_data_with_delta::<i32>(None, None),                 Ok(None));
        assert_eq!(combine_data_with_delta(None,        undo_delete.as_ref()), Ok(Some('b')));
        assert_eq!(combine_data_with_delta(None,        undo_modify.as_ref()), Err(Error::ModifyNonexistingData));
        assert_eq!(combine_data_with_delta(None,        undo_create.as_ref()), Err(Error::RemoveNonexistingData));
        assert_eq!(combine_data_with_delta(Some(&'a'),  None),                 Ok(Some('a')));
        assert_eq!(combine_data_with_delta(Some(&'a'),  undo_delete.as_ref()), Err(Error::DataCreatedMultipleTimes));
        assert_eq!(combine_data_with_delta(Some(&'a'),  undo_modify.as_ref()), Ok(Some('b')));
        assert_eq!(combine_data_with_delta(Some(&'a'),  undo_create.as_ref()), Ok(None));
    }

    #[test]
    #[rustfmt::skip]
    fn test_combine_amount_delta() {
        let amount = |v| Some(Amount::from_atoms(v));
        let s_amount = |v| Some(SignedAmount::from_atoms(v));

        assert_eq!(combine_amount_delta(&None,      &None),         Ok(None));
        assert_eq!(combine_amount_delta(&None,      &s_amount(1)),  Ok(amount(1)));
        assert_eq!(combine_amount_delta(&amount(1), &None),         Ok(amount(1)));
        assert_eq!(combine_amount_delta(&amount(1), &s_amount(1)),  Ok(amount(2)));

        assert_eq!(combine_amount_delta(&None,                                           &s_amount(-1)), Err(Error::ArithmeticErrorToUnsignedFailed));
        assert_eq!(combine_amount_delta(&amount(1),                                      &s_amount(-2)), Err(Error::ArithmeticErrorSumToUnsignedFailed));
        assert_eq!(combine_amount_delta(&amount(UnsignedIntType::MAX),                   &s_amount(1)),  Err(Error::ArithmeticErrorToSignedFailed));
        assert_eq!(combine_amount_delta(&amount(SignedIntType::MAX.try_into().unwrap()), &s_amount(1)),  Err(Error::ArithmeticErrorDeltaAdditionFailed));
    }
}
