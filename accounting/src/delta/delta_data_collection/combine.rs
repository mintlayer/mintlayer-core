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

use super::*;

/// Given two deltas, combine them into one delta, this is the basic delta data composability function
pub fn combine_deltas<T: Clone + PartialEq>(
    lhs: &DataDelta<T>,
    rhs: DataDelta<T>,
) -> Result<Option<DataDelta<T>>, Error> {
    match (lhs, rhs) {
        (DataDelta::Create(_), DataDelta::Create(_)) => Err(Error::DeltaDataCreatedMultipleTimes),
        (DataDelta::Create(_), DataDelta::Modify(_, d)) => Ok(Some(DataDelta::Create(d))),
        (DataDelta::Create(_), DataDelta::Delete(_)) => {
            // if lhs had a creation, and we DataDeltaUndo::Delete, this means nothing is left and there's a net zero to return
            Ok(None)
        }
        (DataDelta::Modify(_, _), DataDelta::Create(_)) => {
            Err(Error::DeltaDataCreatedMultipleTimes)
        }
        (DataDelta::Modify(lhs1, lhs2), DataDelta::Modify(rhs1, rhs2)) => {
            if lhs1 == &rhs2 && lhs2 == &rhs1 {
                Ok(None)
            } else {
                Ok(Some(DataDelta::Modify(lhs1.clone(), rhs2)))
            }
        }
        (DataDelta::Modify(d, _), DataDelta::Delete(_)) => Ok(Some(DataDelta::Delete(d.clone()))),
        (DataDelta::Delete(lhs), DataDelta::Create(rhs)) => {
            if lhs == &rhs {
                Ok(None)
            } else {
                Ok(Some(DataDelta::Modify(lhs.clone(), rhs)))
            }
        }
        (DataDelta::Delete(_), DataDelta::Modify(_, _)) => Err(Error::DeltaDataModifyAfterDelete),
        (DataDelta::Delete(_), DataDelta::Delete(_)) => Err(Error::DeltaDataDeletedMultipleTimes),
    }
}

/// Given a delta and undo delta, combine them into one element.
/// If a combination gives No-op then None is returned.
pub fn combine_delta_with_undo<T: Clone + PartialEq>(
    lhs: &DataDelta<T>,
    rhs: DataDeltaUndo<T>,
) -> Result<Option<DataDelta<T>>, Error> {
    match (lhs, rhs) {
        (DataDelta::Create(_), DataDeltaUndo::Create(_)) => {
            Err(Error::DeltaDataCreatedMultipleTimes)
        }
        (DataDelta::Create(_), DataDeltaUndo::Modify(_, d)) => Ok(Some(DataDelta::Create(d))),
        (DataDelta::Create(_), DataDeltaUndo::Delete(_)) => Ok(None),

        (DataDelta::Modify(_, _), DataDeltaUndo::Create(d)) => Ok(Some(DataDelta::Create(d))),
        (DataDelta::Modify(lhs1, lhs2), DataDeltaUndo::Modify(rhs1, rhs2)) => {
            if lhs1 == &rhs2 && lhs2 == &rhs1 {
                Ok(None)
            } else {
                Ok(Some(DataDelta::Modify(lhs1.clone(), rhs2)))
            }
        }
        (DataDelta::Modify(d, _), DataDeltaUndo::Delete(_)) => {
            Ok(Some(DataDelta::Delete(d.clone())))
        }

        (DataDelta::Delete(lhs), DataDeltaUndo::Create(rhs)) => {
            if lhs == &rhs {
                Ok(None)
            } else {
                // Delete + Undo(Delete) produces Modify if the data has changed.
                // This is introduced specifically for the case: (Modify + Delete) + Undo(Delete) = Modify
                Ok(Some(DataDelta::Modify(lhs.clone(), rhs)))
            }
        }
        (DataDelta::Delete(_), DataDeltaUndo::Modify(_, _)) => {
            Err(Error::DeltaDataModifyAfterDelete)
        }
        (DataDelta::Delete(_), DataDeltaUndo::Delete(_)) => {
            Err(Error::DeltaDataDeletedMultipleTimes)
        }
    }
}

/// Given two DeltaUndos combine them into one.
/// If a combination gives No-op then None is returned.
pub fn combine_undos<T: Clone + PartialEq>(
    lhs: &DataDeltaUndo<T>,
    rhs: DataDeltaUndo<T>,
) -> Result<Option<DataDeltaUndo<T>>, Error> {
    match (lhs, rhs) {
        (DataDeltaUndo::Create(_), DataDeltaUndo::Create(_)) => {
            // Delta(Delete) + Delta(Delete) is forbidden thus its undo is forbidden as well
            Err(Error::DeltaDataDeletedMultipleTimes)
        }
        (DataDeltaUndo::Create(_), DataDeltaUndo::Modify(_, d)) => {
            Ok(Some(DataDeltaUndo::Create(d)))
        }
        (DataDeltaUndo::Create(_), DataDeltaUndo::Delete(_)) => Ok(None),

        (DataDeltaUndo::Modify(_, _), DataDeltaUndo::Create(_)) => {
            Err(Error::DeltaDataCreatedMultipleTimes)
        }
        (DataDeltaUndo::Modify(prev, _), DataDeltaUndo::Modify(_, new)) => {
            Ok(Some(DataDeltaUndo::Modify(prev.clone(), new)))
        }
        (DataDeltaUndo::Modify(d, _), DataDeltaUndo::Delete(_)) => {
            Ok(Some(DataDeltaUndo::Delete(d.clone())))
        }

        (DataDeltaUndo::Delete(lhs), DataDeltaUndo::Create(rhs)) => {
            if lhs == &rhs {
                Ok(None)
            } else {
                Ok(Some(DataDeltaUndo::Modify(lhs.clone(), rhs)))
            }
        }
        (DataDeltaUndo::Delete(_), DataDeltaUndo::Modify(_, _)) => {
            Err(Error::DeltaDataModifyAfterDelete)
        }
        (DataDeltaUndo::Delete(_), DataDeltaUndo::Delete(_)) => {
            // Delta(Create) + Delta(Create) is forbidden thus its undo is forbidden as well
            Err(Error::DeltaDataCreatedMultipleTimes)
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    #[rustfmt::skip]
    fn test_combine_deltas() {
        use DataDelta::{Create, Delete, Modify};
    
        assert_eq!(combine_deltas(&Create('a'), Create('b')),      Err(Error::DeltaDataCreatedMultipleTimes));
        assert_eq!(combine_deltas(&Create('a'), Modify('a', 'b')), Ok(Some(DataDelta::Create('b'))));
        assert_eq!(combine_deltas(&Create('a'), Delete('a')),      Ok(None));
    
        assert_eq!(combine_deltas(&Modify('a', 'b'), Create('c')),      Err(Error::DeltaDataCreatedMultipleTimes));
        assert_eq!(combine_deltas(&Modify('a', 'b'), Modify('c', 'd')), Ok(Some(DataDelta::Modify('a', 'd'))));
        assert_eq!(combine_deltas(&Modify('a', 'b'), Modify('b', 'a')), Ok(None));
        assert_eq!(combine_deltas(&Modify('a', 'b'), Delete('c')),      Ok(Some(DataDelta::Delete('a'))));
    
        assert_eq!(combine_deltas(&Delete('a'), Create('a')),      Ok(None));
        assert_eq!(combine_deltas(&Delete('a'), Create('b')),      Ok(Some(DataDelta::Modify('a', 'b'))));
        assert_eq!(combine_deltas(&Delete('a'), Modify('b', 'c')), Err(Error::DeltaDataModifyAfterDelete));
        assert_eq!(combine_deltas(&Delete('a'), Delete('b')),      Err(Error::DeltaDataDeletedMultipleTimes));
    }

    #[test]
    #[rustfmt::skip]
    fn test_combine_delta_with_undo() {
        assert_eq!(combine_delta_with_undo(&DataDelta::Create('a'),      DataDeltaUndo::Create('b')),      Err(Error::DeltaDataCreatedMultipleTimes));
        assert_eq!(combine_delta_with_undo(&DataDelta::Create('a'),      DataDeltaUndo::Modify('a', 'b')), Ok(Some(DataDelta::Create('b'))));
        assert_eq!(combine_delta_with_undo(&DataDelta::Create('a'),      DataDeltaUndo::Delete('a')),      Ok(None));

        assert_eq!(combine_delta_with_undo(&DataDelta::Modify('a', 'b'), DataDeltaUndo::Create('c')),      Ok(Some(DataDelta::Create('c'))));
        assert_eq!(combine_delta_with_undo(&DataDelta::Modify('a', 'b'), DataDeltaUndo::Modify('c', 'd')), Ok(Some(DataDelta::Modify('a', 'd'))));
        assert_eq!(combine_delta_with_undo(&DataDelta::Modify('a', 'b'), DataDeltaUndo::Modify('b', 'a')), Ok(None));
        assert_eq!(combine_delta_with_undo(&DataDelta::Modify('a', 'b'), DataDeltaUndo::Delete('b')),      Ok(Some(DataDelta::Delete('a'))));

        assert_eq!(combine_delta_with_undo(&DataDelta::Delete('a'),      DataDeltaUndo::Create('a')),      Ok(None));
        assert_eq!(combine_delta_with_undo(&DataDelta::Delete('a'),      DataDeltaUndo::Create('b')),      Ok(Some(DataDelta::Modify('a', 'b'))));
        assert_eq!(combine_delta_with_undo(&DataDelta::Delete('a'),      DataDeltaUndo::Modify('a', 'b')), Err(Error::DeltaDataModifyAfterDelete));
        assert_eq!(combine_delta_with_undo(&DataDelta::Delete('a'),      DataDeltaUndo::Delete('b')),      Err(Error::DeltaDataDeletedMultipleTimes));
    }

    #[test]
    #[rustfmt::skip]
    fn test_combine_undos() {
        assert_eq!(combine_undos(&DataDeltaUndo::Create('a'),      DataDeltaUndo::Create('b')),      Err(Error::DeltaDataDeletedMultipleTimes));
        assert_eq!(combine_undos(&DataDeltaUndo::Create('a'),      DataDeltaUndo::Modify('a', 'b')), Ok(Some(DataDeltaUndo::Create('b'))));
        assert_eq!(combine_undos(&DataDeltaUndo::Create('a'),      DataDeltaUndo::Delete('a')),      Ok(None));
    
        assert_eq!(combine_undos(&DataDeltaUndo::Modify('a', 'b'), DataDeltaUndo::Create('c')),      Err(Error::DeltaDataCreatedMultipleTimes));
        assert_eq!(combine_undos(&DataDeltaUndo::Modify('a', 'b'), DataDeltaUndo::Modify('c', 'd')), Ok(Some(DataDeltaUndo::Modify('a', 'd'))));
        assert_eq!(combine_undos(&DataDeltaUndo::Modify('a', 'b'), DataDeltaUndo::Delete('b')),      Ok(Some(DataDeltaUndo::Delete('a'))));
    
        assert_eq!(combine_undos(&DataDeltaUndo::Delete('a'),      DataDeltaUndo::Create('a')),      Ok(None));
        assert_eq!(combine_undos(&DataDeltaUndo::Delete('a'),      DataDeltaUndo::Create('b')),      Ok(Some(DataDeltaUndo::Modify('a', 'b'))));
        assert_eq!(combine_undos(&DataDeltaUndo::Delete('a'),      DataDeltaUndo::Modify('a', 'b')), Err(Error::DeltaDataModifyAfterDelete));
        assert_eq!(combine_undos(&DataDeltaUndo::Delete('a'),      DataDeltaUndo::Delete('b')),      Err(Error::DeltaDataCreatedMultipleTimes));
    }
}
