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

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum Error {
    #[error("Arithmetic error; conversion to unsigned failed")]
    ArithmeticErrorToUnsignedFailed,
    #[error("Arithmetic error; conversion to signed failed")]
    ArithmeticErrorToSignedFailed,
    #[error("Arithmetic error; delta signed addition failed")]
    ArithmeticErrorDeltaAdditionFailed,
    #[error("Arithmetic error; sum to unsigned failed")]
    ArithmeticErrorSumToUnsignedFailed,
    #[error("Arithmetic error; sum to signed failed")]
    ArithmeticErrorSumToSignedFailed,
    #[error("Consecutive data creation")]
    DataCreatedMultipleTimes,
    #[error("Modify non-existing data")]
    ModifyNonexistingData,
    #[error("Remove non-existing data")]
    RemoveNonexistingData,
    #[error("Consecutive data creation in delta combination")]
    DeltaDataCreatedMultipleTimes,
    #[error("Consecutive data deletion in delta combination")]
    DeltaDataDeletedMultipleTimes,
    #[error("Modification after deletion of data delta")]
    DeltaDataModifyAfterDelete,
    #[error("Delta undo negation error")]
    DeltaUndoNegationError,
    #[error("Applying Delta over Undo is not supported")]
    DeltaOverUndoApplied,
}
