// Copyright (c) 2022-2023 RBB S.r.l
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

//! Subsystem call related error types

/// Error during a subsystem call
#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum CallError {
    #[error(transparent)]
    Submission(#[from] SubmissionError),
    #[error(transparent)]
    Response(#[from] ResponseError),
}

/// Error during a subsystem call submission
#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum SubmissionError {
    #[error("Call send channel closed")]
    ChannelClosed,
}

/// Error retrieving a subsystem call response
#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum ResponseError {
    #[error("Callee subsystem did not respond")]
    NoResponse,
}
