// Copyright (c) 2021 RBB S.r.l
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

//! A consensus related logic.

pub mod pos;
pub mod pow;

pub use crate::{
    error::ConsensusVerificationError,
    pos::error::ConsensusPoSError,
    pow::ConsensusPoWError,
    validator::{
        compute_extra_consensus_data, validate_consensus, BlockIndexHandle, TransactionIndexHandle,
    },
};

mod error;
mod validator;
