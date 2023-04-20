// Copyright (c) 2023 RBB S.r.l
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

use crate::error::{Error, MempoolPolicyError, TxValidationError};

/// Ban score for transactions
pub trait MempoolBanScore {
    fn mempool_ban_score(&self) -> u32;
}

impl MempoolBanScore for Error {
    fn mempool_ban_score(&self) -> u32 {
        match self {
            // Validation error, needs further inspection
            Error::Validity(err) => err.mempool_ban_score(),
            Error::Policy(err) => err.mempool_ban_score(),
        }
    }
}

impl MempoolBanScore for TxValidationError {
    fn mempool_ban_score(&self) -> u32 {
        todo!()
    }
}

impl MempoolBanScore for MempoolPolicyError {
    fn mempool_ban_score(&self) -> u32 {
        todo!()
    }
}
