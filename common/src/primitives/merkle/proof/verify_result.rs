// Copyright (c) 2021-2023 RBB S.r.l
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofVerifyResult {
    /// The verification was successful, and the tree was recreated from the proof.
    PassedDecisively,
    /// The verification was unsuccessful, due to a mismatch in the root hash.
    Failed,
    /// The verification was successful, but trivially. This is the result
    /// by checking that leaf == root. This happens when the number of leaves is 1.
    /// The choice to make this distinction is a security measure to prevent a malicious
    /// user from circumventing verification by providing a proof of a single node.
    PassedTrivially,
}

impl ProofVerifyResult {
    /// The verification was successful, and the tree was recreated from the proof.
    pub fn passed_decisively(self) -> bool {
        match self {
            ProofVerifyResult::PassedDecisively => true,
            ProofVerifyResult::Failed => false,
            ProofVerifyResult::PassedTrivially => false,
        }
    }

    /// The verification was unsuccessful, due to a mismatch in the root hash.
    pub fn failed(self) -> bool {
        match self {
            ProofVerifyResult::PassedDecisively => false,
            ProofVerifyResult::Failed => true,
            ProofVerifyResult::PassedTrivially => false,
        }
    }

    /// The verification was successful, but the verification was trivial, done
    /// by checking that the leaf == root. This happens when the number of leaves is 1.
    pub fn passed_trivially(self) -> bool {
        match self {
            ProofVerifyResult::PassedDecisively => false,
            ProofVerifyResult::Failed => false,
            ProofVerifyResult::PassedTrivially => true,
        }
    }

    /// Combine the current result with a boolean value of checking equality of a hash with root.
    pub(super) fn or(self, other: bool) -> ProofVerifyResult {
        match self {
            ProofVerifyResult::PassedDecisively | ProofVerifyResult::PassedTrivially => match other
            {
                true => ProofVerifyResult::PassedDecisively,
                false => ProofVerifyResult::Failed,
            },
            ProofVerifyResult::Failed => ProofVerifyResult::Failed,
        }
    }
}
