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

pub mod tree;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum MerkleTreeFormError {
    #[error("Merkle tree input too small: {0}")]
    TooSmall(usize),
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum MerkleTreeProofExtractionError {
    #[error("One or more indexes are larger than the number of leaves in the tree: {0:?} vs leaves count {1}")]
    IndexOutOfRange(Vec<u32>, usize),
    #[error("Leaves indices must be sorted in ascending: {0:?}")]
    UnsortedOrUniqueLeavesIndices(Vec<u32>),
    #[error("Access error: {0}")]
    AccessError(#[from] MerkleTreeAccessError),
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum MerkleTreeAccessError {
    #[error("Invalid tree size provided provided is invalid: {0}")]
    InvalidTreeSize(usize),
    #[error("Invalid level number in tree size: {0}, where attempting to access level {1} and index {2}")]
    LevelOutOfRange(usize, usize, usize),
    #[error("Invalid index number in tree size: {0}, where attempting to access level {1} and index {2}")]
    IndexOutOfRange(usize, usize, usize),
}
