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

pub mod hasher;
pub mod pos;
pub mod proof;
pub mod tree;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum MerkleTreeFormError {
    #[error("Merkle tree input too small: {0}")]
    TooSmall(usize),
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum MerkleTreeProofExtractionError {
    #[error("No leaves were provided to create a proof")]
    NoLeavesToCreateProof,
    #[error("One or more indexes are larger than the number of leaves in the tree: {0:?} vs leaf-count {1}")]
    IndexOutOfRange(Vec<u32>, u32),
    #[error("Leaf index out of range: {0} vs leaves count {1}")]
    LeafIndexOutOfRange(u32, u32),
    #[error("Leaves indices must be sorted in ascending: {0:?}")]
    UnsortedOrUniqueLeavesIndices(Vec<u32>),
    #[error("Access error: {0}")]
    AccessError(#[from] MerkleTreeAccessError),
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum MerkleTreeAccessError {
    #[error("Invalid tree size provided is invalid: {0}")]
    InvalidTreeSize(usize),
    #[error("Invalid initial index for leaf in iterator. Provided {0} vs tree size {1}")]
    AbsIndexOutOfRange(u32, u32),
    #[error("Invalid initial index for leaf in iterator. Provided {0} vs size {1}")]
    IterStartIndexOutOfRange(u32, u32),
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum MerkleProofVerificationError {
    #[error("No leaves provided")]
    LeavesContainerProvidedIsEmpty,
    #[error("Invalid tree size")]
    InvalidTreeLeavesCount(u32),
    #[error("One or more leaves have indices out of range: {0:?} vs leaves count {1}")]
    LeavesIndicesOutOfRange(Vec<u32>, u32),
    #[error("One or more nodes have indices out of range: {0:?} vs tree size {1}")]
    NodesIndicesOutOfRange(Vec<u32>, u32),
    #[error("A required node is missing. Index of node: {0}")]
    RequiredNodeMissing(u32),
    #[error("Tree size arithmetic error: {0}")]
    TreeSizeArithmeticError(u32),
}
