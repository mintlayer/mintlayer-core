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

pub enum NodeKind {
    Root,
    LeftChild,
    RightChild,
}

impl NodeKind {
    /// Returns true if the node is a left child of its parent.
    pub fn is_left(&self) -> bool {
        match self {
            NodeKind::Root => false,
            NodeKind::LeftChild => true,
            NodeKind::RightChild => false,
        }
    }

    /// Returns true if the node is a right child of its parent.
    pub fn is_right(&self) -> bool {
        match self {
            NodeKind::Root => false,
            NodeKind::LeftChild => false,
            NodeKind::RightChild => true,
        }
    }

    /// Returns true for the root node in a tree
    pub fn is_root(&self) -> bool {
        match self {
            NodeKind::Root => true,
            NodeKind::LeftChild => false,
            NodeKind::RightChild => false,
        }
    }
}
