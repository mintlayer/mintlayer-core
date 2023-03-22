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

use crate::primitives::merkle::tree::Node;

#[derive(Debug, Clone)]
pub struct NodeWithAbsOrder<'a, T, H> {
    node: Node<'a, T, H>,
}

impl<'a, T, H> NodeWithAbsOrder<'a, T, H> {
    pub fn get(&self) -> &Node<'a, T, H> {
        &self.node
    }
}

impl<'a, T, H> From<Node<'a, T, H>> for NodeWithAbsOrder<'a, T, H> {
    fn from(node: Node<'a, T, H>) -> Self {
        Self { node }
    }
}

impl<'a, T, H> From<NodeWithAbsOrder<'a, T, H>> for Node<'a, T, H> {
    fn from(node: NodeWithAbsOrder<'a, T, H>) -> Self {
        node.node
    }
}

impl<T, H> Ord for NodeWithAbsOrder<'_, T, H> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.node.abs_index().cmp(&other.node.abs_index())
    }
}

impl<T, H> Eq for NodeWithAbsOrder<'_, T, H> {}

impl<T, H> PartialOrd for NodeWithAbsOrder<'_, T, H> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.node.abs_index().partial_cmp(&other.node.abs_index())
    }
}

impl<T, H> PartialEq for NodeWithAbsOrder<'_, T, H> {
    fn eq(&self, other: &Self) -> bool {
        self.node.abs_index() == other.node.abs_index()
    }
}
