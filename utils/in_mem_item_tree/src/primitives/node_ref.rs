// Copyright (c) 2021-2024 RBB S.r.l
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

use super::node_id::NodeId;

/// The wrapper for an immutable reference to `indextree::Node`.
///
/// Note that unlike the wrapped `indextree::Node`, this can never refer to a removed node,
/// so we don't expose the `is_removed` function.
#[derive(Copy, Clone, Debug)]
pub struct NodeRef<'a, T>(pub(super) &'a indextree::Node<T>);

impl<'a, T> NodeRef<'a, T> {
    pub fn get(&self) -> &'a T {
        self.0.get()
    }

    pub fn parent(&self) -> Option<NodeId> {
        self.0.parent().map(NodeId)
    }

    pub fn first_child(&self) -> Option<NodeId> {
        self.0.first_child().map(NodeId)
    }

    pub fn last_child(&self) -> Option<NodeId> {
        self.0.last_child().map(NodeId)
    }

    pub fn previous_sibling(&self) -> Option<NodeId> {
        self.0.previous_sibling().map(NodeId)
    }

    pub fn next_sibling(&self) -> Option<NodeId> {
        self.0.next_sibling().map(NodeId)
    }
}

/// The wrapper for a mutable reference to `indextree::Node`.
///
/// Same as `NodeRef`, this can never refer to a removed node.
#[derive(Debug)]
pub struct NodeMut<'a, T>(pub(super) &'a mut indextree::Node<T>);

impl<'a, T> NodeMut<'a, T> {
    pub fn get_mut(&mut self) -> &mut T {
        self.0.get_mut()
    }

    pub fn parent(&self) -> Option<NodeId> {
        self.0.parent().map(NodeId)
    }

    pub fn first_child(&self) -> Option<NodeId> {
        self.0.first_child().map(NodeId)
    }

    pub fn last_child(&self) -> Option<NodeId> {
        self.0.last_child().map(NodeId)
    }

    pub fn previous_sibling(&self) -> Option<NodeId> {
        self.0.previous_sibling().map(NodeId)
    }

    pub fn next_sibling(&self) -> Option<NodeId> {
        self.0.next_sibling().map(NodeId)
    }
}

impl<'a, T> From<NodeMut<'a, T>> for NodeRef<'a, T> {
    fn from(value: NodeMut<'a, T>) -> Self {
        Self(&*value.0)
    }
}
