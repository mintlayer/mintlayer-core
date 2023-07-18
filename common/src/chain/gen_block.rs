// Copyright (c) 2022 RBB S.r.l
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

//! Generalized block, or [GenBlock]

use ref_cast::RefCast;
use typename::TypeName;

use super::{Block, Genesis};
use crate::primitives::Id;

/// Generalized block that's either [Genesis] or [Block].
///
/// Does not contain any data, only used as `Id<GenBlock>` to signify given Id can refer to either
/// genesis or proper block.
#[derive(Eq, PartialEq, Clone, Debug, TypeName)]
pub enum GenBlock {}

impl From<Id<Block>> for Id<GenBlock> {
    fn from(id: Id<Block>) -> Id<GenBlock> {
        Id::new(id.get())
    }
}

impl<'a> From<&'a Id<Block>> for &'a Id<GenBlock> {
    fn from(id: &Id<Block>) -> &Id<GenBlock> {
        Id::<GenBlock>::ref_cast(id.get_ref())
    }
}

impl From<Id<Genesis>> for Id<GenBlock> {
    fn from(id: Id<Genesis>) -> Id<GenBlock> {
        Id::new(id.get())
    }
}

impl<'a> From<&'a Id<Genesis>> for &'a Id<GenBlock> {
    fn from(id: &Id<Genesis>) -> &Id<GenBlock> {
        Id::<GenBlock>::ref_cast(id.get_ref())
    }
}

impl PartialEq<Id<Block>> for Id<GenBlock> {
    fn eq(&self, other: &Id<Block>) -> bool {
        self.get() == other.get()
    }
}

impl PartialEq<Id<GenBlock>> for Id<Block> {
    fn eq(&self, other: &Id<GenBlock>) -> bool {
        self.get() == other.get()
    }
}

impl PartialEq<Id<Genesis>> for Id<GenBlock> {
    fn eq(&self, other: &Id<Genesis>) -> bool {
        self.get() == other.get()
    }
}

impl PartialEq<Id<GenBlock>> for Id<Genesis> {
    fn eq(&self, other: &Id<GenBlock>) -> bool {
        self.get() == other.get()
    }
}

impl Id<GenBlock> {
    /// Figure out if this [Id] refers to a [Genesis] or a proper [Block].
    pub fn classify(&self, c: &crate::chain::config::ChainConfig) -> GenBlockId {
        if self.get() == c.genesis_block_id().get() {
            GenBlockId::Genesis(Id::new(self.get()))
        } else {
            GenBlockId::Block(Id::new(self.get()))
        }
    }

    /// Figure out if this [Id] refers to a [Genesis] or a proper [Block].
    pub fn classify_ref(&self, c: &crate::chain::config::ChainConfig) -> GenBlockIdRef<'_> {
        if self.get() == c.genesis_block_id().get() {
            GenBlockIdRef::Genesis(Id::<Genesis>::ref_cast(self.get_ref()))
        } else {
            GenBlockIdRef::Block(Id::<Block>::ref_cast(self.get_ref()))
        }
    }
}

/// Classified generalized block
#[derive(Eq, PartialEq, Clone, Debug)]
pub enum GenBlockId {
    Genesis(Id<Genesis>),
    Block(Id<Block>),
}

impl GenBlockId {
    pub fn is_genesis(&self) -> bool {
        matches!(self, GenBlockId::Genesis(_))
    }

    pub fn chain_block_id(self) -> Option<Id<Block>> {
        match self {
            GenBlockId::Genesis(_) => None,
            GenBlockId::Block(id) => Some(id),
        }
    }
}

/// Classified generalized block reference
#[derive(Eq, PartialEq, Clone, Debug)]
pub enum GenBlockIdRef<'a> {
    Genesis(&'a Id<Genesis>),
    Block(&'a Id<Block>),
}

impl<'a> GenBlockIdRef<'a> {
    pub fn is_genesis(&self) -> bool {
        matches!(self, GenBlockIdRef::Genesis(_))
    }

    pub fn chain_block_id(&self) -> Option<&'a Id<Block>> {
        match self {
            GenBlockIdRef::Genesis(_) => None,
            GenBlockIdRef::Block(id) => Some(id),
        }
    }
}
