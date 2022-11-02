// Copyright (c) 2021-2022 RBB S.r.l
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

use std::{borrow::Cow, sync::Arc};

use common::{
    chain::{ChainConfig, GenBlock, GenBlockId},
    primitives::{BlockHeight, Id},
};

use crate::{
    get_skip_height, storage_result, BlockIndexHandle, GenBlockIndex, GetAncestorError,
    PropertyQueryError,
};

pub enum AncestorGetterStartingPoint<'a> {
    BlockIndex(&'a GenBlockIndex),
    BlockId(&'a Id<GenBlock>),
}

impl<'a> From<&'a Id<GenBlock>> for AncestorGetterStartingPoint<'a> {
    fn from(v: &'a Id<GenBlock>) -> Self {
        AncestorGetterStartingPoint::BlockId(v)
    }
}

impl<'a> From<&'a GenBlockIndex> for AncestorGetterStartingPoint<'a> {
    fn from(v: &'a GenBlockIndex) -> Self {
        AncestorGetterStartingPoint::BlockIndex(v)
    }
}

pub fn block_index_ancestor_getter<S, G>(
    gen_block_index_getter: G,
    db_tx: &S,
    chain_config: &ChainConfig,
    starting_point: AncestorGetterStartingPoint,
    target_height: BlockHeight,
) -> Result<GenBlockIndex, GetAncestorError>
where
    G: Fn(&S, &ChainConfig, &Id<GenBlock>) -> Result<Option<GenBlockIndex>, storage_result::Error>,
{
    let block_index = match starting_point {
        AncestorGetterStartingPoint::BlockIndex(bi) => Cow::Borrowed(bi),
        AncestorGetterStartingPoint::BlockId(id) => Cow::Owned(
            gen_block_index_getter(db_tx, chain_config, id)?
                .ok_or(GetAncestorError::StartingPointNotFound(*id))?,
        ),
    };

    if target_height > block_index.block_height() {
        return Err(GetAncestorError::InvalidAncestorHeight {
            block_height: block_index.block_height(),
            ancestor_height: target_height,
        });
    }

    let mut height_walk = block_index.block_height();
    let mut block_index_walk = block_index.into_owned();
    loop {
        assert!(height_walk >= target_height, "Skipped too much");
        if height_walk == target_height {
            break Ok(block_index_walk);
        }
        let cur_block_index = match block_index_walk {
            GenBlockIndex::Genesis(_) => break Ok(block_index_walk),
            GenBlockIndex::Block(idx) => idx,
        };

        let ancestor = cur_block_index.some_ancestor();

        let height_walk_prev =
            height_walk.prev_height().expect("Can never fail because prev is zero at worst");
        let height_skip = get_skip_height(height_walk);
        let height_skip_prev = get_skip_height(height_walk_prev);

        // prepare the booleans for the check
        let at_target = height_skip == target_height;
        let still_not_there = height_skip > target_height;
        let too_close = height_skip_prev.next_height().next_height() < height_skip;
        let prev_too_close = height_skip_prev >= target_height;

        if at_target || (still_not_there && !(too_close && prev_too_close)) {
            block_index_walk = gen_block_index_getter(db_tx, chain_config, ancestor)?
                .expect("Block index of ancestor must exist, since id exists");
            height_walk = height_skip;
        } else {
            let prev_block_id = cur_block_index.prev_block_id();
            block_index_walk = gen_block_index_getter(db_tx, chain_config, prev_block_id)?
                .ok_or(GetAncestorError::PrevBlockIndexNotFound(*prev_block_id))?;
            height_walk = height_walk_prev;
        }
    }
}

pub fn gen_block_index_getter<S: BlockIndexHandle>(
    db_tx: &S,
    chain_config: &ChainConfig,
    block_id: &Id<GenBlock>,
) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
    match block_id.classify(chain_config) {
        GenBlockId::Genesis(_id) => Ok(Some(GenBlockIndex::Genesis(Arc::clone(
            chain_config.genesis_block(),
        )))),
        GenBlockId::Block(id) => db_tx.get_block_index(&id).map(|b| b.map(GenBlockIndex::Block)),
    }
}
