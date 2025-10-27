// Copyright (c) 2021-2025 RBB S.r.l
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

use crate::Error;

// Note: the order of items of this enum is how they will appear in the help message.
// Though not super important, it's nicer when the order is consistent with the contents
// of the "DEFAULT_BLOCK_OUTPUT_FIELDS_XXX" arrays.
#[derive(Eq, PartialEq, Debug, Copy, Clone, strum::Display, strum::EnumString, strum::EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum BlockOutputField {
    Height,
    IsMainchain,
    Id,
    Timestamp,
    PoolId,
    Target,
    ChainTrust,
    Status,
    ParentId,
}

pub static DEFAULT_BLOCK_OUTPUT_FIELDS_MAINCHAIN_ONLY: [BlockOutputField; 5] = [
    BlockOutputField::Height,
    BlockOutputField::Id,
    BlockOutputField::Timestamp,
    BlockOutputField::PoolId,
    BlockOutputField::Target,
];

pub static DEFAULT_BLOCK_OUTPUT_FIELDS_WITH_STALE_CHAINS: [BlockOutputField; 7] = [
    BlockOutputField::Height,
    BlockOutputField::IsMainchain,
    BlockOutputField::Id,
    BlockOutputField::Timestamp,
    BlockOutputField::PoolId,
    BlockOutputField::Target,
    BlockOutputField::ParentId,
];

pub fn parse_block_output_fields_list(list: &str) -> Result<Vec<BlockOutputField>, Error> {
    let result = list
        .split(',')
        .map(|field| {
            let field = field.trim();
            field.parse::<BlockOutputField>().map_err(|_| Error::UnexpectedOutputField {
                field: field.to_owned(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(result)
}
