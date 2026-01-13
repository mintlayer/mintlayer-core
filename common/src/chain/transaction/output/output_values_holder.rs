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

use std::collections::BTreeSet;

use crate::chain::{
    output_value::{OutputValue, RpcOutputValue},
    tokens::TokenId,
};

/// A trait that will be implemented by types that contain one or more `OutputValue`'s, e.g.
/// a transaction output, a transaction itself, a block.
pub trait OutputValuesHolder {
    fn output_values_iter(&self) -> impl Iterator<Item = &OutputValue>;
}

/// A trait that will be implemented by types that contain one or more `RpcOutputValue`'s.
pub trait RpcOutputValuesHolder {
    fn rpc_output_values_iter(&self) -> impl Iterator<Item = &RpcOutputValue>;
}

pub fn collect_token_v1_ids_from_output_values_holder_into(
    holder: &impl OutputValuesHolder,
    dest: &mut BTreeSet<TokenId>,
) {
    for token_id in holder
        .output_values_iter()
        .flat_map(|output_value| output_value.token_v1_id().into_iter())
    {
        dest.insert(*token_id);
    }
}

pub fn collect_token_v1_ids_from_output_values_holder(
    holder: &impl OutputValuesHolder,
) -> BTreeSet<TokenId> {
    collect_token_v1_ids_from_output_values_holders(std::iter::once(holder))
}

pub fn collect_token_v1_ids_from_output_values_holders<'a, H: OutputValuesHolder + 'a>(
    holders: impl IntoIterator<Item = &'a H>,
) -> BTreeSet<TokenId> {
    let mut result = BTreeSet::new();
    for holder in holders {
        collect_token_v1_ids_from_output_values_holder_into(holder, &mut result);
    }
    result
}

pub fn collect_token_v1_ids_from_rpc_output_values_holder_into(
    holder: &impl RpcOutputValuesHolder,
    dest: &mut BTreeSet<TokenId>,
) {
    for token_id in holder
        .rpc_output_values_iter()
        .flat_map(|output_value| output_value.token_id().into_iter())
    {
        dest.insert(*token_id);
    }
}

pub fn collect_token_v1_ids_from_rpc_output_values_holders<'a, H: RpcOutputValuesHolder + 'a>(
    holders: impl IntoIterator<Item = &'a H>,
) -> BTreeSet<TokenId> {
    let mut result = BTreeSet::new();
    for holder in holders {
        collect_token_v1_ids_from_rpc_output_values_holder_into(holder, &mut result);
    }
    result
}
