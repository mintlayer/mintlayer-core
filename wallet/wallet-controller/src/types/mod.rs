// Copyright (c) 2023 RBB S.r.l
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

//! Support types for presenting data in user-facing settings

mod balances;
mod block_info;
mod seed_phrase;
mod transaction;

pub use balances::Balances;
pub use block_info::{BlockInfo, CreatedBlockInfo};
pub use common::primitives::DecimalAmount;
use common::primitives::H256;
pub use seed_phrase::SeedWithPassPhrase;
pub use transaction::{
    InspectTransaction, SignatureStats, TransactionToInspect, ValidatedSignatures,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, rpc_description::HasValueHint)]
pub struct WalletInfo {
    pub wallet_id: H256,
    pub account_names: Vec<Option<String>>,
}
