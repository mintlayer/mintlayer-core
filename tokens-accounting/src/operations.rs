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

use accounting::DataDeltaUndo;
use common::{chain::tokens::TokenId, primitives::Amount};
use serialization::{Decode, Encode};
use variant_count::VariantCount;

use crate::{data::TokenData, error::Result};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct IssueTokenUndo {
    pub(crate) id: TokenId,
    pub(crate) undo_data: DataDeltaUndo<TokenData>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct MintTokenUndo {
    pub(crate) id: TokenId,
    pub(crate) amount_to_add: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct BurnTokenUndo {
    pub(crate) id: TokenId,
    pub(crate) amount_to_burn: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LockSupplyUndo {
    pub(crate) id: TokenId,
    pub(crate) undo_data: DataDeltaUndo<TokenData>,
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, VariantCount)]
pub enum TokenAccountingUndo {
    IssueToken(IssueTokenUndo),
    MintTokens(MintTokenUndo),
    BurnTokens(BurnTokenUndo),
    LockSupply(LockSupplyUndo),
}

pub trait TokensAccountingOperations {
    fn issue_token(&mut self, id: TokenId, data: TokenData) -> Result<TokenAccountingUndo>;

    fn mint_tokens(&mut self, id: TokenId, amount_to_add: Amount) -> Result<TokenAccountingUndo>;
    fn burn_tokens(&mut self, id: TokenId, amount_to_burn: Amount) -> Result<TokenAccountingUndo>;

    fn lock_total_supply(&mut self, id: TokenId) -> Result<TokenAccountingUndo>;

    fn undo(&mut self, undo_data: TokenAccountingUndo) -> Result<()>;
}
