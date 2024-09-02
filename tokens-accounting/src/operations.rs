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
use common::{
    chain::{
        tokens::{IsTokenUnfreezable, TokenId},
        Destination,
    },
    primitives::{Amount, H256},
};
use randomness::Rng;
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
pub struct UnmintTokenUndo {
    pub(crate) id: TokenId,
    pub(crate) amount_to_burn: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct LockSupplyUndo {
    pub(crate) id: TokenId,
    pub(crate) undo_data: DataDeltaUndo<TokenData>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct FreezeTokenUndo {
    pub(crate) id: TokenId,
    pub(crate) undo_data: DataDeltaUndo<TokenData>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct UnfreezeTokenUndo {
    pub(crate) id: TokenId,
    pub(crate) undo_data: DataDeltaUndo<TokenData>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ChangeTokenAuthorityUndo {
    pub(crate) id: TokenId,
    pub(crate) undo_data: DataDeltaUndo<TokenData>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ChangeTokenMetadataUriUndo {
    pub(crate) id: TokenId,
    pub(crate) undo_data: DataDeltaUndo<TokenData>,
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, VariantCount)]
pub enum TokenAccountingUndo {
    #[codec(index = 0)]
    IssueToken(IssueTokenUndo),
    #[codec(index = 1)]
    MintTokens(MintTokenUndo),
    #[codec(index = 2)]
    UnmintTokens(UnmintTokenUndo),
    #[codec(index = 3)]
    LockSupply(LockSupplyUndo),
    #[codec(index = 4)]
    FreezeToken(FreezeTokenUndo),
    #[codec(index = 5)]
    UnfreezeToken(UnfreezeTokenUndo),
    #[codec(index = 6)]
    ChangeTokenAuthority(ChangeTokenAuthorityUndo),
    #[codec(index = 7)]
    ChangeTokenMetadataUri(ChangeTokenMetadataUriUndo),
}

pub fn random_undo_for_test(rng: &mut impl Rng) -> TokenAccountingUndo {
    let id: TokenId = H256::random_using(rng).into();
    let amount_to_add = Amount::from_atoms(rng.gen_range(0..100_000));

    // TODO: return other undo types
    TokenAccountingUndo::MintTokens(MintTokenUndo { id, amount_to_add })
}

pub trait TokensAccountingOperations {
    fn issue_token(&mut self, id: TokenId, data: TokenData) -> Result<TokenAccountingUndo>;

    fn mint_tokens(&mut self, id: TokenId, amount_to_add: Amount) -> Result<TokenAccountingUndo>;
    fn unmint_tokens(&mut self, id: TokenId, amount_to_burn: Amount)
        -> Result<TokenAccountingUndo>;

    fn lock_circulating_supply(&mut self, id: TokenId) -> Result<TokenAccountingUndo>;

    fn freeze_token(
        &mut self,
        id: TokenId,
        is_unfreezable: IsTokenUnfreezable,
    ) -> Result<TokenAccountingUndo>;
    fn unfreeze_token(&mut self, id: TokenId) -> Result<TokenAccountingUndo>;

    fn change_authority(
        &mut self,
        id: TokenId,
        new_authority: Destination,
    ) -> Result<TokenAccountingUndo>;

    fn change_metadata_uri(
        &mut self,
        id: TokenId,
        metadata_uri: Vec<u8>,
    ) -> Result<TokenAccountingUndo>;

    fn undo(&mut self, undo_data: TokenAccountingUndo) -> Result<()>;
}
