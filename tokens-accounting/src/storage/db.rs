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

use common::{chain::tokens::TokenId, primitives::Amount};

use crate::{
    data::{TokensAccountingDeltaData, TokensAccountingDeltaUndoData},
    error::Error,
    TokenData, TokensAccountingView,
};

use super::{TokensAccountingStorageRead, TokensAccountingStorageWrite};

#[must_use]
pub struct TokensAccountingDB<S>(S);

impl<S: TokensAccountingStorageRead> TokensAccountingDB<S> {
    pub fn new(store: S) -> Self {
        Self(store)
    }
}

impl<S: TokensAccountingStorageWrite> TokensAccountingDB<S> {
    pub fn merge_with_delta(
        &mut self,
        other: TokensAccountingDeltaData,
    ) -> Result<TokensAccountingDeltaUndoData, Error> {
        todo!()
    }
}

impl<S: TokensAccountingStorageRead> TokensAccountingView for TokensAccountingDB<S> {
    type Error = Error;

    fn get_token_data(&self, id: &TokenId) -> Result<Option<TokenData>, Self::Error> {
        todo!()
    }

    fn get_circulating_supply(&self, id: &TokenId) -> Result<Option<Amount>, Self::Error> {
        todo!()
    }
}

impl<S: TokensAccountingStorageRead> TokensAccountingStorageRead for TokensAccountingDB<S> {
    type Error = S::Error;

    fn get_token_data(
        &self,
        id: &common::chain::tokens::TokenId,
    ) -> Result<Option<crate::TokenData>, Self::Error> {
        todo!()
    }

    fn get_circulating_supply(
        &self,
        id: &common::chain::tokens::TokenId,
    ) -> Result<Option<common::primitives::Amount>, Self::Error> {
        todo!()
    }
}

impl<S: TokensAccountingStorageWrite> TokensAccountingStorageWrite for TokensAccountingDB<S> {
    fn set_token_data(
        &mut self,
        id: &common::chain::tokens::TokenId,
        data: &crate::TokenData,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn del_token_data(&mut self, id: &common::chain::tokens::TokenId) -> Result<(), Self::Error> {
        todo!()
    }

    fn set_circulating_supply(
        &mut self,
        id: &common::chain::tokens::TokenId,
        supply: &common::primitives::Amount,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn del_circulating_supply(
        &mut self,
        id: &common::chain::tokens::TokenId,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}
