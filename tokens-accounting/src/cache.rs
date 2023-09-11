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

use accounting::combine_amount_delta;
use common::{chain::tokens::TokenId, primitives::Amount};

use crate::{
    data::{TokenData, TokensAccountingDeltaData},
    error::Error,
    operations::{TokenAccountingUndo, TokensAccountingOperations},
    view::TokensAccountingView,
};

pub struct TokensAccountingCache<P> {
    parent: P,
    data: TokensAccountingDeltaData,
}

impl<P: TokensAccountingView> TokensAccountingCache<P> {
    pub fn new(parent: P) -> Self {
        Self {
            parent,
            data: TokensAccountingDeltaData::new(),
        }
    }

    pub fn consume(self) -> TokensAccountingDeltaData {
        self.data
    }

    pub fn data(&self) -> &TokensAccountingDeltaData {
        &self.data
    }
}

impl<P: TokensAccountingView> TokensAccountingView for TokensAccountingCache<P> {
    type Error = Error;

    fn get_token_data(&self, id: &TokenId) -> Result<Option<TokenData>, Self::Error> {
        match self.data.token_data.get_data(&id) {
            accounting::GetDataResult::Present(d) => Ok(Some(d.clone())),
            accounting::GetDataResult::Deleted => Ok(None),
            accounting::GetDataResult::Missing => {
                Ok(self.parent.get_token_data(id).map_err(|_| Error::ViewFail)?)
            }
        }
    }

    fn get_circulating_supply(&self, id: &TokenId) -> Result<Option<Amount>, Self::Error> {
        let parent_supply = self.parent.get_circulating_supply(id).map_err(|_| Error::ViewFail)?;
        let local_delta = self.data.circulating_supply.data().get(&id).cloned();
        combine_amount_delta(&parent_supply, &local_delta).map_err(Error::AccountingError)
    }
}

impl<P: TokensAccountingView> TokensAccountingOperations for TokensAccountingCache<P> {
    fn issue_token(&mut self, id: TokenId, data: TokenData) -> Result<TokenAccountingUndo, Error> {
        todo!()
    }

    fn mint_tokens(&mut self, id: TokenId, amount: Amount) -> Result<TokenAccountingUndo, Error> {
        todo!()
    }

    fn lock_total_supply(&mut self, id: TokenId) -> crate::error::Result<TokenAccountingUndo> {
        todo!()
    }

    fn undo(&mut self, undo_data: TokenAccountingUndo) -> Result<(), Error> {
        todo!()
    }
}
