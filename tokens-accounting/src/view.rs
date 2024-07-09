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

use std::ops::Deref;

use common::{chain::tokens::TokenId, primitives::Amount};

use crate::data::{TokenData, TokensAccountingDeltaData, TokensAccountingDeltaUndoData};

pub trait TokensAccountingView {
    /// Error that can occur during queries
    type Error: std::error::Error;

    /// Retrieves token data.
    fn get_token_data(&self, id: &TokenId) -> Result<Option<TokenData>, Self::Error>;

    /// Retrieves token circulating supply.
    fn get_circulating_supply(&self, id: &TokenId) -> Result<Amount, Self::Error>;
}

pub trait FlushableTokensAccountingView {
    /// Errors potentially triggered by flushing the view
    type Error: std::error::Error;

    /// Performs bulk modification
    fn batch_write_tokens_data(
        &mut self,
        delta: TokensAccountingDeltaData,
    ) -> Result<TokensAccountingDeltaUndoData, Self::Error>;
}

impl<T> TokensAccountingView for T
where
    T: Deref,
    <T as Deref>::Target: TokensAccountingView,
{
    type Error = <T::Target as TokensAccountingView>::Error;

    fn get_token_data(&self, id: &TokenId) -> Result<Option<TokenData>, Self::Error> {
        self.deref().get_token_data(id)
    }

    fn get_circulating_supply(&self, id: &TokenId) -> Result<Amount, Self::Error> {
        self.deref().get_circulating_supply(id)
    }
}
