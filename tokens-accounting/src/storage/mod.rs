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

use common::{chain::tokens::TokenId, primitives::Amount};
use std::ops::{Deref, DerefMut};

use crate::data::TokenData;

pub mod db;
pub mod in_memory;

pub trait TokensAccountingStorageRead {
    type Error: std::error::Error;

    fn get_token_data(&self, id: &TokenId) -> Result<Option<TokenData>, Self::Error>;
    fn get_circulating_supply(&self, id: &TokenId) -> Result<Option<Amount>, Self::Error>;
}

pub trait TokensAccountingStorageWrite: TokensAccountingStorageRead {
    fn set_token_data(&mut self, id: &TokenId, data: &TokenData) -> Result<(), Self::Error>;
    fn del_token_data(&mut self, id: &TokenId) -> Result<(), Self::Error>;

    fn set_circulating_supply(&mut self, id: &TokenId, supply: &Amount) -> Result<(), Self::Error>;
    fn del_circulating_supply(&mut self, id: &TokenId) -> Result<(), Self::Error>;
}

impl<T> TokensAccountingStorageRead for T
where
    T: Deref,
    <T as Deref>::Target: TokensAccountingStorageRead,
{
    type Error = <T::Target as TokensAccountingStorageRead>::Error;

    fn get_token_data(&self, id: &TokenId) -> Result<Option<TokenData>, Self::Error> {
        self.deref().get_token_data(id)
    }

    fn get_circulating_supply(&self, id: &TokenId) -> Result<Option<Amount>, Self::Error> {
        self.deref().get_circulating_supply(id)
    }
}

impl<T> TokensAccountingStorageWrite for T
where
    T: DerefMut,
    <T as Deref>::Target: TokensAccountingStorageWrite,
{
    fn set_token_data(&mut self, id: &TokenId, data: &TokenData) -> Result<(), Self::Error> {
        self.deref_mut().set_token_data(id, data)
    }

    fn del_token_data(&mut self, id: &TokenId) -> Result<(), Self::Error> {
        self.deref_mut().del_token_data(id)
    }

    fn set_circulating_supply(&mut self, id: &TokenId, supply: &Amount) -> Result<(), Self::Error> {
        self.deref_mut().set_circulating_supply(id, supply)
    }

    fn del_circulating_supply(&mut self, id: &TokenId) -> Result<(), Self::Error> {
        self.deref_mut().del_circulating_supply(id)
    }
}
