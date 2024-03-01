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

use std::{collections::BTreeMap, ops::Neg};

use accounting::{
    combine_amount_delta, combine_data_with_delta, DeltaAmountCollection, DeltaDataUndoCollection,
};
use common::{chain::tokens::TokenId, primitives::Amount};
use utils::tap_log::TapLog;

use crate::{
    data::{TokensAccountingDeltaData, TokensAccountingDeltaUndoData},
    error::Error,
    FlushableTokensAccountingView, TokenData, TokensAccountingView,
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
        let data_undo = other
            .token_data
            .consume()
            .into_iter()
            .map(|(id, delta)| -> Result<_, Error> {
                let undo = delta.clone().invert();
                let old_data = self.0.get_token_data(&id).log_err().map_err(|_| Error::ViewFail)?;
                match combine_data_with_delta(old_data, Some(delta))? {
                    Some(result) => self
                        .0
                        .set_token_data(&id, &result)
                        .log_err()
                        .map_err(|_| Error::StorageWrite)?,
                    None => {
                        self.0.del_token_data(&id).log_err().map_err(|_| Error::StorageWrite)?
                    }
                };
                Ok((id, undo))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let circulating_supply_undo = other
            .circulating_supply
            .consume()
            .into_iter()
            .map(|(id, delta)| -> Result<_, Error> {
                let balance =
                    self.0.get_circulating_supply(&id).log_err().map_err(|_| Error::ViewFail)?;
                match combine_amount_delta(&balance, &Some(delta))? {
                    Some(result) => {
                        if result > Amount::ZERO {
                            self.0
                                .set_circulating_supply(&id, &result)
                                .log_err()
                                .map_err(|_| Error::StorageWrite)?
                        } else {
                            self.0
                                .del_circulating_supply(&id)
                                .log_err()
                                .map_err(|_| Error::StorageWrite)?
                        }
                    }
                    None => self
                        .0
                        .del_circulating_supply(&id)
                        .log_err()
                        .map_err(|_| Error::StorageWrite)?,
                };
                let balance_undo = delta.neg().expect("amount negation some");
                Ok((id, balance_undo))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(TokensAccountingDeltaUndoData {
            token_data: DeltaDataUndoCollection::from_data(data_undo),
            circulating_supply: DeltaAmountCollection::from_iter(circulating_supply_undo),
        })
    }
}

impl<S: TokensAccountingStorageRead> TokensAccountingView for TokensAccountingDB<S> {
    type Error = S::Error;

    fn get_token_data(&self, id: &TokenId) -> Result<Option<TokenData>, Self::Error> {
        self.0.get_token_data(id)
    }

    fn get_circulating_supply(&self, id: &TokenId) -> Result<Option<Amount>, Self::Error> {
        self.0.get_circulating_supply(id)
    }
}

impl<S: TokensAccountingStorageRead> TokensAccountingStorageRead for TokensAccountingDB<S> {
    type Error = S::Error;

    fn get_token_data(&self, id: &TokenId) -> Result<Option<crate::TokenData>, Self::Error> {
        self.0.get_token_data(id)
    }

    fn get_circulating_supply(&self, id: &TokenId) -> Result<Option<Amount>, Self::Error> {
        self.0.get_circulating_supply(id)
    }
}

impl<S: TokensAccountingStorageWrite> TokensAccountingStorageWrite for TokensAccountingDB<S> {
    fn set_token_data(&mut self, id: &TokenId, data: &crate::TokenData) -> Result<(), Self::Error> {
        self.0.set_token_data(id, data)
    }

    fn del_token_data(&mut self, id: &TokenId) -> Result<(), Self::Error> {
        self.0.del_token_data(id)
    }

    fn set_circulating_supply(&mut self, id: &TokenId, supply: &Amount) -> Result<(), Self::Error> {
        self.0.set_circulating_supply(id, supply)
    }

    fn del_circulating_supply(&mut self, id: &TokenId) -> Result<(), Self::Error> {
        self.0.del_circulating_supply(id)
    }
}

impl<S: TokensAccountingStorageWrite> FlushableTokensAccountingView for TokensAccountingDB<S> {
    type Error = Error;

    fn batch_write_tokens_data(
        &mut self,
        delta: TokensAccountingDeltaData,
    ) -> Result<TokensAccountingDeltaUndoData, Self::Error> {
        self.merge_with_delta(delta).log_err().map_err(|_| Error::StorageWrite)
    }
}
