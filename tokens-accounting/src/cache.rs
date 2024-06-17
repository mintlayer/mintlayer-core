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
use common::{
    chain::{
        tokens::{IsTokenUnfreezable, TokenId, TokenTotalSupply},
        Destination,
    },
    primitives::Amount,
};

use crate::{
    data::{TokenData, TokensAccountingDeltaData},
    error::Error,
    operations::{
        ChangeTokenAuthorityUndo, FreezeTokenUndo, IssueTokenUndo, LockSupplyUndo, MintTokenUndo,
        TokenAccountingUndo, TokensAccountingOperations, UnfreezeTokenUndo, UnmintTokenUndo,
    },
    view::TokensAccountingView,
    FlushableTokensAccountingView,
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
        match self.data.token_data.get_data(id) {
            accounting::GetDataResult::Present(d) => Ok(Some(d.clone())),
            accounting::GetDataResult::Deleted => Ok(None),
            accounting::GetDataResult::Missing => {
                Ok(self.parent.get_token_data(id).map_err(|_| Error::ViewFail)?)
            }
        }
    }

    fn get_circulating_supply(&self, id: &TokenId) -> Result<Option<Amount>, Self::Error> {
        let parent_supply = self.parent.get_circulating_supply(id).map_err(|_| Error::ViewFail)?;
        let local_delta = self.data.circulating_supply.data().get(id).cloned();
        let supply =
            combine_amount_delta(&parent_supply, &local_delta).map_err(Error::AccountingError)?;

        // When combining deltas with amounts it's impossible to distinguish None from Some(Amount::ZERO).
        // Use information from DeltaData to make the decision.
        if self.get_token_data(id)?.is_some() {
            Ok(supply)
        } else {
            utils::ensure!(
                supply.unwrap_or(Amount::ZERO) == Amount::ZERO,
                Error::InvariantErrorNonZeroSupplyForNonExistingToken
            );
            Ok(None)
        }
    }
}

impl<P> FlushableTokensAccountingView for TokensAccountingCache<P> {
    type Error = Error;

    fn batch_write_tokens_data(
        &mut self,
        delta: TokensAccountingDeltaData,
    ) -> Result<crate::data::TokensAccountingDeltaUndoData, Self::Error> {
        self.data.merge_with_delta(delta)
    }
}

impl<P: TokensAccountingView> TokensAccountingOperations for TokensAccountingCache<P> {
    fn issue_token(&mut self, id: TokenId, data: TokenData) -> Result<TokenAccountingUndo, Error> {
        if self.get_token_data(&id)?.is_some() {
            return Err(Error::TokenAlreadyExists(id));
        }

        if self.get_circulating_supply(&id)?.is_some() {
            return Err(Error::TokenAlreadyExists(id));
        }

        let undo_data = self
            .data
            .token_data
            .merge_delta_data_element(id, accounting::DataDelta::new(None, Some(data)))?;

        Ok(TokenAccountingUndo::IssueToken(IssueTokenUndo {
            id,
            undo_data,
        }))
    }

    fn mint_tokens(
        &mut self,
        id: TokenId,
        amount_to_add: Amount,
    ) -> Result<TokenAccountingUndo, Error> {
        let token_data = self.get_token_data(&id)?.ok_or(Error::TokenDataNotFound(id))?;
        let circulating_supply = self.get_circulating_supply(&id)?.unwrap_or(Amount::ZERO);

        match token_data {
            TokenData::FungibleToken(data) => {
                if data.is_frozen() {
                    return Err(Error::CannotMintFrozenToken(id));
                }

                match data.total_supply() {
                    TokenTotalSupply::Fixed(limit) => {
                        let expected_circulating_supply =
                            (circulating_supply + amount_to_add).ok_or(Error::AmountOverflow)?;
                        if expected_circulating_supply > *limit {
                            return Err(Error::MintExceedsSupplyLimit(amount_to_add, *limit, id));
                        }
                    }
                    TokenTotalSupply::Lockable => {
                        if data.is_locked() {
                            return Err(Error::CannotMintFromLockedSupply(id));
                        }
                    }
                    TokenTotalSupply::Unlimited => { /* do nothing */ }
                };
            }
        };

        self.data.circulating_supply.add_unsigned(id, amount_to_add)?;

        Ok(TokenAccountingUndo::MintTokens(MintTokenUndo {
            id,
            amount_to_add,
        }))
    }

    fn unmint_tokens(
        &mut self,
        id: TokenId,
        amount_to_burn: Amount,
    ) -> Result<TokenAccountingUndo, Error> {
        let token_data = self.get_token_data(&id)?.ok_or(Error::TokenDataNotFound(id))?;
        let circulating_supply =
            self.get_circulating_supply(&id)?.ok_or(Error::CirculatingSupplyNotFound(id))?;

        match token_data {
            TokenData::FungibleToken(data) => {
                if data.is_locked() {
                    return Err(Error::CannotUnmintFromLockedSupply(id));
                } else if data.is_frozen() {
                    return Err(Error::CannotUnmintFrozenToken(id));
                }
            }
        };

        if circulating_supply < amount_to_burn {
            return Err(Error::NotEnoughCirculatingSupplyToUnmint(
                circulating_supply,
                amount_to_burn,
                id,
            ));
        }

        self.data.circulating_supply.sub_unsigned(id, amount_to_burn)?;

        Ok(TokenAccountingUndo::UnmintTokens(UnmintTokenUndo {
            id,
            amount_to_burn,
        }))
    }

    fn lock_circulating_supply(
        &mut self,
        id: TokenId,
    ) -> crate::error::Result<TokenAccountingUndo> {
        let token_data = self.get_token_data(&id)?.ok_or(Error::TokenDataNotFound(id))?;

        let undo_data = match token_data {
            TokenData::FungibleToken(data) => {
                if data.is_locked() {
                    return Err(Error::SupplyIsAlreadyLocked(id));
                } else if data.is_frozen() {
                    return Err(Error::CannotLockFrozenToken(id));
                }

                let new_data =
                    data.clone().try_lock().map_err(|_| Error::CannotLockNotLockableSupply(id))?;
                self.data.token_data.merge_delta_data_element(
                    id,
                    accounting::DataDelta::new(
                        Some(TokenData::FungibleToken(data)),
                        Some(TokenData::FungibleToken(new_data)),
                    ),
                )?
            }
        };
        Ok(TokenAccountingUndo::LockSupply(LockSupplyUndo {
            id,
            undo_data,
        }))
    }

    fn freeze_token(
        &mut self,
        id: TokenId,
        is_unfreezable: IsTokenUnfreezable,
    ) -> Result<TokenAccountingUndo, Error> {
        let token_data = self.get_token_data(&id)?.ok_or(Error::TokenDataNotFound(id))?;

        let undo_data = match token_data {
            TokenData::FungibleToken(data) => {
                if data.is_frozen() {
                    return Err(Error::TokenIsAlreadyFrozen(id));
                }
                let new_data = data
                    .clone()
                    .try_freeze(is_unfreezable)
                    .map_err(|_| Error::CannotFreezeNotFreezableToken(id))?;
                self.data.token_data.merge_delta_data_element(
                    id,
                    accounting::DataDelta::new(
                        Some(TokenData::FungibleToken(data)),
                        Some(TokenData::FungibleToken(new_data)),
                    ),
                )?
            }
        };
        Ok(TokenAccountingUndo::FreezeToken(FreezeTokenUndo {
            id,
            undo_data,
        }))
    }

    fn unfreeze_token(&mut self, id: TokenId) -> Result<TokenAccountingUndo, Error> {
        let token_data = self.get_token_data(&id)?.ok_or(Error::TokenDataNotFound(id))?;

        let undo_data = match token_data {
            TokenData::FungibleToken(data) => {
                if !data.is_frozen() {
                    return Err(Error::CannotUnfreezeTokenThatIsNotFrozen(id));
                }
                let new_data = data
                    .clone()
                    .try_unfreeze()
                    .map_err(|_| Error::CannotUnfreezeNotUnfreezableToken(id))?;
                self.data.token_data.merge_delta_data_element(
                    id,
                    accounting::DataDelta::new(
                        Some(TokenData::FungibleToken(data)),
                        Some(TokenData::FungibleToken(new_data)),
                    ),
                )?
            }
        };
        Ok(TokenAccountingUndo::UnfreezeToken(UnfreezeTokenUndo {
            id,
            undo_data,
        }))
    }

    fn change_authority(
        &mut self,
        id: TokenId,
        new_authority: Destination,
    ) -> Result<TokenAccountingUndo, Error> {
        let token_data = self.get_token_data(&id)?.ok_or(Error::TokenDataNotFound(id))?;

        let undo_data = match token_data {
            TokenData::FungibleToken(data) => {
                if data.is_frozen() {
                    return Err(Error::CannotChangeAuthorityForFrozenToken(id));
                }

                let new_data = data.clone().change_authority(new_authority);
                self.data.token_data.merge_delta_data_element(
                    id,
                    accounting::DataDelta::new(
                        Some(TokenData::FungibleToken(data)),
                        Some(TokenData::FungibleToken(new_data)),
                    ),
                )?
            }
        };
        Ok(TokenAccountingUndo::ChangeTokenAuthority(
            ChangeTokenAuthorityUndo { id, undo_data },
        ))
    }

    fn undo(&mut self, undo_data: TokenAccountingUndo) -> Result<(), Error> {
        match undo_data {
            TokenAccountingUndo::IssueToken(undo) => {
                let _ = self
                    .get_token_data(&undo.id)?
                    .ok_or(Error::TokenDataNotFoundOnReversal(undo.id))?;
                self.data.token_data.undo_merge_delta_data_element(undo.id, undo.undo_data)?;
                Ok(())
            }
            TokenAccountingUndo::MintTokens(undo) => {
                let data = self
                    .get_token_data(&undo.id)?
                    .ok_or(Error::TokenDataNotFoundOnReversal(undo.id))?;
                match data {
                    TokenData::FungibleToken(data) => {
                        if data.is_locked() {
                            return Err(Error::CannotUndoMintForLockedSupplyOnReversal(undo.id));
                        }
                    }
                };

                self.data
                    .circulating_supply
                    .sub_unsigned(undo.id, undo.amount_to_add)
                    .map_err(Error::AccountingError)
            }
            TokenAccountingUndo::UnmintTokens(undo) => {
                let data = self
                    .get_token_data(&undo.id)?
                    .ok_or(Error::TokenDataNotFoundOnReversal(undo.id))?;
                match data {
                    TokenData::FungibleToken(data) => {
                        if data.is_locked() {
                            return Err(Error::CannotUndoUnmintForLockedSupplyOnReversal(undo.id));
                        }
                    }
                };

                self.data
                    .circulating_supply
                    .add_unsigned(undo.id, undo.amount_to_burn)
                    .map_err(Error::AccountingError)
            }
            TokenAccountingUndo::LockSupply(undo) => {
                let data = self
                    .get_token_data(&undo.id)?
                    .ok_or(Error::TokenDataNotFoundOnReversal(undo.id))?;
                match data {
                    TokenData::FungibleToken(data) => {
                        if !data.is_locked() {
                            return Err(Error::CannotUnlockNotLockedSupplyOnReversal(undo.id));
                        }
                    }
                };
                self.data.token_data.undo_merge_delta_data_element(undo.id, undo.undo_data)?;
                Ok(())
            }
            TokenAccountingUndo::FreezeToken(undo) => {
                let data = self
                    .get_token_data(&undo.id)?
                    .ok_or(Error::TokenDataNotFoundOnReversal(undo.id))?;
                match data {
                    TokenData::FungibleToken(data) => {
                        if !data.is_frozen() {
                            return Err(Error::CannotUndoFreezeTokenThatIsNotFrozen(undo.id));
                        }
                    }
                };
                self.data.token_data.undo_merge_delta_data_element(undo.id, undo.undo_data)?;
                Ok(())
            }
            TokenAccountingUndo::UnfreezeToken(undo) => {
                let data = self
                    .get_token_data(&undo.id)?
                    .ok_or(Error::TokenDataNotFoundOnReversal(undo.id))?;
                match data {
                    TokenData::FungibleToken(data) => {
                        if data.is_frozen() {
                            return Err(Error::CannotUndoUnfreezeTokenThatIsFrozen(undo.id));
                        }
                    }
                };
                self.data.token_data.undo_merge_delta_data_element(undo.id, undo.undo_data)?;
                Ok(())
            }
            TokenAccountingUndo::ChangeTokenAuthority(undo) => {
                let data = self
                    .get_token_data(&undo.id)?
                    .ok_or(Error::TokenDataNotFoundOnReversal(undo.id))?;
                match data {
                    TokenData::FungibleToken(data) => {
                        if data.is_frozen() {
                            return Err(Error::CannotUndoChangeAuthorityForFrozenToken(undo.id));
                        }
                    }
                };
                self.data.token_data.undo_merge_delta_data_element(undo.id, undo.undo_data)?;
                Ok(())
            }
        }
    }
}
