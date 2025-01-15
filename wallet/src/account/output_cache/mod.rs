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

use std::{
    cmp::Reverse,
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    ops::Add,
};

use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        make_order_id,
        output_value::OutputValue,
        stakelock::StakePoolData,
        tokens::{
            is_token_or_nft_issuance, make_token_id, IsTokenFreezable, IsTokenUnfreezable,
            RPCFungibleTokenInfo, RPCIsTokenFrozen, RPCTokenTotalSupply, TokenId, TokenIssuance,
            TokenTotalSupply,
        },
        AccountCommand, AccountNonce, AccountSpending, DelegationId, Destination, GenBlock,
        OrderId, OutPointSourceId, PoolId, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{id::WithId, per_thousand::PerThousand, Amount, BlockHeight, Id, Idable},
};
use crypto::vrf::VRFPublicKey;
use itertools::Itertools;
use pos_accounting::make_delegation_id;
use rpc_description::HasValueHint;
use tx_verifier::transaction_verifier::calculate_tokens_burned_in_outputs;
use utils::ensure;
use wallet_types::{
    currency::Currency,
    utxo_types::{get_utxo_state, UtxoState, UtxoStates},
    wallet_tx::{TxData, TxState},
    with_locked::WithLocked,
    AccountWalletTxId, BlockInfo, WalletTx,
};

use crate::{destination_getters::get_all_tx_output_destinations, WalletError, WalletResult};

pub type UtxoWithTxOutput<'a> = (UtxoOutPoint, (&'a TxOutput, Option<TokenId>));

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct TxInfo {
    pub id: Id<Transaction>,
    pub height: BlockHeight,
    pub timestamp: BlockTimestamp,
}

impl TxInfo {
    fn new(id: Id<Transaction>, height: BlockHeight, timestamp: BlockTimestamp) -> Self {
        Self {
            id,
            height,
            timestamp,
        }
    }
}

pub struct DelegationData {
    pub pool_id: PoolId,
    pub destination: Destination,
    pub last_nonce: Option<AccountNonce>,
    /// last parent transaction if the parent is unconfirmed
    pub last_parent: Option<OutPointSourceId>,
    pub not_staked_yet: bool,
}

impl DelegationData {
    fn new(pool_id: PoolId, destination: Destination) -> DelegationData {
        DelegationData {
            pool_id,
            destination,
            last_nonce: None,
            last_parent: None,
            not_staked_yet: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PoolData {
    pub utxo_outpoint: UtxoOutPoint,
    pub creation_block: BlockInfo,
    pub decommission_key: Destination,
    pub stake_destination: Destination,
    pub vrf_public_key: VRFPublicKey,
    pub margin_ratio_per_thousand: PerThousand,
    pub cost_per_block: Amount,
}

impl PoolData {
    fn new(
        utxo_outpoint: UtxoOutPoint,
        creation_block: BlockInfo,
        pool_data: &StakePoolData,
    ) -> Self {
        PoolData {
            utxo_outpoint,
            creation_block,
            decommission_key: pool_data.decommission_key().clone(),
            stake_destination: pool_data.staker().clone(),
            vrf_public_key: pool_data.vrf_public_key().clone(),
            margin_ratio_per_thousand: pool_data.margin_ratio_per_thousand(),
            cost_per_block: pool_data.cost_per_block(),
        }
    }
}

pub enum TokenCurrentSupplyState {
    Fixed(Amount, Amount),              // fixed to a certain amount
    Lockable(Amount), // not known in advance but can be locked once at some point in time
    Locked(#[allow(dead_code)] Amount), // Locked
    Unlimited(Amount), // limited only by the Amount data type
}

impl From<TokenTotalSupply> for TokenCurrentSupplyState {
    fn from(value: TokenTotalSupply) -> Self {
        match value {
            TokenTotalSupply::Fixed(amount) => TokenCurrentSupplyState::Fixed(amount, Amount::ZERO),
            TokenTotalSupply::Lockable => TokenCurrentSupplyState::Lockable(Amount::ZERO),
            TokenTotalSupply::Unlimited => TokenCurrentSupplyState::Unlimited(Amount::ZERO),
        }
    }
}

impl From<RPCTokenTotalSupply> for TokenCurrentSupplyState {
    fn from(value: RPCTokenTotalSupply) -> Self {
        match value {
            RPCTokenTotalSupply::Fixed { amount } => {
                TokenCurrentSupplyState::Fixed(amount, Amount::ZERO)
            }
            RPCTokenTotalSupply::Lockable => TokenCurrentSupplyState::Lockable(Amount::ZERO),
            RPCTokenTotalSupply::Unlimited => TokenCurrentSupplyState::Unlimited(Amount::ZERO),
        }
    }
}

impl TokenCurrentSupplyState {
    pub fn str_state(&self) -> &'static str {
        match self {
            Self::Unlimited(_) => "Unlimited",
            Self::Locked(_) => "Locked",
            Self::Lockable(_) => "Lockable",
            Self::Fixed(_, _) => "Fixed",
        }
    }

    #[cfg(test)]
    pub fn current_supply(&self) -> Amount {
        match self {
            Self::Unlimited(amount)
            | Self::Fixed(_, amount)
            | Self::Locked(amount)
            | Self::Lockable(amount) => *amount,
        }
    }

    pub fn check_can_mint(&self, amount: Amount) -> WalletResult<()> {
        match self {
            Self::Unlimited(_) | Self::Lockable(_) => Ok(()),
            Self::Fixed(max, current) => {
                let changed = current.add(amount).ok_or(WalletError::OutputAmountOverflow)?;
                ensure!(
                    changed <= *max,
                    WalletError::CannotMintFixedTokenSupply(*max, *current, amount)
                );
                Ok(())
            }
            Self::Locked(_) => Err(WalletError::CannotChangeLockedTokenSupply),
        }
    }

    pub fn check_can_unmint(&self, amount: Amount) -> WalletResult<()> {
        match self {
            Self::Unlimited(current) | Self::Lockable(current) | Self::Fixed(_, current) => {
                ensure!(
                    *current >= amount,
                    WalletError::CannotUnmintTokenSupply(amount, *current)
                );
                Ok(())
            }
            Self::Locked(_) => Err(WalletError::CannotChangeLockedTokenSupply),
        }
    }

    pub fn check_can_lock(&self) -> WalletResult<()> {
        match self {
            TokenCurrentSupplyState::Lockable(_) => Ok(()),
            TokenCurrentSupplyState::Unlimited(_)
            | TokenCurrentSupplyState::Fixed(_, _)
            | TokenCurrentSupplyState::Locked(_) => {
                Err(WalletError::CannotLockTokenSupply(self.str_state()))
            }
        }
    }

    fn mint(&self, amount: Amount) -> WalletResult<TokenCurrentSupplyState> {
        match self {
            TokenCurrentSupplyState::Lockable(current) => Ok(TokenCurrentSupplyState::Lockable(
                (*current + amount).ok_or(WalletError::OutputAmountOverflow)?,
            )),
            TokenCurrentSupplyState::Unlimited(current) => Ok(TokenCurrentSupplyState::Unlimited(
                (*current + amount).ok_or(WalletError::OutputAmountOverflow)?,
            )),
            TokenCurrentSupplyState::Fixed(max, current) => {
                let changed = (*current + amount).ok_or(WalletError::OutputAmountOverflow)?;
                ensure!(
                    changed <= *max,
                    WalletError::CannotMintFixedTokenSupply(*max, *current, amount)
                );
                Ok(TokenCurrentSupplyState::Fixed(*max, changed))
            }
            TokenCurrentSupplyState::Locked(_) => Err(WalletError::CannotChangeLockedTokenSupply),
        }
    }

    fn unmint(&self, amount: Amount) -> WalletResult<TokenCurrentSupplyState> {
        match self {
            TokenCurrentSupplyState::Lockable(current) => Ok(TokenCurrentSupplyState::Lockable(
                (*current - amount)
                    .ok_or(WalletError::CannotUnmintTokenSupply(amount, *current))?,
            )),
            TokenCurrentSupplyState::Unlimited(current) => Ok(TokenCurrentSupplyState::Unlimited(
                (*current - amount)
                    .ok_or(WalletError::CannotUnmintTokenSupply(amount, *current))?,
            )),
            TokenCurrentSupplyState::Fixed(max, current) => Ok(TokenCurrentSupplyState::Fixed(
                *max,
                (*current - amount)
                    .ok_or(WalletError::CannotUnmintTokenSupply(amount, *current))?,
            )),
            TokenCurrentSupplyState::Locked(_) => Err(WalletError::CannotChangeLockedTokenSupply),
        }
    }

    fn lock(&self) -> WalletResult<TokenCurrentSupplyState> {
        match self {
            TokenCurrentSupplyState::Lockable(current) => {
                Ok(TokenCurrentSupplyState::Locked(*current))
            }
            TokenCurrentSupplyState::Unlimited(_)
            | TokenCurrentSupplyState::Fixed(_, _)
            | TokenCurrentSupplyState::Locked(_) => {
                Err(WalletError::CannotLockTokenSupply(self.str_state()))
            }
        }
    }
}

pub struct FungibleTokenInfo {
    frozen: TokenFreezableState,
    last_nonce: Option<AccountNonce>,
    total_supply: TokenCurrentSupplyState,
    authority: Destination,
}

pub enum UnconfirmedTokenInfo {
    OwnFungibleToken(TokenId, FungibleTokenInfo),
    FungibleToken(TokenId, TokenFreezableState),
    NonFungibleToken(TokenId),
}

impl UnconfirmedTokenInfo {
    pub fn token_id(&self) -> &TokenId {
        match self {
            Self::OwnFungibleToken(token_id, _)
            | Self::FungibleToken(token_id, _)
            | Self::NonFungibleToken(token_id) => token_id,
        }
    }

    pub fn check_can_be_used(&self) -> WalletResult<()> {
        match self {
            Self::OwnFungibleToken(_, state) => state.frozen.check_can_be_used(),
            Self::FungibleToken(_, state) => state.check_can_be_used(),
            Self::NonFungibleToken(_) => Ok(()),
        }
    }

    pub fn check_can_freeze(&self) -> WalletResult<()> {
        match self {
            Self::OwnFungibleToken(_, state) => state.frozen.check_can_freeze(),
            Self::FungibleToken(token_id, _) => {
                Err(WalletError::CannotChangeNotOwnedToken(*token_id))
            }
            Self::NonFungibleToken(token_id) => {
                Err(WalletError::CannotChangeNonFungibleToken(*token_id))
            }
        }
    }

    pub fn check_can_unfreeze(&self) -> WalletResult<()> {
        match self {
            Self::OwnFungibleToken(_, state) => state.frozen.check_can_unfreeze(),
            Self::FungibleToken(token_id, _) => {
                Err(WalletError::CannotChangeNotOwnedToken(*token_id))
            }
            Self::NonFungibleToken(token_id) => {
                Err(WalletError::CannotChangeNonFungibleToken(*token_id))
            }
        }
    }

    pub fn get_next_nonce(&self) -> WalletResult<AccountNonce> {
        match self {
            Self::OwnFungibleToken(token_id, state) => state
                .last_nonce
                .map_or(Some(AccountNonce::new(0)), |nonce| nonce.increment())
                .ok_or(WalletError::TokenIssuanceNonceOverflow(*token_id)),
            Self::FungibleToken(token_id, _) => {
                Err(WalletError::CannotChangeNotOwnedToken(*token_id))
            }
            Self::NonFungibleToken(token_id) => {
                Err(WalletError::CannotChangeNonFungibleToken(*token_id))
            }
        }
    }

    pub fn authority(&self) -> WalletResult<&Destination> {
        match self {
            Self::OwnFungibleToken(_, state) => Ok(&state.authority),
            Self::FungibleToken(token_id, _) => {
                Err(WalletError::CannotChangeNotOwnedToken(*token_id))
            }
            Self::NonFungibleToken(token_id) => {
                Err(WalletError::CannotChangeNonFungibleToken(*token_id))
            }
        }
    }

    pub fn check_can_mint(&self, amount: Amount) -> WalletResult<()> {
        match self {
            Self::OwnFungibleToken(_, state) => state.total_supply.check_can_mint(amount),
            Self::FungibleToken(token_id, _) => {
                Err(WalletError::CannotChangeNotOwnedToken(*token_id))
            }
            Self::NonFungibleToken(token_id) => {
                Err(WalletError::CannotChangeNonFungibleToken(*token_id))
            }
        }
    }

    pub fn check_can_unmint(&self, amount: Amount) -> WalletResult<()> {
        match self {
            Self::OwnFungibleToken(_, state) => state.total_supply.check_can_unmint(amount),
            Self::FungibleToken(token_id, _) => {
                Err(WalletError::CannotChangeNotOwnedToken(*token_id))
            }
            Self::NonFungibleToken(token_id) => {
                Err(WalletError::CannotChangeNonFungibleToken(*token_id))
            }
        }
    }

    pub fn check_can_lock(&self) -> WalletResult<()> {
        match self {
            Self::OwnFungibleToken(_, state) => state.total_supply.check_can_lock(),
            Self::FungibleToken(token_id, _) => {
                Err(WalletError::CannotChangeNotOwnedToken(*token_id))
            }
            Self::NonFungibleToken(token_id) => {
                Err(WalletError::CannotChangeNonFungibleToken(*token_id))
            }
        }
    }

    #[cfg(test)]
    pub fn current_supply(&self) -> Option<Amount> {
        match self {
            Self::OwnFungibleToken(_, state) => Some(state.total_supply.current_supply()),
            Self::FungibleToken(_, _) => None,
            Self::NonFungibleToken(_) => None,
        }
    }
}

pub enum TokenFreezableState {
    NotFrozen(IsTokenFreezable),
    Frozen(IsTokenUnfreezable),
}

impl From<RPCIsTokenFrozen> for TokenFreezableState {
    fn from(value: RPCIsTokenFrozen) -> Self {
        match value {
            RPCIsTokenFrozen::NotFrozen { freezable } => match freezable {
                false => Self::NotFrozen(IsTokenFreezable::No),
                true => Self::NotFrozen(IsTokenFreezable::Yes),
            },
            RPCIsTokenFrozen::Frozen { unfreezable } => match unfreezable {
                false => Self::Frozen(IsTokenUnfreezable::No),
                true => Self::Frozen(IsTokenUnfreezable::Yes),
            },
        }
    }
}

impl TokenFreezableState {
    pub fn check_can_be_used(&self) -> WalletResult<()> {
        match self {
            Self::Frozen(_) => Err(WalletError::CannotUseFrozenToken),
            Self::NotFrozen(_) => Ok(()),
        }
    }

    fn freeze(&self, is_unfreezable: IsTokenUnfreezable) -> WalletResult<Self> {
        match self {
            Self::NotFrozen(IsTokenFreezable::Yes) => Ok(Self::Frozen(is_unfreezable)),
            Self::NotFrozen(IsTokenFreezable::No) => {
                Err(WalletError::CannotFreezeNotFreezableToken)
            }
            Self::Frozen(_) => Err(WalletError::CannotFreezeAlreadyFrozenToken),
        }
    }

    pub fn check_can_freeze(&self) -> WalletResult<()> {
        match self {
            Self::NotFrozen(IsTokenFreezable::Yes) => Ok(()),
            Self::NotFrozen(IsTokenFreezable::No) => {
                Err(WalletError::CannotFreezeNotFreezableToken)
            }
            Self::Frozen(_) => Err(WalletError::CannotFreezeAlreadyFrozenToken),
        }
    }

    fn unfreeze(&self) -> WalletResult<Self> {
        match self {
            Self::Frozen(IsTokenUnfreezable::Yes) => Ok(Self::NotFrozen(IsTokenFreezable::Yes)),
            Self::Frozen(IsTokenUnfreezable::No) => Err(WalletError::CannotUnfreezeToken),
            Self::NotFrozen(_) => Err(WalletError::CannotUnfreezeANotFrozenToken),
        }
    }

    pub fn check_can_unfreeze(&self) -> WalletResult<()> {
        match self {
            Self::Frozen(IsTokenUnfreezable::Yes) => Ok(()),
            Self::Frozen(IsTokenUnfreezable::No) => Err(WalletError::CannotUnfreezeToken),
            Self::NotFrozen(_) => Err(WalletError::CannotUnfreezeANotFrozenToken),
        }
    }
}

#[derive(Debug)]
pub struct TokenIssuanceData {
    pub authority: Destination,
    pub last_nonce: Option<AccountNonce>,

    /// last parent transaction if the parent is unconfirmed
    pub last_parent: Option<OutPointSourceId>,

    /// unconfirmed transactions that modify the total supply or frozen state of this token
    unconfirmed_txs: BTreeSet<OutPointSourceId>,
}

impl TokenIssuanceData {
    fn new(authority: Destination) -> Self {
        Self {
            authority,
            last_nonce: None,
            last_parent: None,
            unconfirmed_txs: BTreeSet::new(),
        }
    }
}

pub struct OrderData {
    pub conclude_key: Destination,
    pub give_currency: Currency,
    pub ask_currency: Currency,

    pub last_nonce: Option<AccountNonce>,
    /// last parent transaction if the parent is unconfirmed
    pub last_parent: Option<OutPointSourceId>,
}

impl OrderData {
    pub fn new(conclude_key: Destination, give_currency: Currency, ask_currency: Currency) -> Self {
        Self {
            conclude_key,
            give_currency,
            ask_currency,
            last_nonce: None,
            last_parent: None,
        }
    }
}

/// A helper structure for the UTXO search.
///
/// All transactions and blocks from the DB are cached here. If a transaction
/// consumes a wallet input (send transaction) or produces a wallet output
/// (receive transaction), it's stored in the DB and cached here. To find all UTXOs,
/// all transaction/block outputs are collected. Then, from all these outputs,
/// we remove all outputs that are consumed by the same locally stored
/// transactions and blocks. Then we filter the outputs that are from our wallet
/// (can be signed) to get the final UTXO list that is ready to use.
/// In case of reorg, top blocks (and the transactions they contain) are simply removed from the DB/cache.
/// A similar approach is used by the Bitcoin Core wallet.
pub struct OutputCache {
    txs: BTreeMap<OutPointSourceId, WalletTx>,
    consumed: BTreeMap<UtxoOutPoint, TxState>,
    unconfirmed_descendants: BTreeMap<OutPointSourceId, BTreeSet<OutPointSourceId>>,
    pools: BTreeMap<PoolId, PoolData>,
    delegations: BTreeMap<DelegationId, DelegationData>,
    token_issuance: BTreeMap<TokenId, TokenIssuanceData>,
    orders: BTreeMap<OrderId, OrderData>,
}

impl OutputCache {
    pub fn empty() -> Self {
        Self {
            txs: BTreeMap::new(),
            consumed: BTreeMap::new(),
            unconfirmed_descendants: BTreeMap::new(),
            pools: BTreeMap::new(),
            delegations: BTreeMap::new(),
            token_issuance: BTreeMap::new(),
            orders: BTreeMap::new(),
        }
    }

    pub fn new(mut txs: Vec<(AccountWalletTxId, WalletTx)>) -> WalletResult<Self> {
        let mut cache = Self::empty();

        txs.sort_by(|x, y| wallet_tx_order(&x.1, &y.1));
        for (tx_id, tx) in txs {
            cache.add_tx(tx_id.into_item_id(), tx)?;
        }
        Ok(cache)
    }

    pub fn txs_with_unconfirmed(&self) -> &BTreeMap<OutPointSourceId, WalletTx> {
        &self.txs
    }

    pub fn has_confirmed_transactions(&self) -> bool {
        self.txs.values().any(|tx| match tx.state() {
            TxState::Inactive(_)
            | TxState::InMempool(_)
            | TxState::Conflicted(_)
            | TxState::Abandoned => false,
            TxState::Confirmed(_, _, _) => true,
        })
    }

    pub fn get_txo(&self, outpoint: &UtxoOutPoint) -> Option<&TxOutput> {
        self.txs
            .get(&outpoint.source_id())
            .and_then(|tx| tx.outputs().get(outpoint.output_index() as usize))
    }

    pub fn pool_ids(&self) -> Vec<(PoolId, PoolData)> {
        self.pools
            .iter()
            .filter_map(|(pool_id, pool_data)| {
                (!self.consumed.contains_key(&pool_data.utxo_outpoint))
                    .then_some((*pool_id, (*pool_data).clone()))
            })
            .collect()
    }

    fn is_txo_for_pool_id(pool_id_to_find: PoolId, output: &TxOutput) -> bool {
        match output {
            TxOutput::CreateStakePool(pool_id, _) | TxOutput::ProduceBlockFromStake(_, pool_id) => {
                *pool_id == pool_id_to_find
            }
            TxOutput::Burn(_)
            | TxOutput::Transfer(_, _)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::DataDeposit(_)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::Htlc(_, _)
            | TxOutput::CreateOrder(_) => false,
        }
    }

    fn find_latest_utxo_for_pool(&self, pool_id: PoolId) -> Option<UtxoOutPoint> {
        self.txs
            .values()
            .flat_map(|tx| {
                tx.outputs()
                    .iter()
                    .enumerate()
                    .map(|(idx, output)| (output, UtxoOutPoint::new(tx.id(), idx as u32)))
                    .filter(move |(_output, outpoint)| !self.consumed.contains_key(outpoint))
            })
            .find_map(|(output, outpoint)| {
                Self::is_txo_for_pool_id(pool_id, output).then_some(outpoint)
            })
    }

    pub fn pool_data(&self, pool_id: PoolId) -> WalletResult<&PoolData> {
        self.pools.get(&pool_id).ok_or(WalletError::UnknownPoolId(pool_id))
    }

    pub fn delegation_ids(&self) -> impl Iterator<Item = (&DelegationId, &DelegationData)> {
        self.delegations.iter()
    }

    pub fn delegation_data(&self, delegation_id: &DelegationId) -> Option<&DelegationData> {
        self.delegations.get(delegation_id)
    }

    pub fn token_data(&self, token_id: &TokenId) -> Option<&TokenIssuanceData> {
        self.token_issuance.get(token_id)
    }

    pub fn order_data(&self, order_id: &OrderId) -> Option<&OrderData> {
        self.orders.get(order_id)
    }

    pub fn get_token_unconfirmed_info<F: Fn(&Destination) -> bool>(
        &self,
        token_info: &RPCFungibleTokenInfo,
        is_mine: F,
    ) -> WalletResult<UnconfirmedTokenInfo> {
        let token_data = match self.token_issuance.get(&token_info.token_id) {
            Some(token_data) => {
                if !is_mine(&token_data.authority) {
                    return Ok(UnconfirmedTokenInfo::FungibleToken(
                        token_info.token_id,
                        token_info.frozen.into(),
                    ));
                }
                token_data
            }
            // If it is not ours just return what is in the token_info
            None => {
                return Ok(UnconfirmedTokenInfo::FungibleToken(
                    token_info.token_id,
                    token_info.frozen.into(),
                ));
            }
        };

        let unconfirmed_txs = token_data
            .unconfirmed_txs
            .iter()
            .map(|tx_id| self.txs.get(tx_id).expect("tx must be present"))
            .sorted_by(|x, y| wallet_tx_order(x, y))
            .collect_vec();

        let mut frozen_state = token_info.frozen.into();
        let mut total_supply: TokenCurrentSupplyState = token_info.total_supply.into();
        total_supply = total_supply.mint(token_info.circulating_supply)?;
        if token_info.is_locked {
            total_supply = total_supply.lock()?;
        }

        for tx in unconfirmed_txs {
            frozen_state = apply_freeze_mutations_from_tx(frozen_state, tx, &token_info.token_id)?;
            total_supply =
                apply_total_supply_mutations_from_tx(total_supply, tx, &token_info.token_id)?;
        }

        Ok(UnconfirmedTokenInfo::OwnFungibleToken(
            token_info.token_id,
            FungibleTokenInfo {
                frozen: frozen_state,
                last_nonce: token_data.last_nonce,
                total_supply,
                authority: token_data.authority.clone(),
            },
        ))
    }

    pub fn check_conflicting(&mut self, tx: &WalletTx, block_id: Id<GenBlock>) -> Vec<&WalletTx> {
        let is_unconfirmed = match tx.state() {
            TxState::Inactive(_)
            | TxState::InMempool(_)
            | TxState::Conflicted(_)
            | TxState::Abandoned => true,
            TxState::Confirmed(_, _, _) => false,
        };

        if is_unconfirmed {
            return vec![];
        }

        let frozen_token_id = tx.inputs().iter().find_map(|inp| match inp {
            TxInput::Utxo(_) | TxInput::Account(_) => None,
            TxInput::AccountCommand(_, cmd) => match cmd {
                AccountCommand::MintTokens(_, _)
                | AccountCommand::UnmintTokens(_)
                | AccountCommand::LockTokenSupply(_)
                | AccountCommand::ChangeTokenMetadataUri(_, _)
                | AccountCommand::ChangeTokenAuthority(_, _)
                | AccountCommand::UnfreezeToken(_)
                | AccountCommand::ConcludeOrder(_)
                | AccountCommand::FillOrder(_, _, _) => None,
                AccountCommand::FreezeToken(frozen_token_id, _) => Some(frozen_token_id),
            },
        });

        let mut conflicting_txs = vec![];
        if let Some(frozen_token_id) = frozen_token_id {
            for unconfirmed in self.unconfirmed_descendants.keys() {
                let unconfirmed_tx = self.txs.get(unconfirmed).expect("must be present");
                if self.uses_token(unconfirmed_tx, frozen_token_id) {
                    let unconfirmed_tx = self.txs.get_mut(unconfirmed).expect("must be present");
                    match unconfirmed_tx {
                        WalletTx::Tx(ref mut tx) => {
                            tx.set_state(TxState::Conflicted(block_id));
                        }
                        WalletTx::Block(_) => {}
                    };

                    conflicting_txs.push(unconfirmed);
                }
            }
        }

        conflicting_txs
            .into_iter()
            .map(|tx_id| self.txs.get(tx_id).expect("must be present"))
            .collect_vec()
    }

    fn uses_token(&self, unconfirmed_tx: &WalletTx, frozen_token_id: &TokenId) -> bool {
        unconfirmed_tx.inputs().iter().any(|inp| match inp {
            TxInput::Utxo(outpoint) => self.txs.get(&outpoint.source_id()).is_some_and(|tx| {
                let output =
                    tx.outputs().get(outpoint.output_index() as usize).expect("must be present");

                match output {
                    TxOutput::Transfer(v, _)
                    | TxOutput::LockThenTransfer(v, _, _)
                    | TxOutput::Burn(v)
                    | TxOutput::Htlc(v, _) => match v {
                        OutputValue::TokenV1(token_id, _) => frozen_token_id == token_id,
                        OutputValue::TokenV0(_) | OutputValue::Coin(_) => false,
                    },
                    TxOutput::CreateOrder(data) => {
                        [data.ask(), data.give()].iter().any(|v| match v {
                            OutputValue::TokenV1(token_id, _) => frozen_token_id == token_id,
                            OutputValue::TokenV0(_) | OutputValue::Coin(_) => false,
                        })
                    }
                    TxOutput::IssueNft(_, _, _)
                    | TxOutput::DataDeposit(_)
                    | TxOutput::CreateStakePool(_, _)
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::CreateDelegationId(_, _)
                    | TxOutput::IssueFungibleToken(_)
                    | TxOutput::ProduceBlockFromStake(_, _) => false,
                }
            }),
            TxInput::AccountCommand(_, cmd) => match cmd {
                AccountCommand::LockTokenSupply(token_id)
                | AccountCommand::MintTokens(token_id, _)
                | AccountCommand::FreezeToken(token_id, _)
                | AccountCommand::UnfreezeToken(token_id)
                | AccountCommand::ChangeTokenMetadataUri(token_id, _)
                | AccountCommand::ChangeTokenAuthority(token_id, _)
                | AccountCommand::UnmintTokens(token_id) => frozen_token_id == token_id,
                AccountCommand::ConcludeOrder(order_id)
                | AccountCommand::FillOrder(order_id, _, _) => {
                    self.order_data(order_id).is_some_and(|data| {
                        [data.ask_currency, data.give_currency].iter().any(|v| match v {
                            Currency::Coin => false,
                            Currency::Token(token_id) => frozen_token_id == token_id,
                        })
                    })
                }
            },
            TxInput::Account(_) => false,
        })
    }

    pub fn add_tx(&mut self, tx_id: OutPointSourceId, tx: WalletTx) -> WalletResult<()> {
        let already_present = self.txs.get(&tx_id).is_some_and(|tx| !tx.state().is_abandoned());
        let is_unconfirmed = match tx.state() {
            TxState::Inactive(_)
            | TxState::InMempool(_)
            | TxState::Conflicted(_)
            | TxState::Abandoned => true,
            TxState::Confirmed(_, _, _) => false,
        };
        if is_unconfirmed && !already_present {
            self.unconfirmed_descendants.insert(tx_id.clone(), BTreeSet::new());
        }

        self.update_inputs(&tx, is_unconfirmed, &tx_id, already_present)?;

        self.update_outputs(&tx, get_block_info(&tx), already_present)?;

        self.txs.insert(tx_id, tx);
        Ok(())
    }

    /// Update the pool states for a newly confirmed transaction
    fn update_outputs(
        &mut self,
        tx: &WalletTx,
        block_info: Option<BlockInfo>,
        already_present: bool,
    ) -> Result<(), WalletError> {
        for (idx, output) in tx.outputs().iter().enumerate() {
            match output {
                TxOutput::ProduceBlockFromStake(_, pool_id) => {
                    if let Some(pool_data) = self.pools.get_mut(pool_id) {
                        pool_data.utxo_outpoint = UtxoOutPoint::new(tx.id(), idx as u32)
                    } else {
                        return Err(WalletError::InconsistentProduceBlockFromStake(*pool_id));
                    }
                }
                TxOutput::CreateStakePool(pool_id, data) => {
                    if let Some(block_info) = block_info {
                        self.pools
                            .entry(*pool_id)
                            .and_modify(|entry| {
                                entry.utxo_outpoint = UtxoOutPoint::new(tx.id(), idx as u32)
                            })
                            .or_insert_with(|| {
                                PoolData::new(
                                    UtxoOutPoint::new(tx.id(), idx as u32),
                                    block_info,
                                    data,
                                )
                            });
                    }
                }
                TxOutput::DelegateStaking(_, delegation_id) => {
                    if block_info.is_none() {
                        continue;
                    }
                    if let Some(delegation_data) = self.delegations.get_mut(delegation_id) {
                        delegation_data.not_staked_yet = false;
                    }
                    // Else it is not ours
                }
                TxOutput::CreateDelegationId(destination, pool_id) => {
                    if block_info.is_none() {
                        continue;
                    }
                    let input0_outpoint = crate::utils::get_first_utxo_outpoint(tx.inputs())?;
                    let delegation_id = make_delegation_id(input0_outpoint);
                    self.delegations.insert(
                        delegation_id,
                        DelegationData::new(*pool_id, destination.clone()),
                    );
                }
                | TxOutput::Burn(_)
                | TxOutput::DataDeposit(_)
                | TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::Htlc(_, _) => {}
                TxOutput::IssueFungibleToken(issuance) => {
                    if already_present {
                        continue;
                    }
                    let token_id = make_token_id(tx.inputs()).ok_or(WalletError::NoUtxos)?;
                    match issuance.as_ref() {
                        TokenIssuance::V1(data) => {
                            self.token_issuance
                                .insert(token_id, TokenIssuanceData::new(data.authority.clone()));
                        }
                    }
                }
                TxOutput::IssueNft(_, _, _) => {}
                TxOutput::CreateOrder(order_data) => {
                    let input0_outpoint = crate::utils::get_first_utxo_outpoint(tx.inputs())?;
                    let order_id = make_order_id(input0_outpoint);
                    let give_currency = Currency::from_output_value(order_data.give())
                        .ok_or(WalletError::TokenV0(tx.id()))?;
                    let ask_currency = Currency::from_output_value(order_data.ask())
                        .ok_or(WalletError::TokenV0(tx.id()))?;
                    self.orders.insert(
                        order_id,
                        OrderData::new(
                            order_data.conclude_key().clone(),
                            give_currency,
                            ask_currency,
                        ),
                    );
                }
            };
        }
        Ok(())
    }

    /// Update the inputs for a new transaction, mark them as consumed and update delegation account
    /// balances
    fn update_inputs(
        &mut self,
        tx: &WalletTx,
        is_unconfirmed: bool,
        tx_id: &OutPointSourceId,
        already_present: bool,
    ) -> Result<(), WalletError> {
        for input in tx.inputs() {
            match input {
                TxInput::Utxo(outpoint) => {
                    self.consumed.insert(outpoint.clone(), tx.state());
                    if is_unconfirmed {
                        self.unconfirmed_descendants
                            .get_mut(&outpoint.source_id())
                            .as_mut()
                            .map(|descendants| descendants.insert(tx_id.clone()));
                    } else {
                        self.unconfirmed_descendants.remove(tx_id);
                    }
                }
                TxInput::Account(outpoint) => match outpoint.account() {
                    AccountSpending::DelegationBalance(delegation_id, _) => {
                        if !already_present {
                            if let Some(data) = self.delegations.get_mut(delegation_id) {
                                Self::update_delegation_state(
                                    &mut self.unconfirmed_descendants,
                                    data,
                                    delegation_id,
                                    outpoint.nonce(),
                                    tx_id,
                                )?;
                            }
                        }
                    }
                },
                TxInput::AccountCommand(nonce, op) => match op {
                    AccountCommand::MintTokens(token_id, _)
                    | AccountCommand::UnmintTokens(token_id)
                    | AccountCommand::LockTokenSupply(token_id)
                    | AccountCommand::FreezeToken(token_id, _)
                    | AccountCommand::UnfreezeToken(token_id)
                    | AccountCommand::ChangeTokenMetadataUri(token_id, _) => {
                        if let Some(data) = self.token_issuance.get_mut(token_id) {
                            if !already_present {
                                Self::update_token_issuance_state(
                                    &mut self.unconfirmed_descendants,
                                    data,
                                    token_id,
                                    *nonce,
                                    tx_id,
                                )?;
                            }
                            if is_unconfirmed {
                                data.unconfirmed_txs.insert(tx_id.clone());
                            } else {
                                data.unconfirmed_txs.remove(tx_id);
                            }
                        }
                    }
                    AccountCommand::ChangeTokenAuthority(token_id, authority) => {
                        if let Some(data) = self.token_issuance.get_mut(token_id) {
                            if !already_present {
                                Self::update_token_issuance_state(
                                    &mut self.unconfirmed_descendants,
                                    data,
                                    token_id,
                                    *nonce,
                                    tx_id,
                                )?;
                                data.authority = authority.clone();
                            }
                            if is_unconfirmed {
                                data.unconfirmed_txs.insert(tx_id.clone());
                            } else {
                                data.unconfirmed_txs.remove(tx_id);
                            }
                        } else if !is_unconfirmed {
                            let mut data = TokenIssuanceData::new(authority.clone());
                            data.last_nonce = Some(*nonce);
                            self.token_issuance.insert(*token_id, data);
                        }
                    }
                    AccountCommand::ConcludeOrder(order_id)
                    | AccountCommand::FillOrder(order_id, _, _) => {
                        if !already_present {
                            if let Some(data) = self.orders.get_mut(order_id) {
                                Self::update_order_state(
                                    &mut self.unconfirmed_descendants,
                                    data,
                                    order_id,
                                    *nonce,
                                    tx_id,
                                )?;
                            }
                        }
                    }
                },
            }
        }
        Ok(())
    }

    /// Update delegation state with new tx input
    fn update_delegation_state(
        unconfirmed_descendants: &mut BTreeMap<OutPointSourceId, BTreeSet<OutPointSourceId>>,
        data: &mut DelegationData,
        delegation_id: &DelegationId,
        delegation_nonce: AccountNonce,
        tx_id: &OutPointSourceId,
    ) -> Result<(), WalletError> {
        let next_nonce = data
            .last_nonce
            .map_or(Some(AccountNonce::new(0)), |nonce| nonce.increment())
            .ok_or(WalletError::DelegationNonceOverflow(*delegation_id))?;

        ensure!(
            delegation_nonce == next_nonce,
            WalletError::InconsistentDelegationDuplicateNonce(*delegation_id, delegation_nonce)
        );

        data.last_nonce = Some(delegation_nonce);
        // update unconfirmed descendants
        if let Some(descendants) = data
            .last_parent
            .as_ref()
            .and_then(|parent_tx_id| unconfirmed_descendants.get_mut(parent_tx_id))
        {
            descendants.insert(tx_id.clone());
        }
        data.last_parent = Some(tx_id.clone());
        Ok(())
    }

    /// Update token issuance state with new tx input
    fn update_token_issuance_state(
        unconfirmed_descendants: &mut BTreeMap<OutPointSourceId, BTreeSet<OutPointSourceId>>,
        data: &mut TokenIssuanceData,
        delegation_id: &TokenId,
        token_nonce: AccountNonce,
        tx_id: &OutPointSourceId,
    ) -> Result<(), WalletError> {
        let next_nonce = data
            .last_nonce
            .map_or(Some(AccountNonce::new(0)), |nonce| nonce.increment())
            .ok_or(WalletError::TokenIssuanceNonceOverflow(*delegation_id))?;

        ensure!(
            token_nonce == next_nonce,
            WalletError::InconsistentTokenIssuanceDuplicateNonce(*delegation_id, token_nonce)
        );

        data.last_nonce = Some(token_nonce);
        // update unconfirmed descendants
        if let Some(descendants) = data
            .last_parent
            .as_ref()
            .and_then(|parent_tx_id| unconfirmed_descendants.get_mut(parent_tx_id))
        {
            descendants.insert(tx_id.clone());
        }
        data.last_parent = Some(tx_id.clone());
        Ok(())
    }

    /// Update order state with new tx input
    fn update_order_state(
        unconfirmed_descendants: &mut BTreeMap<OutPointSourceId, BTreeSet<OutPointSourceId>>,
        data: &mut OrderData,
        order_id: &OrderId,
        nonce: AccountNonce,
        tx_id: &OutPointSourceId,
    ) -> Result<(), WalletError> {
        let next_nonce = data
            .last_nonce
            .map_or(Some(AccountNonce::new(0)), |nonce| nonce.increment())
            .ok_or(WalletError::OrderNonceOverflow(*order_id))?;

        ensure!(
            nonce == next_nonce,
            WalletError::InconsistentOrderDuplicateNonce(*order_id, nonce)
        );

        data.last_nonce = Some(nonce);
        // update unconfirmed descendants
        if let Some(descendants) = data
            .last_parent
            .as_ref()
            .and_then(|parent_tx_id| unconfirmed_descendants.get_mut(parent_tx_id))
        {
            descendants.insert(tx_id.clone());
        }
        data.last_parent = Some(tx_id.clone());
        Ok(())
    }

    pub fn remove_tx(&mut self, tx_id: &OutPointSourceId) -> WalletResult<()> {
        let tx_opt = self.txs.remove(tx_id);
        if let Some(tx) = tx_opt {
            for input in tx.inputs() {
                match input {
                    TxInput::Utxo(outpoint) => {
                        self.consumed.remove(outpoint);
                        self.unconfirmed_descendants.remove(tx_id);
                    }
                    TxInput::Account(outpoint) => match outpoint.account() {
                        AccountSpending::DelegationBalance(delegation_id, _) => {
                            if let Some(data) = self.delegations.get_mut(delegation_id) {
                                data.last_nonce = outpoint.nonce().decrement();
                                data.last_parent =
                                    find_parent(&self.unconfirmed_descendants, tx_id.clone());
                            }
                        }
                    },
                    TxInput::AccountCommand(nonce, op) => match op {
                        AccountCommand::MintTokens(token_id, _)
                        | AccountCommand::UnmintTokens(token_id)
                        | AccountCommand::LockTokenSupply(token_id)
                        | AccountCommand::FreezeToken(token_id, _)
                        | AccountCommand::UnfreezeToken(token_id)
                        | AccountCommand::ChangeTokenMetadataUri(token_id, _)
                        | AccountCommand::ChangeTokenAuthority(token_id, _) => {
                            if let Some(data) = self.token_issuance.get_mut(token_id) {
                                data.last_nonce = nonce.decrement();
                                data.last_parent =
                                    find_parent(&self.unconfirmed_descendants, tx_id.clone());
                                data.unconfirmed_txs.remove(tx_id);
                            }
                        }
                        AccountCommand::ConcludeOrder(order_id)
                        | AccountCommand::FillOrder(order_id, _, _) => {
                            if let Some(data) = self.orders.get_mut(order_id) {
                                data.last_nonce = nonce.decrement();
                                data.last_parent =
                                    find_parent(&self.unconfirmed_descendants, tx_id.clone());
                            }
                        }
                    },
                }
            }
            for output in tx.outputs() {
                match output {
                    TxOutput::CreateStakePool(pool_id, _) => {
                        self.pools.remove(pool_id);
                    }
                    TxOutput::ProduceBlockFromStake(_, pool_id) => {
                        if self.pools.contains_key(pool_id) {
                            let latest_utxo = self.find_latest_utxo_for_pool(*pool_id);
                            if let Some(pool_data) = self.pools.get_mut(pool_id) {
                                pool_data.utxo_outpoint = latest_utxo.expect("must be present");
                            }
                        }
                    }
                    TxOutput::Burn(_)
                    | TxOutput::Transfer(_, _)
                    | TxOutput::IssueNft(_, _, _)
                    | TxOutput::DataDeposit(_)
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::LockThenTransfer(_, _, _)
                    | TxOutput::CreateDelegationId(_, _)
                    | TxOutput::IssueFungibleToken(_)
                    | TxOutput::Htlc(_, _)
                    | TxOutput::CreateOrder(_) => {}
                }
            }
        }
        Ok(())
    }

    fn is_consumed(&self, utxo_states: UtxoStates, outpoint: &UtxoOutPoint) -> bool {
        self.consumed
            .get(outpoint)
            .is_some_and(|consumed_state| utxo_states.contains(get_utxo_state(consumed_state)))
    }

    pub fn find_unspent_unlocked_utxo(
        &self,
        utxo: &UtxoOutPoint,
        current_block_info: BlockInfo,
    ) -> WalletResult<(&TxOutput, Option<TokenId>)> {
        let tx = self
            .txs
            .get(&utxo.source_id())
            .ok_or(WalletError::CannotFindUtxo(utxo.clone()))?;
        let tx_block_info = get_block_info(tx);
        let output = tx
            .outputs()
            .get(utxo.output_index() as usize)
            .ok_or(WalletError::CannotFindUtxo(utxo.clone()))?;

        ensure!(
            !self.is_consumed(
                UtxoState::Confirmed | UtxoState::InMempool | UtxoState::Inactive,
                utxo,
            ),
            WalletError::ConsumedUtxo(utxo.clone())
        );

        ensure!(
            is_specific_lock_state(
                WithLocked::Unlocked,
                output,
                current_block_info,
                tx_block_info,
                utxo,
            ),
            WalletError::LockedUtxo(utxo.clone())
        );

        ensure!(
            !is_v0_token_output(output),
            WalletError::TokenV0Utxo(utxo.clone())
        );

        let token_id = match tx {
            WalletTx::Tx(tx_data) => is_token_or_nft_issuance(output)
                .then_some(make_token_id(tx_data.get_transaction().inputs()))
                .flatten(),
            WalletTx::Block(_) => None,
        };

        Ok((output, token_id))
    }

    pub fn find_used_tokens(
        &self,
        current_block_info: BlockInfo,
        inputs: &[UtxoOutPoint],
    ) -> WalletResult<BTreeSet<TokenId>> {
        inputs
            .iter()
            .filter_map(|utxo| {
                self.find_unspent_unlocked_utxo(utxo, current_block_info)
                    .map(|(_, token_id)| token_id)
                    .transpose()
            })
            .collect()
    }

    pub fn find_utxos(
        &self,
        current_block_info: BlockInfo,
        inputs: Vec<UtxoOutPoint>,
    ) -> WalletResult<Vec<UtxoWithTxOutput>> {
        inputs
            .into_iter()
            .map(|utxo| {
                self.find_unspent_unlocked_utxo(&utxo, current_block_info)
                    .map(|res| (utxo, res))
            })
            .collect()
    }

    pub fn utxos_with_token_ids<F: Fn(&TxOutput) -> bool>(
        &self,
        current_block_info: BlockInfo,
        utxo_states: UtxoStates,
        locked_state: WithLocked,
        output_filter: F,
    ) -> Vec<(UtxoOutPoint, (&TxOutput, Option<TokenId>))> {
        let output_filter = &output_filter;
        self.txs
            .values()
            .filter(|tx| is_in_state(tx, utxo_states))
            .flat_map(|tx| {
                let tx_block_info = get_block_info(tx);

                tx.outputs()
                    .iter()
                    .enumerate()
                    .map(|(idx, output)| (output, UtxoOutPoint::new(tx.id(), idx as u32)))
                    .filter(move |(output, outpoint)| {
                        !self.is_consumed(utxo_states, outpoint)
                            && is_specific_lock_state(
                                locked_state,
                                output,
                                current_block_info,
                                tx_block_info,
                                outpoint,
                            )
                            && !is_v0_token_output(output)
                            && output_filter(output)
                    })
                    .map(move |(output, outpoint)| {
                        let token_id = match tx {
                            WalletTx::Tx(tx_data) => is_token_or_nft_issuance(output)
                                .then_some(make_token_id(tx_data.get_transaction().inputs()))
                                .flatten(),
                            WalletTx::Block(_) => None,
                        };
                        (outpoint, (output, token_id))
                    })
            })
            .collect()
    }

    pub fn pending_transactions(&self) -> Vec<WithId<&Transaction>> {
        self.txs
            .values()
            .filter_map(|tx| match tx {
                WalletTx::Block(_) => None,
                WalletTx::Tx(tx) => match tx.state() {
                    TxState::Inactive(_) | TxState::Conflicted(_) => {
                        Some(tx.get_transaction_with_id())
                    }
                    TxState::Confirmed(_, _, _) | TxState::InMempool(_) | TxState::Abandoned => {
                        None
                    }
                },
            })
            .collect()
    }

    pub fn mainchain_transactions(
        &self,
        destination: Option<Destination>,
        limit: usize,
    ) -> Vec<TxInfo> {
        let mut txs: Vec<&WalletTx> = self.txs.values().collect();
        txs.sort_by_key(|tx| Reverse((tx.state().block_height(), tx.state().block_order_index())));

        txs.iter()
            .filter_map(|tx| match tx {
                WalletTx::Block(_) => None,
                WalletTx::Tx(tx) => match tx.state() {
                    TxState::Confirmed(block_height, timestamp, _) => {
                        let tx_with_id = tx.get_transaction_with_id();
                        if let Some(dest) = &destination {
                            (self.destination_in_tx_outputs(&tx_with_id, dest)
                                || self.destination_in_tx_inputs(&tx_with_id, dest))
                            .then_some(TxInfo::new(tx_with_id.get_id(), *block_height, *timestamp))
                        } else {
                            Some(TxInfo::new(tx_with_id.get_id(), *block_height, *timestamp))
                        }
                    }
                    TxState::Inactive(_)
                    | TxState::Conflicted(_)
                    | TxState::InMempool(_)
                    | TxState::Abandoned => None,
                },
            })
            .take(limit)
            .collect()
    }

    /// Returns true if the destination is found in the transaction's inputs
    fn destination_in_tx_inputs(&self, tx: &WithId<&Transaction>, dest: &Destination) -> bool {
        tx.inputs().iter().any(|inp| match inp {
            TxInput::Utxo(utxo) => self
                .txs
                .get(&utxo.source_id())
                .and_then(|tx| tx.outputs().get(utxo.output_index() as usize))
                .and_then(|txo| {
                    get_all_tx_output_destinations(txo, &|pool_id| self.pools.get(pool_id))
                })
                .is_some_and(|output_dest| output_dest.contains(dest)),
            TxInput::Account(_) | TxInput::AccountCommand(_, _) => false,
        })
    }

    /// Returns true if the destination is found in the transaction's outputs
    fn destination_in_tx_outputs(&self, tx: &WithId<&Transaction>, dest: &Destination) -> bool {
        tx.outputs().iter().any(|txo| {
            get_all_tx_output_destinations(txo, &|pool_id| self.pools.get(pool_id))
                .is_some_and(|output_dest| output_dest.contains(dest))
        })
    }

    /// Mark a transaction and its descendants as abandoned
    /// Returns a Vec of the transaction Ids that have been abandoned
    pub fn abandon_transaction(
        &mut self,
        tx_id: Id<Transaction>,
    ) -> WalletResult<Vec<Id<Transaction>>> {
        let mut all_abandoned = Vec::new();
        let mut to_abandon = BTreeSet::from_iter([OutPointSourceId::from(tx_id)]);

        while let Some(outpoint_source_id) = to_abandon.pop_first() {
            all_abandoned.push(*outpoint_source_id.get_tx_id().expect("must be a transaction"));

            if let Some(descendants) = self.unconfirmed_descendants.remove(&outpoint_source_id) {
                to_abandon.extend(descendants.into_iter())
            }
        }

        for tx_id in all_abandoned.iter().rev().copied() {
            match self.txs.entry(tx_id.into()) {
                Entry::Occupied(mut entry) => match entry.get_mut() {
                    WalletTx::Block(_) => Err(WalletError::CannotFindTransactionWithId(tx_id)),
                    WalletTx::Tx(tx) => match tx.state() {
                        TxState::Inactive(_) | TxState::Conflicted(_) => {
                            tx.set_state(TxState::Abandoned);
                            for input in tx.get_transaction().inputs() {
                                match input {
                                    TxInput::Utxo(outpoint) => {
                                        self.consumed.insert(outpoint.clone(), *tx.state());
                                    }
                                    TxInput::Account(outpoint) => match outpoint.account() {
                                        AccountSpending::DelegationBalance(delegation_id, _) => {
                                            if let Some(data) =
                                                self.delegations.get_mut(delegation_id)
                                            {
                                                data.last_nonce = outpoint.nonce().decrement();
                                                data.last_parent = find_parent(
                                                    &self.unconfirmed_descendants,
                                                    tx_id.into(),
                                                );
                                            }
                                        }
                                    },
                                    TxInput::AccountCommand(nonce, op) => match op {
                                        AccountCommand::MintTokens(token_id, _)
                                        | AccountCommand::UnmintTokens(token_id)
                                        | AccountCommand::LockTokenSupply(token_id)
                                        | AccountCommand::FreezeToken(token_id, _)
                                        | AccountCommand::UnfreezeToken(token_id)
                                        | AccountCommand::ChangeTokenMetadataUri(token_id, _)
                                        | AccountCommand::ChangeTokenAuthority(token_id, _) => {
                                            if let Some(data) =
                                                self.token_issuance.get_mut(token_id)
                                            {
                                                data.last_nonce = nonce.decrement();
                                                data.last_parent = find_parent(
                                                    &self.unconfirmed_descendants,
                                                    tx_id.into(),
                                                );
                                                data.unconfirmed_txs.remove(&tx_id.into());
                                            }
                                        }
                                        AccountCommand::ConcludeOrder(order_id)
                                        | AccountCommand::FillOrder(order_id, _, _) => {
                                            if let Some(data) = self.orders.get_mut(order_id) {
                                                data.last_nonce = nonce.decrement();
                                                data.last_parent = find_parent(
                                                    &self.unconfirmed_descendants,
                                                    tx_id.into(),
                                                );
                                            }
                                        }
                                    },
                                }
                            }
                            Ok(())
                        }
                        state => Err(WalletError::CannotAbandonTransaction(*state)),
                    },
                },
                Entry::Vacant(_) => Err(WalletError::CannotFindTransactionWithId(tx_id)),
            }?;
        }

        Ok(all_abandoned)
    }

    pub fn get_transaction(&self, transaction_id: Id<Transaction>) -> WalletResult<&TxData> {
        match self.txs.get(&transaction_id.into()) {
            None | Some(WalletTx::Block(_)) => Err(WalletError::NoTransactionFound(transaction_id)),
            Some(WalletTx::Tx(tx)) => Ok(tx),
        }
    }

    pub fn get_created_blocks<F: Fn(&Destination) -> bool>(
        &self,
        is_mine: F,
    ) -> Vec<(BlockHeight, Id<GenBlock>, PoolId)> {
        self.txs
            .values()
            .filter_map(|wtx| match wtx {
                WalletTx::Tx(_) => None,
                WalletTx::Block(block) => block
                    .kernel_inputs()
                    .iter()
                    .find_map(|inp| self.created_by_our_stake_pool(inp, &is_mine))
                    .map(|pool_id| (block.height(), *block.block_id(), pool_id)),
            })
            .collect_vec()
    }

    fn created_by_our_stake_pool<F: Fn(&Destination) -> bool>(
        &self,
        inp: &TxInput,
        is_mine: &F,
    ) -> Option<PoolId> {
        match inp {
            TxInput::Account(_) | TxInput::AccountCommand(_, _) => None,
            TxInput::Utxo(outpoint) => self
                .txs
                .get(&outpoint.source_id())
                .and_then(|tx| tx.outputs().get(outpoint.output_index() as usize))
                .and_then(|out| match out {
                    TxOutput::IssueFungibleToken(_)
                    | TxOutput::CreateDelegationId(_, _)
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::DataDeposit(_)
                    | TxOutput::IssueNft(_, _, _)
                    | TxOutput::Burn(_)
                    | TxOutput::Transfer(_, _)
                    | TxOutput::LockThenTransfer(_, _, _)
                    | TxOutput::Htlc(_, _)
                    | TxOutput::CreateOrder(_) => None,
                    TxOutput::ProduceBlockFromStake(_, pool_id)
                    | TxOutput::CreateStakePool(pool_id, _) => {
                        self.pools.get(pool_id).and_then(|pool_data| {
                            is_mine(&pool_data.stake_destination).then_some(*pool_id)
                        })
                    }
                }),
        }
    }
}

fn wallet_tx_order(x: &WalletTx, y: &WalletTx) -> std::cmp::Ordering {
    match (x.state(), y.state()) {
        (TxState::Confirmed(h1, _, idx1), TxState::Confirmed(h2, _, idx2)) => {
            (h1, idx1).cmp(&(h2, idx2))
        }
        (TxState::Confirmed(_, _, _), _) => std::cmp::Ordering::Less,
        (_, TxState::Confirmed(_, _, _)) => std::cmp::Ordering::Greater,
        (TxState::InMempool(idx1), TxState::InMempool(idx2)) => idx1.cmp(&idx2),
        (TxState::InMempool(idx1), TxState::Inactive(idx2)) => idx1.cmp(&idx2),
        (TxState::Inactive(idx1), TxState::Inactive(idx2)) => idx1.cmp(&idx2),
        (TxState::Inactive(idx1), TxState::InMempool(idx2)) => idx1.cmp(&idx2),
        (_, _) => std::cmp::Ordering::Equal,
    }
}

/// Check if the TxOutput is a v0 token
fn is_v0_token_output(output: &TxOutput) -> bool {
    match output {
        TxOutput::LockThenTransfer(out, _, _)
        | TxOutput::Transfer(out, _)
        | TxOutput::Htlc(out, _) => match out {
            OutputValue::TokenV0(_) => true,
            OutputValue::Coin(_) | OutputValue::TokenV1(_, _) => false,
        },
        TxOutput::Burn(_)
        | TxOutput::CreateStakePool(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::IssueNft(_, _, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::DataDeposit(_)
        | TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::CreateOrder(_) => false,
    }
}

/// Checks the output against the current block height and compares it with the locked_state parameter.
/// If they match, the function return true, if they don't, it returns false.
/// For example, if we would like to check that an output is locked,
/// we pass locked_state = WithLocked::Locked, and pass the output in question.
/// If the output is locked, the function returns true. Otherwise, it returns false
fn is_specific_lock_state(
    locked_state: WithLocked,
    output: &TxOutput,
    current_block_info: BlockInfo,
    tx_block_info: Option<BlockInfo>,
    outpoint: &UtxoOutPoint,
) -> bool {
    match locked_state {
        WithLocked::Any => true,
        WithLocked::Locked => {
            !valid_timelock(output, &current_block_info, &tx_block_info, outpoint)
        }
        WithLocked::Unlocked => {
            valid_timelock(output, &current_block_info, &tx_block_info, outpoint)
        }
    }
}

/// Get the block info (block height and timestamp) if the Tx is in confirmed state
fn get_block_info(tx: &WalletTx) -> Option<BlockInfo> {
    match tx.state() {
        TxState::Confirmed(height, timestamp, _) => Some(BlockInfo { height, timestamp }),
        TxState::InMempool(_)
        | TxState::Inactive(_)
        | TxState::Conflicted(_)
        | TxState::Abandoned => None,
    }
}

/// Check the TxOutput's timelock is unlocked
fn valid_timelock(
    output: &TxOutput,
    current_block_info: &BlockInfo,
    transaction_block_info: &Option<BlockInfo>,
    outpoint: &UtxoOutPoint,
) -> bool {
    output.timelock().map_or(true, |timelock| {
        transaction_block_info.as_ref().is_some_and(|transaction_block_info| {
            tx_verifier::timelock_check::check_timelock(
                &transaction_block_info.height,
                &transaction_block_info.timestamp,
                timelock,
                &current_block_info.height,
                &current_block_info.timestamp,
                outpoint,
            )
            .is_ok()
        })
    })
}

/// Check Tx is in the selected state Confirmed/Inactive/Abandoned...
fn is_in_state(tx: &WalletTx, utxo_states: UtxoStates) -> bool {
    utxo_states.contains(get_utxo_state(&tx.state()))
}

/// Find the parent tx if it is in the unconfirmed transactions
fn find_parent(
    unconfirmed_descendants: &BTreeMap<OutPointSourceId, BTreeSet<OutPointSourceId>>,
    tx_id: OutPointSourceId,
) -> Option<OutPointSourceId> {
    unconfirmed_descendants
        .iter()
        .find_map(|(parent_id, descendants)| descendants.contains(&tx_id).then_some(parent_id))
        .cloned()
}

fn apply_freeze_mutations_from_tx(
    mut frozen_state: TokenFreezableState,
    tx: &WalletTx,
    own_token_id: &TokenId,
) -> WalletResult<TokenFreezableState> {
    for inp in tx.inputs() {
        match inp {
            TxInput::Utxo(_) => {}
            TxInput::Account(acc) => match acc.account() {
                AccountSpending::DelegationBalance(_, _) => {}
            },
            TxInput::AccountCommand(_, op) => match op {
                AccountCommand::FreezeToken(token_id, is_unfreezable) => {
                    if token_id == own_token_id {
                        frozen_state = frozen_state.freeze(*is_unfreezable)?;
                    }
                }
                AccountCommand::UnfreezeToken(token_id) => {
                    if token_id == own_token_id {
                        frozen_state = frozen_state.unfreeze()?;
                    }
                }
                AccountCommand::MintTokens(_, _)
                | AccountCommand::UnmintTokens(_)
                | AccountCommand::LockTokenSupply(_)
                | AccountCommand::ChangeTokenMetadataUri(_, _)
                | AccountCommand::ChangeTokenAuthority(_, _)
                | AccountCommand::ConcludeOrder(_)
                | AccountCommand::FillOrder(_, _, _) => {}
            },
        }
    }

    Ok(frozen_state)
}

fn apply_total_supply_mutations_from_tx(
    mut total_supply: TokenCurrentSupplyState,
    tx: &WalletTx,
    own_token_id: &TokenId,
) -> WalletResult<TokenCurrentSupplyState> {
    for inp in tx.inputs() {
        match inp {
            TxInput::Utxo(_) => {}
            TxInput::Account(acc) => match acc.account() {
                AccountSpending::DelegationBalance(_, _) => {}
            },
            TxInput::AccountCommand(_, op) => match op {
                AccountCommand::MintTokens(token_id, amount) => {
                    if token_id == own_token_id {
                        total_supply = total_supply.mint(*amount)?;
                    }
                }
                AccountCommand::UnmintTokens(token_id) => match tx {
                    WalletTx::Tx(tx) => {
                        let total_burned =
                            calculate_tokens_burned_in_outputs(tx.get_transaction(), token_id)
                                .map_err(|_| WalletError::OutputAmountOverflow)?;
                        total_supply = total_supply.unmint(total_burned)?;
                    }
                    WalletTx::Block(_) => {}
                },
                AccountCommand::LockTokenSupply(_) => {
                    total_supply = total_supply.lock()?;
                }
                AccountCommand::FreezeToken(_, _)
                | AccountCommand::UnfreezeToken(_)
                | AccountCommand::ChangeTokenMetadataUri(_, _)
                | AccountCommand::ChangeTokenAuthority(_, _)
                | AccountCommand::ConcludeOrder(_)
                | AccountCommand::FillOrder(_, _, _) => {}
            },
        }
    }

    Ok(total_supply)
}
