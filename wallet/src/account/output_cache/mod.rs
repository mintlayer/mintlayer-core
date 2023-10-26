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
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    ops::Add,
};

use common::{
    chain::{
        output_value::OutputValue,
        tokens::{
            is_token_or_nft_issuance, make_token_id, TokenId, TokenIssuance, TokenTotalSupply,
        },
        AccountNonce, AccountOp, DelegationId, Destination, OutPointSourceId, PoolId, Transaction,
        TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{id::WithId, Amount, Id},
};
use pos_accounting::make_delegation_id;
use utils::ensure;
use wallet_types::{
    utxo_types::{get_utxo_state, UtxoState, UtxoStates},
    wallet_tx::TxState,
    with_locked::WithLocked,
    AccountWalletTxId, BlockInfo, WalletTx,
};

use crate::{WalletError, WalletResult};

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

pub struct PoolData {
    pub utxo_outpoint: UtxoOutPoint,
    pub creation_block: BlockInfo,
    pub decommission_key: Destination,
}

impl PoolData {
    fn new(
        utxo_outpoint: UtxoOutPoint,
        creation_block: BlockInfo,
        decommission_key: Destination,
    ) -> Self {
        PoolData {
            utxo_outpoint,
            creation_block,
            decommission_key,
        }
    }
}

pub enum TokenCurrentSupplyState {
    Fixed(Amount, Amount), // fixed to a certain amount
    Lockable(Amount),      // not known in advance but can be locked once at some point in time
    Locked(Amount),        // Locked
    Unlimited(Amount),     // limited only by the Amount data type
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

impl TokenCurrentSupplyState {
    pub fn str_state(&self) -> &'static str {
        match self {
            Self::Unlimited(_) => "Unlimited",
            Self::Locked(_) => "Locked",
            Self::Lockable(_) => "Lockable",
            Self::Fixed(_, _) => "Fixed",
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

    pub fn current_supply(&self) -> Amount {
        match self {
            Self::Unlimited(amount)
            | Self::Fixed(_, amount)
            | Self::Locked(amount)
            | Self::Lockable(amount) => *amount,
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

    fn unlock(&self) -> WalletResult<TokenCurrentSupplyState> {
        match self {
            TokenCurrentSupplyState::Locked(current) => {
                Ok(TokenCurrentSupplyState::Lockable(*current))
            }
            TokenCurrentSupplyState::Unlimited(_)
            | TokenCurrentSupplyState::Fixed(_, _)
            | TokenCurrentSupplyState::Lockable(_) => {
                Err(WalletError::InconsistentUnlockTokenSupply(self.str_state()))
            }
        }
    }
}

pub struct TokenIssuanceData {
    pub total_supply: TokenCurrentSupplyState,
    pub authority: Destination,
    pub last_nonce: Option<AccountNonce>,
    /// last parent transaction if the parent is unconfirmed
    pub last_parent: Option<OutPointSourceId>,
}

impl TokenIssuanceData {
    fn new(data: TokenTotalSupply, authority: Destination) -> Self {
        Self {
            total_supply: data.into(),
            authority,
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
        }
    }

    pub fn new(mut txs: Vec<(AccountWalletTxId, WalletTx)>) -> WalletResult<Self> {
        let mut cache = Self::empty();

        txs.sort_by(|x, y| match (x.1.state(), y.1.state()) {
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
        });
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

    pub fn pool_ids(&self) -> Vec<(PoolId, BlockInfo)> {
        self.pools
            .iter()
            .filter_map(|(pool_id, pool_data)| {
                (!self.consumed.contains_key(&pool_data.utxo_outpoint))
                    .then_some((*pool_id, pool_data.creation_block))
            })
            .collect()
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

    pub fn add_tx(&mut self, tx_id: OutPointSourceId, tx: WalletTx) -> WalletResult<()> {
        let already_present = self.txs.get(&tx_id).map_or(false, |tx| !tx.state().is_abandoned());
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
                                    data.decommission_key().clone(),
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
                    let input0_outpoint = tx
                        .inputs()
                        .get(0)
                        .ok_or(WalletError::NoUtxos)?
                        .utxo_outpoint()
                        .ok_or(WalletError::NoUtxos)?;
                    let delegation_id = make_delegation_id(input0_outpoint);
                    self.delegations.insert(
                        delegation_id,
                        DelegationData::new(*pool_id, destination.clone()),
                    );
                }
                | TxOutput::Burn(_)
                | TxOutput::DataDeposit(_)
                | TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _) => {}
                TxOutput::IssueFungibleToken(issuance) => {
                    if already_present {
                        continue;
                    }
                    let input0_outpoint = tx.inputs();
                    let token_id = make_token_id(input0_outpoint).ok_or(WalletError::NoUtxos)?;
                    match issuance.as_ref() {
                        TokenIssuance::V1(data) => {
                            self.token_issuance.insert(
                                token_id,
                                TokenIssuanceData::new(data.total_supply, data.authority.clone()),
                            );
                        }
                    }
                }
                TxOutput::IssueNft(_, _, _) => {}
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
                TxInput::Account(outpoint) => {
                    if !already_present {
                        match outpoint.account() {
                            AccountOp::SpendDelegationBalance(delegation_id, _) => {
                                if let Some(data) = self.delegations.get_mut(delegation_id) {
                                    Self::update_delegation_state(
                                        &mut self.unconfirmed_descendants,
                                        data,
                                        delegation_id,
                                        outpoint,
                                        tx_id,
                                    )?;
                                }
                            }
                            AccountOp::MintTokens(token_id, amount) => {
                                if let Some(data) = self.token_issuance.get_mut(token_id) {
                                    Self::update_token_issuance_state(
                                        &mut self.unconfirmed_descendants,
                                        data,
                                        token_id,
                                        outpoint,
                                        tx_id,
                                    )?;
                                    data.total_supply = data.total_supply.mint(*amount)?;
                                }
                            }
                            AccountOp::UnmintTokens(token_id) => {
                                if let Some(data) = self.token_issuance.get_mut(token_id) {
                                    Self::update_token_issuance_state(
                                        &mut self.unconfirmed_descendants,
                                        data,
                                        token_id,
                                        outpoint,
                                        tx_id,
                                    )?;
                                    let amount = sum_burned_token_amount(tx.outputs(), token_id)?;
                                    data.total_supply = data.total_supply.unmint(amount)?;
                                }
                            }
                            | AccountOp::LockTokenSupply(token_id) => {
                                if let Some(data) = self.token_issuance.get_mut(token_id) {
                                    Self::update_token_issuance_state(
                                        &mut self.unconfirmed_descendants,
                                        data,
                                        token_id,
                                        outpoint,
                                        tx_id,
                                    )?;
                                    data.total_supply = data.total_supply.lock()?;
                                }
                            }
                            AccountOp::FreezeToken(_, _) => todo!(),
                            AccountOp::UnfreezeToken(_) => todo!(),
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Update delegation state with new tx input
    fn update_delegation_state(
        unconfirmed_descendants: &mut BTreeMap<OutPointSourceId, BTreeSet<OutPointSourceId>>,
        data: &mut DelegationData,
        delegation_id: &DelegationId,
        outpoint: &common::chain::AccountOutPoint,
        tx_id: &OutPointSourceId,
    ) -> Result<(), WalletError> {
        let next_nonce = data
            .last_nonce
            .map_or(Some(AccountNonce::new(0)), |nonce| nonce.increment())
            .ok_or(WalletError::DelegationNonceOverflow(*delegation_id))?;

        ensure!(
            outpoint.nonce() == next_nonce,
            WalletError::InconsistentDelegationDuplicateNonce(*delegation_id, outpoint.nonce())
        );

        data.last_nonce = Some(outpoint.nonce());
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
        outpoint: &common::chain::AccountOutPoint,
        tx_id: &OutPointSourceId,
    ) -> Result<(), WalletError> {
        let next_nonce = data
            .last_nonce
            .map_or(Some(AccountNonce::new(0)), |nonce| nonce.increment())
            .ok_or(WalletError::TokenIssuanceNonceOverflow(*delegation_id))?;

        ensure!(
            outpoint.nonce() == next_nonce,
            WalletError::InconsistentTokenIssuanceDuplicateNonce(*delegation_id, outpoint.nonce())
        );

        data.last_nonce = Some(outpoint.nonce());
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
                        AccountOp::SpendDelegationBalance(delegation_id, _) => {
                            if let Some(data) = self.delegations.get_mut(delegation_id) {
                                data.last_nonce = outpoint.nonce().decrement();
                                data.last_parent =
                                    find_parent(&self.unconfirmed_descendants, tx_id.clone());
                            }
                        }
                        AccountOp::MintTokens(token_id, amount) => {
                            if let Some(data) = self.token_issuance.get_mut(token_id) {
                                data.last_nonce = outpoint.nonce().decrement();
                                data.last_parent =
                                    find_parent(&self.unconfirmed_descendants, tx_id.clone());
                                data.total_supply = data.total_supply.unmint(*amount)?;
                            }
                        }

                        AccountOp::UnmintTokens(token_id) => {
                            if let Some(data) = self.token_issuance.get_mut(token_id) {
                                data.last_nonce = outpoint.nonce().decrement();
                                data.last_parent =
                                    find_parent(&self.unconfirmed_descendants, tx_id.clone());
                                let amount = sum_burned_token_amount(tx.outputs(), token_id)?;
                                data.total_supply = data.total_supply.mint(amount)?;
                            }
                        }
                        AccountOp::LockTokenSupply(token_id) => {
                            if let Some(data) = self.token_issuance.get_mut(token_id) {
                                data.last_nonce = outpoint.nonce().decrement();
                                data.last_parent =
                                    find_parent(&self.unconfirmed_descendants, tx_id.clone());
                                data.total_supply = data.total_supply.unlock()?;
                            }
                        }
                        AccountOp::FreezeToken(_, _) => todo!(),
                        AccountOp::UnfreezeToken(_) => todo!(),
                    },
                }
            }
        }
        Ok(())
    }

    fn is_consumed(&self, utxo_states: UtxoStates, outpoint: &UtxoOutPoint) -> bool {
        self.consumed.get(outpoint).map_or(false, |consumed_state| {
            utxo_states.contains(get_utxo_state(consumed_state))
        })
    }

    fn find_unspent_unlocked_utxo(
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
            WalletTx::Tx(tx_data) => make_token_id(tx_data.get_transaction().inputs()),
            WalletTx::Block(_) => None,
        };

        Ok((output, token_id))
    }

    pub fn find_utxos(
        &self,
        current_block_info: BlockInfo,
        inputs: Vec<UtxoOutPoint>,
    ) -> WalletResult<BTreeMap<UtxoOutPoint, (&TxOutput, Option<TokenId>)>> {
        inputs
            .into_iter()
            .map(|utxo| {
                self.find_unspent_unlocked_utxo(&utxo, current_block_info)
                    .map(|res| (utxo, res))
            })
            .collect()
    }

    pub fn utxos_with_token_ids(
        &self,
        current_block_info: BlockInfo,
        utxo_states: UtxoStates,
        locked_state: WithLocked,
    ) -> BTreeMap<UtxoOutPoint, (&TxOutput, Option<TokenId>)> {
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

    pub fn pending_transactions(&self) -> Vec<&WithId<Transaction>> {
        self.txs
            .values()
            .filter_map(|tx| match tx {
                WalletTx::Block(_) => None,
                WalletTx::Tx(tx) => match tx.state() {
                    TxState::Inactive(_) => Some(tx.get_transaction_with_id()),
                    TxState::Confirmed(_, _, _)
                    | TxState::Conflicted(_)
                    | TxState::InMempool(_)
                    | TxState::Abandoned => None,
                },
            })
            .collect()
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
                        TxState::Inactive(_) => {
                            tx.set_state(TxState::Abandoned);
                            for input in tx.get_transaction().inputs() {
                                match input {
                                    TxInput::Utxo(outpoint) => {
                                        self.consumed.insert(outpoint.clone(), *tx.state());
                                    }
                                    TxInput::Account(outpoint) => match outpoint.account() {
                                        AccountOp::SpendDelegationBalance(delegation_id, _) => {
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
                                        AccountOp::MintTokens(token_id, amount) => {
                                            if let Some(data) =
                                                self.token_issuance.get_mut(token_id)
                                            {
                                                data.last_nonce = outpoint.nonce().decrement();
                                                data.last_parent = find_parent(
                                                    &self.unconfirmed_descendants,
                                                    tx_id.into(),
                                                );
                                                data.total_supply =
                                                    data.total_supply.unmint(*amount)?;
                                            }
                                        }
                                        | AccountOp::UnmintTokens(token_id) => {
                                            if let Some(data) =
                                                self.token_issuance.get_mut(token_id)
                                            {
                                                data.last_nonce = outpoint.nonce().decrement();
                                                data.last_parent = find_parent(
                                                    &self.unconfirmed_descendants,
                                                    tx_id.into(),
                                                );
                                                let amount = sum_burned_token_amount(
                                                    tx.get_transaction().outputs(),
                                                    token_id,
                                                )?;
                                                data.total_supply =
                                                    data.total_supply.mint(amount)?;
                                            }
                                        }
                                        | AccountOp::LockTokenSupply(token_id) => {
                                            if let Some(data) =
                                                self.token_issuance.get_mut(token_id)
                                            {
                                                data.last_nonce = outpoint.nonce().decrement();
                                                data.last_parent = find_parent(
                                                    &self.unconfirmed_descendants,
                                                    tx_id.into(),
                                                );
                                                data.total_supply = data.total_supply.unlock()?;
                                            }
                                        }
                                        AccountOp::FreezeToken(_, _) => todo!(),
                                        AccountOp::UnfreezeToken(_) => todo!(),
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
}

fn sum_burned_token_amount(
    outputs: &[TxOutput],
    token_id: &TokenId,
) -> Result<Amount, WalletError> {
    let amount = outputs
        .iter()
        .filter_map(|output| match output {
            TxOutput::Burn(OutputValue::TokenV1(tid, amount)) if tid == token_id => Some(*amount),
            TxOutput::Transfer(_, _)
            | TxOutput::Burn(_)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::CreateStakePool(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DataDeposit(_)
            | TxOutput::ProduceBlockFromStake(_, _) => None,
        })
        .sum::<Option<Amount>>()
        .ok_or(WalletError::OutputAmountOverflow);
    amount
}

/// Check if the TxOutput is a v0 token
fn is_v0_token_output(output: &TxOutput) -> bool {
    match output {
        TxOutput::LockThenTransfer(out, _, _) | TxOutput::Transfer(out, _) => match out {
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
        | TxOutput::ProduceBlockFromStake(_, _) => false,
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
        transaction_block_info.as_ref().map_or(false, |transaction_block_info| {
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
